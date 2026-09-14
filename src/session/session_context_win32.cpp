/**
 * @file src/session/session_context_win32.cpp
 * @brief Windows placeholder for the seat/session model.
 *
 * The Linux implementation is built on systemd-logind: seats, logind session
 * descriptors, X11 DISPLAY/XAUTHORITY discovery, PulseAudio and D-Bus
 * addresses, SO_PEERCRED peer verification and a privileged supervisor process.
 * None of that exists on Windows; the equivalent is a Windows service plus WTS
 * session notifications, which is a different design rather than a port.
 *
 * Every entry point fails closed: no session is described, no account is
 * attested, no display lease is granted. A permissive stub would let the host
 * believe it had attached a user to a desktop it cannot see.
 */

#include "session_context.h"

#include <windows.h>
#include <wtsapi32.h>

#include <string>
#include <vector>

#include "src/auth/second_factor.h"
#include "src/config.h"
#include "src/logging.h"

using namespace std::literals;

namespace plank::session {
  namespace {
    void unimplemented_once(const char *what) {
      static thread_local bool warned = false;
      if (!warned) {
        warned = true;
        BOOST_LOG(warning)
          << "PLANK session supervision is not implemented on Windows ("
          << what << "). The host cannot attach a desktop session.";
      }
    }
  }  // namespace

  bool eligible_graphical_session(const descriptor_t &) {
    return false;
  }

  std::optional<descriptor_t> describe(std::string_view) {
    unimplemented_once("describe");
    return std::nullopt;
  }

  std::optional<descriptor_t> active_seat0_graphical_session() {
    unimplemented_once("active_seat0_graphical_session");
    return std::nullopt;
  }

  std::optional<environment_t> discover_environment(const descriptor_t &) {
    unimplemented_once("discover_environment");
    return std::nullopt;
  }

  namespace {
    /**
     * @brief Account name owning a WTS session, if anyone is logged in to it.
     */
    std::wstring session_account(DWORD session_id) {
      LPWSTR user = nullptr;
      DWORD user_bytes = 0;
      if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id,
                                       WTSUserName, &user, &user_bytes) ||
          user == nullptr) {
        return {};
      }
      std::wstring account {user};
      WTSFreeMemory(user);
      if (account.empty()) {
        return {};  // session exists but nobody is logged in
      }

      LPWSTR domain = nullptr;
      DWORD domain_bytes = 0;
      if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id,
                                      WTSDomainName, &domain, &domain_bytes) &&
          domain != nullptr) {
        std::wstring domain_name {domain};
        WTSFreeMemory(domain);
        if (!domain_name.empty()) {
          account = domain_name + L"\\" + account;
        }
      }
      return account;
    }
  }  // namespace

  namespace {
    /// Resolve an account name to its SID bytes; empty when it cannot be resolved.
    std::vector<unsigned char> account_sid(const std::wstring &account) {
      if (account.empty()) {
        return {};
      }
      DWORD sid_size = 0;
      DWORD domain_size = 0;
      SID_NAME_USE use {};
      LookupAccountNameW(nullptr, account.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
      if (sid_size == 0) {
        return {};
      }
      std::vector<unsigned char> sid(sid_size);
      std::wstring domain(domain_size, L'\0');
      if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size, domain.data(), &domain_size, &use) ||
          use != SidTypeUser) {
        return {};
      }
      return sid;
    }

    std::wstring widen(std::string_view text) {
      if (text.empty()) {
        return {};
      }
      const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring wide(static_cast<std::size_t>(size), L'\0');
      MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
      return wide;
    }
  }  // namespace

  bool supervisor_attests_account_for_active_seat0(uid_t) {
    // A RID is unique only within one domain or machine, so it cannot decide
    // desktop ownership on Windows. Callers use the account-name overload.
    BOOST_LOG(error) << "RID-only desktop attestation is not supported on Windows; refusing.";
    return false;
  }

  bool supervisor_attests_account_name_for_active_seat0(std::string_view account) {
    // The desktop PLANK captures is the one this process runs in, so that is
    // the session whose owner is attested.
    DWORD host_session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &host_session) || host_session == 0) {
      BOOST_LOG(warning)
        << "Host is not running in an interactive session (session 0 has no desktop); refusing.";
      return false;
    }
    const DWORD console_session = WTSGetActiveConsoleSessionId();
    if (host_session != console_session) {
      if (!config::plank_auth.allow_remote_desktop_session) {
        BOOST_LOG(warning)
          << "Host runs in remote-desktop session "sv << host_session
          << ", not the physical console; refusing. Set allow_remote_desktop_session = true to permit this."sv;
        return false;
      }
      BOOST_LOG(warning)
        << "Attesting remote-desktop session "sv << host_session
        << " because allow_remote_desktop_session is enabled"sv;
    }
    auto sid = account_sid(widen(plank::auth::qualified_windows_account(account)));
    if (sid.empty()) {
      BOOST_LOG(warning) << "Unable to resolve the authenticated account; refusing.";
      return false;
    }
    const auto *count = GetSidSubAuthorityCount(reinterpret_cast<PSID>(sid.data()));
    const bool builtin_administrator =
      count != nullptr && *count > 0 &&
      *GetSidSubAuthority(reinterpret_cast<PSID>(sid.data()), static_cast<DWORD>(*count - 1)) ==
        DOMAIN_USER_RID_ADMIN;
    if (builtin_administrator && !config::plank_auth.allow_root_login) {
      BOOST_LOG(warning)
        << "The built-in Administrator account may not connect "
           "(security.allow_root_login is false); refusing.";
      return false;
    }

    const auto relation = desktop_owner_relation(account);
    if (relation == desktop_owner_e::different) {
      BOOST_LOG(warning)
        << "Authenticated account does not own the host's desktop session; refusing.";
      return false;
    }
    if (relation == desktop_owner_e::none) {
      // Login screen: as at the Linux GDM greeter, any authenticated account may
      // connect and sign in inside the stream. Ownership is rechecked while
      // streaming (desktop_owner_relation) once someone signs in.
      BOOST_LOG(info) << "Attesting the Windows login screen for " << account;
    }
    return true;
  }

  desktop_owner_e desktop_owner_relation(std::string_view account) {
    DWORD host_session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &host_session)) {
      return desktop_owner_e::different;
    }
    const auto owner = session_account(host_session);
    if (owner.empty()) {
      return desktop_owner_e::none;
    }
    auto owner_sid = account_sid(owner);
    auto requested_sid = account_sid(widen(plank::auth::qualified_windows_account(account)));
    if (owner_sid.empty() || requested_sid.empty() ||
        !EqualSid(reinterpret_cast<PSID>(owner_sid.data()), reinterpret_cast<PSID>(requested_sid.data()))) {
      return desktop_owner_e::different;
    }
    return desktop_owner_e::same;
  }

  std::string session_update_message(const update_t &) {
    return {};
  }

  std::optional<update_t> parse_session_update(std::string_view) {
    return std::nullopt;
  }

  std::string display_request_message(const display_request_t &) {
    return {};
  }

  std::optional<display_request_t> parse_display_request(std::string_view) {
    return std::nullopt;
  }

  std::string runtime_display_state_message(const runtime_display_state_t &) {
    return {};
  }

  std::optional<runtime_display_state_t> parse_runtime_display_state(std::string_view) {
    return std::nullopt;
  }

  std::optional<runtime_display_state_t> read_runtime_display_state(std::string_view) {
    return std::nullopt;
  }

  std::optional<bool> secondary_output_visible_from_overlay(std::string_view) {
    return std::nullopt;
  }

  startup_layout_t configured_startup_layout(std::string_view) {
    return startup_layout_t::physical;
  }

  display_request_status request_display_transition(const display_request_t &) {
    unimplemented_once("request_display_transition");
    return display_request_status::unavailable;
  }

  display_request_status activate_display_lease(uid_t) {
    unimplemented_once("activate_display_lease");
    return display_request_status::unavailable;
  }

  display_request_status release_display_lease(uid_t) {
    return display_request_status::unavailable;
  }

  std::unique_ptr<supervisor_control_t> start_supervisor_control(
    std::function<void(std::uint64_t)>) {
    unimplemented_once("start_supervisor_control");
    return nullptr;
  }

  std::uint64_t desktop_generation() {
    return 0;
  }
}  // namespace plank::session
