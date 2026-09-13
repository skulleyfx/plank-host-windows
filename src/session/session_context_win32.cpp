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
     * @brief Resolve an account name to a stable numeric identifier.
     *
     * Windows has no uid. The relative identifier (RID) - the final
     * sub-authority of the account SID - is the closest stable analogue and is
     * unique within a domain or machine, which is the scope PLANK compares
     * over. Returns 0 when the account cannot be resolved.
     */
    std::uint32_t account_rid(const std::wstring &account) {
      if (account.empty()) {
        return 0;
      }
      DWORD sid_size = 0;
      DWORD domain_size = 0;
      SID_NAME_USE use {};
      LookupAccountNameW(nullptr, account.c_str(), nullptr, &sid_size,
                         nullptr, &domain_size, &use);
      if (sid_size == 0) {
        return 0;
      }
      std::vector<unsigned char> sid(sid_size);
      std::wstring domain(domain_size, L'\0');
      if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size,
                              domain.data(), &domain_size, &use)) {
        return 0;
      }
      auto *sid_pointer = reinterpret_cast<PSID>(sid.data());
      const auto *count = GetSidSubAuthorityCount(sid_pointer);
      if (count == nullptr || *count == 0) {
        return 0;
      }
      return *GetSidSubAuthority(sid_pointer, static_cast<DWORD>(*count - 1));
    }

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

  bool supervisor_attests_account_for_active_seat0(uid_t account_uid) {
    if (account_uid == 0) {
      return false;
    }
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
    const auto owner = session_account(host_session);
    if (owner.empty()) {
      BOOST_LOG(warning) << "Nobody is logged in to the host's session; refusing.";
      return false;
    }
    const auto owner_uid = account_rid(owner);
    if (owner_uid == 0) {
      BOOST_LOG(warning) << "Unable to resolve the host session account; refusing.";
      return false;
    }
    if (owner_uid != account_uid) {
      BOOST_LOG(warning)
        << "Authenticated account does not own the host's desktop session; refusing.";
      return false;
    }
    return true;
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
