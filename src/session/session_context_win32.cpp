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

#include <atomic>
#include <chrono>
#include <functional>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "src/auth/second_factor.h"
#include "src/config.h"
#include "src/display_device.h"
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

  namespace {
    std::atomic_uint64_t &lock_generation() {
      static std::atomic_uint64_t generation {0};
      return generation;
    }

    bool session_locked(DWORD session_id) {
      WTSINFOEXW *info = nullptr;
      DWORD bytes = 0;
      if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, WTSSessionInfoEx,
                                       reinterpret_cast<LPWSTR *>(&info), &bytes) ||
          info == nullptr) {
        return false;
      }
      // WTS_SESSIONSTATE_LOCK is 0; Windows 7 and Server 2008 R2 invert it, which we do not support.
      const bool locked = info->Level == 1 && info->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK;
      WTSFreeMemory(info);
      return locked;
    }
  }  // namespace

  void schedule_lock_after_disconnect(std::function<bool()> still_idle) {
    if (!config::plank_auth.lock_on_disconnect) {
      return;
    }
    const auto generation = ++lock_generation();
    const auto delay = std::chrono::seconds {config::plank_auth.lock_on_disconnect_delay};
    std::thread([generation, delay, still_idle = std::move(still_idle)] {
      std::this_thread::sleep_for(delay);
      if (lock_generation() != generation || !still_idle()) {
        return;  // a stream resumed, or another lock is pending
      }
      DWORD host_session = 0;
      if (!ProcessIdToSessionId(GetCurrentProcessId(), &host_session) || host_session == 0 ||
          session_account(host_session).empty() || session_locked(host_session)) {
        return;  // sign-in screen, already locked, or no interactive session
      }
      if (LockWorkStation()) {
        BOOST_LOG(info) << "Locked the workstation after the PLANK stream ended";
      } else {
        BOOST_LOG(warning) << "Unable to lock the workstation after the PLANK stream ended ("
                           << GetLastError() << ')';
      }
    }).detach();
  }

  void cancel_lock_after_disconnect() {
    ++lock_generation();
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

  namespace {
    /**
     * @brief Temporary resolution lease on the host's physical display.
     *
     * Windows workstations use physical displays (or display emulators), so a
     * requested single-display layout is served by switching the active
     * display's mode rather than creating a virtual output. The display
     * library persists the original configuration, so it is restored at
     * session end or, after a crash, when the host next starts.
     */
    std::mutex &lease_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    std::optional<runtime_display_state_t> &display_lease() {
      static std::optional<runtime_display_state_t> lease;
      return lease;
    }

    bool parse_mode(std::string_view mode, unsigned &width, unsigned &height) {
      const auto separator = mode.find('x');
      if (separator == std::string_view::npos) {
        return false;
      }
      width = static_cast<unsigned>(std::strtoul(std::string {mode.substr(0, separator)}.c_str(), nullptr, 10));
      height = static_cast<unsigned>(std::strtoul(std::string {mode.substr(separator + 1)}.c_str(), nullptr, 10));
      return width > 0 && height > 0;
    }

    /// Active mode of the primary display, which the display library configures.
    bool primary_display_mode(unsigned &width, unsigned &height) {
      DEVMODEW mode {};
      mode.dmSize = sizeof(mode);
      if (!EnumDisplaySettingsExW(nullptr, ENUM_CURRENT_SETTINGS, &mode, 0)) {
        return false;
      }
      width = mode.dmPelsWidth;
      height = mode.dmPelsHeight;
      return true;
    }

    int active_display_count() {
      int count = 0;
      DISPLAY_DEVICEW device {};
      device.cb = sizeof(device);
      for (DWORD index = 0; EnumDisplayDevicesW(nullptr, index, &device, 0); ++index) {
        if (device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) {
          ++count;
        }
        device.cb = sizeof(device);
      }
      return count;
    }
  }  // namespace

  std::optional<runtime_display_state_t> read_runtime_display_state(std::string_view) {
    std::lock_guard lock {lease_mutex()};
    return display_lease();
  }

  std::optional<bool> secondary_output_visible_from_overlay(std::string_view) {
    return std::nullopt;
  }

  startup_layout_t configured_startup_layout(std::string_view) {
    return startup_layout_t::physical;
  }

  display_request_status request_display_transition(const display_request_t &request) {
    if (request.action != display_request_t::action_t::acquire) {
      return display_request_status::invalid;
    }
    std::lock_guard lock {lease_mutex()};
    if (display_lease() && display_lease()->lease_uid != request.account_uid) {
      return display_request_status::wrong_user;
    }
    // Only a single display is switched; a dual layout would need two
    // physical displays positioned side by side.
    unsigned width = 0;
    unsigned height = 0;
    if (request.layout != "single" || !request.mode_2.empty() ||
        !parse_mode(request.mode_1, width, height) || active_display_count() != 1) {
      BOOST_LOG(warning) << "Windows host can only switch a single active display; requested layout "
                         << request.layout << ' ' << request.mode_1 << (request.mode_2.empty() ? "" : "+" + request.mode_2);
      return display_request_status::unavailable;
    }

    unsigned current_width = 0;
    unsigned current_height = 0;
    if (!primary_display_mode(current_width, current_height) ||
        current_width != width || current_height != height) {
      ::display_device::SingleDisplayConfiguration configuration;
      configuration.m_device_prep = ::display_device::SingleDisplayConfiguration::DevicePreparation::VerifyOnly;
      configuration.m_resolution = ::display_device::Resolution {width, height};
      BOOST_LOG(info) << "Switching the host display to " << width << 'x' << height << " for a PLANK session";
      ::display_device::configure_display(configuration);

      // The display library applies settings on its own thread; confirm the
      // mode actually changed before promising the layout to the client.
      bool applied = false;
      for (int attempt = 0; attempt < 40 && !applied; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds {100});
        applied = primary_display_mode(current_width, current_height) &&
                  current_width == width && current_height == height;
      }
      if (!applied) {
        BOOST_LOG(warning) << "The host display does not support " << width << 'x' << height
                           << "; keeping its current mode";
        ::display_device::revert_configuration();
        return display_request_status::unavailable;
      }
    }

    display_lease() = runtime_display_state_t {request.layout, request.mode_1, {}, request.account_uid};
    return display_request_status::submitted;
  }

  display_request_status activate_display_lease(uid_t account_uid) {
    std::lock_guard lock {lease_mutex()};
    return display_lease() && display_lease()->lease_uid == account_uid ?
             display_request_status::submitted :
             display_request_status::unavailable;
  }

  display_request_status release_display_lease(uid_t account_uid) {
    std::lock_guard lock {lease_mutex()};
    if (!display_lease() || display_lease()->lease_uid != account_uid) {
      return display_request_status::unavailable;
    }
    BOOST_LOG(info) << "Restoring the host display after the PLANK session";
    ::display_device::revert_configuration();
    display_lease().reset();
    return display_request_status::submitted;
  }

  std::string_view desktop_stage(const descriptor_t &, const descriptor_t &) {
    // Windows has no logind descriptors; confirmed_desktop_stage() answers directly.
    return "unknown";
  }

  std::string confirmed_desktop_stage() {
    DWORD host_session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &host_session) || host_session == 0) {
      return "unknown";
    }
    // Nobody signed in to the captured session means the Windows sign-in screen.
    return session_account(host_session).empty() ? "greeter" : "user";
  }

  std::unique_ptr<supervisor_control_t> start_supervisor_control(
    std::function<void(std::uint64_t)>, std::function<void()>) {
    unimplemented_once("start_supervisor_control");
    return nullptr;
  }

  std::uint64_t desktop_generation() {
    return 0;
  }
}  // namespace plank::session
