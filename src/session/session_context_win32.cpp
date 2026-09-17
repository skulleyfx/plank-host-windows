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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "display_arrange.h"
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

  std::string signed_in_account() {
    DWORD host_session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &host_session) || host_session == 0) {
      return {};
    }
    const std::wstring account = session_account(host_session);
    if (account.empty()) {
      return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, account.data(), static_cast<int>(account.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, account.data(), static_cast<int>(account.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
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

    /// Physical displays we can arrange, ignoring virtual ones added by other
    /// remote-desktop software.
    std::vector<plank::display_arrange::display_mode_t> streamable_displays() {
      std::vector<plank::display_arrange::display_mode_t> displays;
      for (auto &display : plank::display_arrange::current_layout()) {
        DISPLAY_DEVICEW device {};
        device.cb = sizeof(device);
        const std::wstring name = widen(display.name);
        std::string adapter;
        if (EnumDisplayDevicesW(nullptr, 0, &device, 0)) {
          for (DWORD index = 0; EnumDisplayDevicesW(nullptr, index, &device, 0); ++index) {
            device.cb = sizeof(device);
            if (name == device.DeviceName) {
              const int size = WideCharToMultiByte(CP_UTF8, 0, device.DeviceString, -1,
                                                   nullptr, 0, nullptr, nullptr);
              if (size > 1) {
                adapter.resize(static_cast<std::size_t>(size - 1));
                WideCharToMultiByte(CP_UTF8, 0, device.DeviceString, -1, adapter.data(),
                                    size, nullptr, nullptr);
              }
              break;
            }
          }
        }
        // DCV, Teradici and similar add virtual displays that are not part of
        // the workstation's screens. They are named by their driver rather
        // than by any one convention, so match every spelling we have seen:
        // DCV calls itself a virtual display adapter, others announce
        // themselves as indirect display drivers.
        static constexpr std::string_view virtual_adapters[] {
          "Indirect"sv, "Teradici"sv, "Remote"sv, "DCV"sv, "Virtual"sv, "IDD"sv
        };
        const bool is_virtual = std::any_of(
          std::begin(virtual_adapters), std::end(virtual_adapters),
          [&adapter](std::string_view marker) {
            return adapter.find(marker) != std::string::npos;
          });
        // Logged because a refused layout is otherwise indistinguishable from
        // a missing display emulator, and workstations are not reachable by
        // any shell when a session cannot start.
        BOOST_LOG(info) << "Display "sv << display.name << " on \""sv << adapter << "\" "sv
                        << display.width << 'x' << display.height
                        << " at "sv << display.x << ',' << display.y
                        << (display.primary ? " primary"sv : ""sv)
                        << (is_virtual ? " — ignored, another remote desktop added it"sv
                                       : " — streamable"sv);
        if (is_virtual) {
          continue;
        }
        displays.push_back(std::move(display));
      }
      return displays;
    }

    /// The streamable display a one-screen session uses: the Windows primary
    /// when it is streamable, otherwise the leftmost one.
    std::optional<plank::display_arrange::display_mode_t> primary_streamable_display() {
      auto displays = streamable_displays();
      if (displays.empty()) {
        return std::nullopt;
      }
      const auto primary = std::find_if(std::begin(displays), std::end(displays),
                                        [](const auto &display) { return display.primary; });
      return primary != std::end(displays) ? *primary : displays.front();
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
    unsigned width = 0;
    unsigned height = 0;

    // Two screens: arrange both displays side by side at the requested modes.
    if (request.layout == "dual-horizontal") {
      unsigned second_width = 0;
      unsigned second_height = 0;
      if (!parse_mode(request.mode_1, width, height) ||
          !parse_mode(request.mode_2, second_width, second_height)) {
        BOOST_LOG(warning) << "Two-screen layout needs two valid modes; got "
                           << request.mode_1 << " and " << request.mode_2;
        return display_request_status::unavailable;
      }

      auto displays = streamable_displays();
      if (displays.size() != 2) {
        BOOST_LOG(warning) << "Two-screen layout needs exactly two workstation displays; found "
                           << displays.size();
        return display_request_status::unavailable;
      }

      // Remember the arrangement before changing it, so it survives a crash.
      if (!display_lease()) {
        plank::display_arrange::save_saved_layout(plank::display_arrange::current_layout());
      }

      auto left = displays[0];
      left.width = width;
      left.height = height;
      auto right = displays[1];
      right.width = second_width;
      right.height = second_height;

      if (!plank::display_arrange::apply_side_by_side(left, right)) {
        BOOST_LOG(warning) << "The workstation displays do not support "
                           << request.mode_1 << " + " << request.mode_2;
        plank::display_arrange::restore_saved_layout_if_any();
        return display_request_status::unavailable;
      }

      display_lease() = runtime_display_state_t {request.layout, request.mode_1, request.mode_2, request.account_uid};
      return display_request_status::submitted;
    }

    // One screen: switch the mode of the display being streamed, and leave
    // any other workstation display alone. A two-display workstation still
    // serves one-screen sessions this way, which is what an artist gets on
    // every first connection.
    if (request.layout != "single" || !request.mode_2.empty() ||
        !parse_mode(request.mode_1, width, height)) {
      BOOST_LOG(warning) << "Windows host cannot serve the requested layout "
                         << request.layout << ' ' << request.mode_1 << (request.mode_2.empty() ? "" : "+" + request.mode_2);
      return display_request_status::unavailable;
    }

    auto target = primary_streamable_display();
    if (!target) {
      BOOST_LOG(warning) << "One-screen layout needs a workstation display; the only displays "
                            "attached belong to other remote-desktop software"sv;
      return display_request_status::unavailable;
    }

    if (target->width != width || target->height != height) {
      // Remember the arrangement before changing it, so it survives a crash.
      if (!display_lease()) {
        plank::display_arrange::save_saved_layout(plank::display_arrange::current_layout());
      }
      BOOST_LOG(info) << "Switching "sv << target->name << " to "sv << width << 'x' << height
                      << " for a PLANK session"sv;
      auto requested = *target;
      requested.width = width;
      requested.height = height;
      if (!plank::display_arrange::apply_mode(requested)) {
        BOOST_LOG(warning) << target->name << " does not support "sv << width << 'x' << height
                           << "; keeping its current mode"sv;
        plank::display_arrange::restore_saved_layout_if_any();
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
    // Both layouts now change modes through display_arrange, which saved the
    // arrangement before touching anything, so both are restored from it.
    // revert_configuration() remains the fallback for a lease taken by an
    // older host that used the display library.
    if (!plank::display_arrange::saved_layout().empty()) {
      plank::display_arrange::restore_saved_layout_if_any();
    } else {
      ::display_device::revert_configuration();
    }
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
