/**
 * @file src/platform/windows/ndi_output.cpp
 * @brief Supervises the plank-ndi helper that publishes the screens over NDI.
 *
 * The NDI work itself (screen capture and sending) lives in tools/plank-ndi.cpp,
 * a separate process, for two reasons:
 * - DXGI Desktop Duplication does not allow a second duplication of an output
 *   from the same process, and this process already duplicates it for the PLANK
 *   stream. A helper process may duplicate it alongside.
 * - The NDI runtime is proprietary and this host is GPL-3. It is only ever
 *   loaded inside the helper, never into this process.
 *
 * This file only starts the helper, forwards its log lines, restarts it with
 * backoff if it dies, and stops it on shutdown. Everything runs on its own
 * threads; start() returns immediately and nothing here can block the host.
 *
 * Process model: Sunshine.exe already runs as SYSTEM inside the console session
 * (launched by sunshinesvc.exe). The helper is created with CreateProcessW from
 * here, so it inherits that token and session; it is placed on winsta0\default
 * and follows the input desktop itself. A kill-on-close job object ties its
 * lifetime to ours, and its stdin pipe doubles as the stop signal.
 */
// standard includes
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <memory>

// platform includes
// clang-format off
#include <Windows.h>
// clang-format on

// local includes
#include "ndi_output.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/plank_ndi.h"
#include "utf_utils.h"

// Declared in src/stream.h, which can't be included after <Windows.h> (WinSock order).
namespace stream::session {
  unsigned running_count();
}  // namespace stream::session

using namespace std::literals;

namespace platf::ndi_output {
  namespace {
    /// How long the helper gets to exit after its stdin closes before it is terminated.
    constexpr auto graceful_stop_wait = 5s;
    /// A run at least this long counts as healthy and resets the restart backoff.
    constexpr auto healthy_run = 60s;
    /// The NDI runtime was missing. Look again now and then (NDI Tools may be installed later).
    constexpr auto runtime_missing_retry = 10min;
    /// Exit code the helper uses for "NDI runtime not installed".
    constexpr DWORD exit_runtime_missing = 2;
    /// Exit code the helper uses for "bad command line arguments". A restart cannot cure that.
    constexpr DWORD exit_bad_arguments = 64;
    /// How long to let the log pump finish by itself after the helper is gone before cancelling its read.
    constexpr auto pump_grace = 2s;

    std::filesystem::path helper_path() {
      wchar_t buffer[MAX_PATH * 4] {};
      const DWORD length = GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
      if (length == 0 || length >= std::size(buffer)) {
        return {};
      }
      return std::filesystem::path {buffer}.parent_path() / L"tools" / L"plank-ndi.exe";
    }

    struct handle_t {
      HANDLE h {};
      handle_t() = default;
      explicit handle_t(HANDLE value):
          h {value} {}
      handle_t(const handle_t &) = delete;
      handle_t &operator=(const handle_t &) = delete;
      ~handle_t() {
        close();
      }
      void close() {
        if (h && h != INVALID_HANDLE_VALUE) {
          CloseHandle(h);
        }
        h = nullptr;
      }
    };

    /// Shared between the supervisor and the log pump thread.
    struct pump_state_t {
      std::atomic<bool> cancel {false};
      std::atomic<bool> done {false};
      std::atomic<HANDLE> thread {nullptr};  ///< real Win32 handle of the pump thread, for CancelSynchronousIo
    };

    /// Forward each line the helper writes to our log. Sets done when it returns.
    void pump_log(HANDLE read_end, pump_state_t &state) {
      // std::thread::native_handle() is not a Win32 handle with winpthreads, so open our own.
      state.thread = OpenThread(THREAD_TERMINATE, FALSE, GetCurrentThreadId());
      std::string pending;
      char buffer[1024];
      DWORD got = 0;
      auto flush_lines = [&] {
        std::size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos) {
          std::string line = pending.substr(0, pos);
          pending.erase(0, pos + 1);
          while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
          }
          if (!line.empty()) {
            BOOST_LOG(info) << "[plank-ndi] "sv << line;
          }
        }
      };
      while (!state.cancel.load() && ReadFile(read_end, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
        pending.append(buffer, got);
        if (pending.size() > 16384) {
          pending.resize(16384);
          pending += '\n';
        }
        flush_lines();
      }
      pending += '\n';
      flush_lines();
      state.done = true;
    }

    class ndi_output_t: public platf::deinit_t {
    public:
      /**
       * @param start_on True for ndi_output = on: run from the start and never switch off.
       */
      ndi_output_t(std::filesystem::path exe, plank::ndi::helper_options options, bool start_on):
          exe_ {std::move(exe)},
          options_ {std::move(options)},
          always_on_ {start_on},
          wanted_ {start_on} {
        {
          std::lock_guard lock {registry_mutex()};
          registry() = this;
        }
        thread_ = std::thread([this] {
          try {
            run();
          } catch (const std::exception &e) {
            BOOST_LOG(error) << "NDI supervisor stopped: "sv << e.what();
          } catch (...) {
            BOOST_LOG(error) << "NDI supervisor stopped on an unknown error"sv;
          }
        });
        if (!always_on_) {
          watchdog_ = std::thread([this] {
            try {
              watch();
            } catch (...) {
              BOOST_LOG(error) << "NDI auto-off watcher stopped on an error"sv;
            }
          });
        }
      }

      ~ndi_output_t() override {
        {
          // Unregister first so no HTTPS handler can reach us while we shut down.
          std::lock_guard lock {registry_mutex()};
          registry() = nullptr;
        }
        {
          std::lock_guard lock {mutex_};
          stop_ = true;
        }
        cv_.notify_all();
        if (watchdog_.joinable()) {
          watchdog_.join();
        }
        if (thread_.joinable()) {
          thread_.join();  // bounded: see run_once()
        }
      }

      static std::mutex &registry_mutex() {
        static std::mutex m;
        return m;
      }

      static ndi_output_t *&registry() {
        static ndi_output_t *instance = nullptr;
        return instance;
      }

      bool always_on() const {
        return always_on_;
      }

      bool running() const {
        std::lock_guard lock {mutex_};
        return wanted_;
      }

      const plank::ndi::helper_options &options() const {
        return options_;
      }

      /// Request the helper on or off. Never blocks beyond the mutex; the supervisor thread does the work.
      /// @return True if the requested state differs from the current one.
      bool request(bool on, bool session_active) {
        bool changed = false;
        {
          std::lock_guard lock {mutex_};
          changed = wanted_ != on;
          wanted_ = on;
          if (on && changed) {
            switched_on_at_ = std::chrono::steady_clock::now();
            session_was_active_ = session_active;
          }
        }
        cv_.notify_all();
        return changed;
      }

    private:
      /// True when the helper should stop running (shutdown or switched off).
      bool should_stop() const {
        std::lock_guard lock {mutex_};
        return stop_ || !wanted_;
      }

      bool wait(std::chrono::milliseconds period) {
        std::unique_lock lock {mutex_};
        cv_.wait_for(lock, period, [this] {
          return stop_ || !wanted_;
        });
        return stop_ || !wanted_;
      }

      /// Outer loop: sleep while off, supervise the helper while on.
      void run() {
        platf::set_thread_name("ndi::supervisor");
        while (true) {
          {
            std::unique_lock lock {mutex_};
            cv_.wait(lock, [this] {
              return stop_ || wanted_;
            });
            if (stop_) {
              return;
            }
          }
          supervise();
        }
      }

      /// Switches NDI off again when ndi_auto_off_minutes / the session rules say so.
      void watch() {
        platf::set_thread_name("ndi::autooff");
        std::unique_lock lock {mutex_};
        while (!stop_) {
          cv_.wait_for(lock, 1s, [this] {
            return stop_.load();
          });
          if (stop_) {
            return;
          }
          if (!wanted_) {
            continue;
          }
          plank::ndi::auto_off_input in;
          in.switched_on_by_request = !always_on_;
          in.session_was_active = session_was_active_;
          in.session_active_now = ::stream::session::running_count() > 0;
          in.elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - switched_on_at_);
          in.timeout_minutes = config::ndi.auto_off_minutes;
          if (plank::ndi::should_auto_off(in)) {
            wanted_ = false;
            BOOST_LOG(info) << "NDI switched off automatically ("sv
                            << (in.session_was_active ? "the PLANK session it was switched on for has ended"sv : "ndi_auto_off_minutes reached"sv) << ')';
            cv_.notify_all();
          }
        }
      }

      void supervise() {
        int failures = 0;
        while (!should_stop()) {
          const auto started = std::chrono::steady_clock::now();
          DWORD exit_code = 0;
          if (!run_once(exit_code)) {
            // Could not even start it.
            if (wait(plank::ndi::backoff_delay(failures++))) {
              return;
            }
            continue;
          }
          if (should_stop()) {
            return;
          }
          if (exit_code == exit_bad_arguments) {
            // Restarting with the same command line would fail the same way, forever.
            BOOST_LOG(error) << "NDI helper rejected its command line (exit code 64); check ndi_source_name and ndi_groups. NDI output is disabled until the host restarts"sv;
            // Back to "off" so the state reported to clients is honest and the outer loop does not spin.
            std::lock_guard lock {mutex_};
            wanted_ = false;
            return;
          }
          if (exit_code == exit_runtime_missing) {
            // The helper already said why through the log pump.
            if (wait(runtime_missing_retry)) {
              return;
            }
            continue;
          }
          if (std::chrono::steady_clock::now() - started >= healthy_run) {
            failures = 0;
          }
          const auto delay = plank::ndi::backoff_delay(failures++);
          BOOST_LOG(warning) << "NDI helper exited with code "sv << exit_code << "; restarting in "sv << delay.count() / 1000 << " s"sv;
          if (wait(delay)) {
            return;
          }
        }
      }

      /**
       * @brief Start the helper and wait for it to exit or for us to be stopped.
       * @return False if it could not be started.
       */
      bool run_once(DWORD &exit_code) {
        // Every pipe end starts non-inheritable so no other child process launched by the host
        // (apps, commands) can pick them up. Only the helper's two ends are made inheritable,
        // for the instant of CreateProcessW, and only those two are in its handle list.
        // stdout/stderr pipe: helper writes, we read.
        HANDLE out_read = nullptr, out_write = nullptr;
        if (!CreatePipe(&out_read, &out_write, nullptr, 0)) {
          BOOST_LOG(error) << "NDI: CreatePipe failed ["sv << GetLastError() << ']';
          return false;
        }
        handle_t out_read_h {out_read}, out_write_h {out_write};

        // stdin pipe: closing our end tells the helper to stop.
        HANDLE in_read = nullptr, in_write = nullptr;
        if (!CreatePipe(&in_read, &in_write, nullptr, 0)) {
          BOOST_LOG(error) << "NDI: CreatePipe failed ["sv << GetLastError() << ']';
          return false;
        }
        handle_t in_read_h {in_read}, in_write_h {in_write};

        // Only the two pipe ends the helper needs may be inherited, not every inheritable handle we hold.
        HANDLE inherit_list[] {in_read, out_write};
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        std::vector<char> attr_buffer(attr_size);
        auto attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buffer.data());
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) {
          BOOST_LOG(error) << "NDI: could not prepare the helper's handle list ["sv << GetLastError() << ']';
          return false;
        }
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit_list, sizeof(inherit_list), nullptr, nullptr)) {
          BOOST_LOG(error) << "NDI: could not prepare the helper's handle list ["sv << GetLastError() << ']';
          DeleteProcThreadAttributeList(attrs);
          return false;
        }

        STARTUPINFOEXW startup {};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = in_read;
        startup.StartupInfo.hStdOutput = out_write;
        startup.StartupInfo.hStdError = out_write;
        startup.lpAttributeList = attrs;

        auto command = utf_utils::from_utf8(plank::ndi::build_helper_command_line(utf_utils::to_utf8(exe_.wstring()), options_));
        std::vector<wchar_t> command_buffer(command.begin(), command.end());
        command_buffer.push_back(L'\0');

        // The handle list only accepts inheritable handles: flip the flag on just the helper's ends.
        if (!SetHandleInformation(in_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
            !SetHandleInformation(out_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
          BOOST_LOG(error) << "NDI: could not mark the helper's pipe ends inheritable ["sv << GetLastError() << ']';
          DeleteProcThreadAttributeList(attrs);
          return false;
        }

        // Suspended so it can be put in the job before it runs a single instruction.
        PROCESS_INFORMATION process_info {};
        const BOOL created = CreateProcessW(
          exe_.c_str(),
          command_buffer.data(),
          nullptr,
          nullptr,
          TRUE,
          CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
          nullptr,
          exe_.parent_path().c_str(),
          &startup.StartupInfo,
          &process_info
        );
        DeleteProcThreadAttributeList(attrs);
        SetHandleInformation(in_read, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(out_write, HANDLE_FLAG_INHERIT, 0);
        if (!created) {
          BOOST_LOG(error) << "NDI: could not start "sv << utf_utils::to_utf8(exe_.wstring()) << " ["sv << GetLastError() << ']';
          return false;
        }
        handle_t process {process_info.hProcess}, thread {process_info.hThread};

        // Kill the helper if this process goes away, however it goes away.
        handle_t job {CreateJobObjectW(nullptr, nullptr)};
        if (job.h) {
          JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
          limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
          if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
              !AssignProcessToJobObject(job.h, process.h)) {
            BOOST_LOG(warning) << "NDI: could not attach the helper to a job object ["sv << GetLastError() << ']';
          }
        }
        ResumeThread(thread.h);

        // The helper owns its copies of the pipe ends now.
        in_read_h.close();
        out_write_h.close();

        BOOST_LOG(info) << "NDI helper started (pid "sv << process_info.dwProcessId << ')';
        pump_state_t pump_state;
        std::thread pump {pump_log, out_read, std::ref(pump_state)};

        // Wait for exit or for a stop request (polled; the wait is short).
        bool exited = false;
        while (!exited) {
          if (WaitForSingleObject(process.h, 250) == WAIT_OBJECT_0) {
            exited = true;
            break;
          }
          if (should_stop()) {
            break;
          }
        }

        if (!exited) {
          // Graceful: closing stdin makes the helper unwind and exit.
          in_write_h.close();
          if (WaitForSingleObject(process.h, static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(graceful_stop_wait).count())) != WAIT_OBJECT_0) {
            BOOST_LOG(warning) << "NDI helper did not stop in time; terminating it"sv;
            TerminateProcess(process.h, 1);
            WaitForSingleObject(process.h, 2000);
          }
        }
        exit_code = 0;
        GetExitCodeProcess(process.h, &exit_code);
        process.close();
        job.close();  // also kills anything the helper may have left behind
        if (pump.joinable()) {
          // Normally ends at EOF once the helper is gone. If some other process still holds a copy
          // of the write end there is no EOF, so after a grace period cancel the blocked read
          // (repeatedly: the thread may not have entered ReadFile yet) instead of hanging shutdown.
          const auto deadline = std::chrono::steady_clock::now() + pump_grace;
          while (!pump_state.done && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(20ms);
          }
          if (!pump_state.done) {
            pump_state.cancel = true;
            for (int attempt = 0; attempt < 50 && !pump_state.done; ++attempt) {
              if (HANDLE pump_thread = pump_state.thread.load()) {
                CancelSynchronousIo(pump_thread);
              }
              std::this_thread::sleep_for(20ms);
            }
          }
          pump.join();
          if (HANDLE pump_thread = pump_state.thread.load()) {
            CloseHandle(pump_thread);
          }
        }
        return true;
      }

      std::filesystem::path exe_;
      plank::ndi::helper_options options_;
      const bool always_on_;
      mutable std::mutex mutex_;
      std::condition_variable cv_;
      std::atomic<bool> stop_ {false};
      bool wanted_ {false};  ///< Guarded by mutex_. The helper should be running.
      bool session_was_active_ {false};  ///< Guarded by mutex_.
      std::chrono::steady_clock::time_point switched_on_at_ {};  ///< Guarded by mutex_.
      std::thread thread_;
      std::thread watchdog_;
    };

    std::string env_value(const char *name) {
      const char *value = std::getenv(name);
      return value ? std::string {value} : std::string {};
    }

    /// Is the NDI runtime DLL on disk? Same search order as the helper, without loading it.
    bool runtime_installed() {
      static std::mutex m;
      static std::chrono::steady_clock::time_point checked_at {};
      static bool cached = false;
      static bool have_cache = false;
      std::lock_guard lock {m};
      const auto now = std::chrono::steady_clock::now();
      if (have_cache && now - checked_at < 10s) {
        return cached;
      }
      bool found = false;
      for (const auto &path : plank::ndi::runtime_candidates(env_value)) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(std::filesystem::path {utf_utils::from_utf8(path)}, ec)) {
          found = true;
          break;
        }
      }
      cached = found;
      checked_at = now;
      have_cache = true;
      return found;
    }

    std::string computer_name() {
      wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] {};
      DWORD size = static_cast<DWORD>(std::size(buffer));
      if (!GetComputerNameW(buffer, &size)) {
        return {};
      }
      return utf_utils::to_utf8(std::wstring {buffer, size});
    }
  }  // namespace

  std::unique_ptr<platf::deinit_t> start() {
    if (!config::ndi.enabled && !config::ndi.available) {
      return nullptr;
    }

    const auto exe = helper_path();
    std::error_code ec;
    if (exe.empty() || !std::filesystem::exists(exe, ec)) {
      BOOST_LOG(warning) << "NDI output is on but tools\\plank-ndi.exe was not found next to the host; NDI output is disabled"sv;
      return nullptr;
    }

    plank::ndi::helper_options options;
    options.fps = plank::ndi::clamp_fps(config::ndi.fps);
    options.scope = config::ndi.all_outputs ? plank::ndi::scope_e::all : plank::ndi::scope_e::primary;
    options.name = config::ndi.source_name;
    options.groups = config::ndi.groups;

    if (config::ndi.available) {
      BOOST_LOG(info) << "NDI output is available: it stays off until someone switches it on in the PLANK client (ndi_auto_off_minutes = "sv
                      << config::ndi.auto_off_minutes << ')';
    } else {
      BOOST_LOG(info) << "NDI output is on: starting the plank-ndi helper for "sv
                      << (config::ndi.all_outputs ? "all screens"sv : "the primary screen"sv)
                      << " at up to "sv << options.fps << " fps (no audio)"sv;
    }
    return std::make_unique<ndi_output_t>(exe, std::move(options), config::ndi.enabled);
  }

  status_t status() {
    status_t result;
    std::lock_guard lock {ndi_output_t::registry_mutex()};
    auto *self = ndi_output_t::registry();
    if (!self) {
      return result;
    }
    const bool usable = runtime_installed();
    result.report = plank::ndi::report_state(self->always_on() ? plank::ndi::mode_e::on : plank::ndi::mode_e::available, usable, self->running());
    if (result.report == plank::ndi::report_e::on || result.report == plank::ndi::report_e::always) {
      result.source_names = plank::ndi::source_label(self->options().name, computer_name(), self->options().scope == plank::ndi::scope_e::all);
    }
    return result;
  }

  toggle_result_e set_enabled(bool on, bool session_active, std::string_view who) {
    std::lock_guard lock {ndi_output_t::registry_mutex()};
    auto *self = ndi_output_t::registry();
    if (!self) {
      return toggle_result_e::unavailable;
    }
    if (self->always_on()) {
      return toggle_result_e::always_on;
    }
    if (on && !runtime_installed()) {
      return toggle_result_e::unavailable;
    }
    if (self->request(on, session_active)) {
      BOOST_LOG(info) << "NDI switched "sv << (on ? "on"sv : "off"sv) << " by "sv << who;
    }
    return toggle_result_e::ok;
  }
}  // namespace platf::ndi_output
