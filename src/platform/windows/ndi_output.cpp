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
#include <filesystem>
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

    /// Forward each line the helper writes to our log.
    void pump_log(HANDLE read_end) {
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
      while (ReadFile(read_end, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
        pending.append(buffer, got);
        if (pending.size() > 16384) {
          pending.resize(16384);
          pending += '\n';
        }
        flush_lines();
      }
      pending += '\n';
      flush_lines();
    }

    class ndi_output_t: public platf::deinit_t {
    public:
      ndi_output_t(std::filesystem::path exe, plank::ndi::helper_options options):
          exe_ {std::move(exe)},
          options_ {std::move(options)} {
        thread_ = std::thread([this] {
          try {
            supervise();
          } catch (const std::exception &e) {
            BOOST_LOG(error) << "NDI supervisor stopped: "sv << e.what();
          } catch (...) {
            BOOST_LOG(error) << "NDI supervisor stopped on an unknown error"sv;
          }
        });
      }

      ~ndi_output_t() override {
        {
          std::lock_guard lock {mutex_};
          stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) {
          thread_.join();  // bounded: see run_once()
        }
      }

    private:
      bool wait(std::chrono::milliseconds period) {
        std::unique_lock lock {mutex_};
        cv_.wait_for(lock, period, [this] {
          return stop_;
        });
        return stop_;
      }

      void supervise() {
        platf::set_thread_name("ndi::supervisor");
        int failures = 0;
        while (!stop_) {
          const auto started = std::chrono::steady_clock::now();
          DWORD exit_code = 0;
          if (!run_once(exit_code)) {
            // Could not even start it.
            if (wait(plank::ndi::backoff_delay(failures++))) {
              return;
            }
            continue;
          }
          if (stop_) {
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
        SECURITY_ATTRIBUTES inheritable {sizeof(inheritable), nullptr, TRUE};

        // stdout/stderr pipe: helper writes, we read.
        HANDLE out_read = nullptr, out_write = nullptr;
        if (!CreatePipe(&out_read, &out_write, &inheritable, 0)) {
          BOOST_LOG(error) << "NDI: CreatePipe failed ["sv << GetLastError() << ']';
          return false;
        }
        handle_t out_read_h {out_read}, out_write_h {out_write};
        SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);

        // stdin pipe: closing our end tells the helper to stop.
        HANDLE in_read = nullptr, in_write = nullptr;
        if (!CreatePipe(&in_read, &in_write, &inheritable, 0)) {
          BOOST_LOG(error) << "NDI: CreatePipe failed ["sv << GetLastError() << ']';
          return false;
        }
        handle_t in_read_h {in_read}, in_write_h {in_write};
        SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);

        // Only the two pipe ends the helper needs may be inherited, not every inheritable handle we hold.
        HANDLE inherit_list[] {in_read, out_write};
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        std::vector<char> attr_buffer(attr_size);
        auto attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buffer.data());
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size) ||
            !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit_list, sizeof(inherit_list), nullptr, nullptr)) {
          BOOST_LOG(error) << "NDI: could not prepare the helper's handle list ["sv << GetLastError() << ']';
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

        // Suspended so it can be put in the job before it runs a single instruction.
        PROCESS_INFORMATION info {};
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
          &info
        );
        DeleteProcThreadAttributeList(attrs);
        if (!created) {
          BOOST_LOG(error) << "NDI: could not start "sv << utf_utils::to_utf8(exe_.wstring()) << " ["sv << GetLastError() << ']';
          return false;
        }
        handle_t process {info.hProcess}, thread {info.hThread};

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

        BOOST_LOG(info) << "NDI helper started (pid "sv << info.dwProcessId << ')';
        std::thread pump {pump_log, out_read};

        // Wait for exit or for a stop request (polled; the wait is short).
        bool exited = false;
        while (!exited) {
          if (WaitForSingleObject(process.h, 250) == WAIT_OBJECT_0) {
            exited = true;
            break;
          }
          std::lock_guard lock {mutex_};
          if (stop_) {
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
          pump.join();  // ends at EOF once the helper is gone
        }
        return true;
      }

      std::filesystem::path exe_;
      plank::ndi::helper_options options_;
      std::mutex mutex_;
      std::condition_variable cv_;
      bool stop_ {false};
      std::thread thread_;
    };
  }  // namespace

  std::unique_ptr<platf::deinit_t> start() {
    if (!config::ndi.enabled) {
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

    BOOST_LOG(info) << "NDI output is on: starting the plank-ndi helper for "sv
                    << (config::ndi.all_outputs ? "all screens"sv : "the primary screen"sv)
                    << " at up to "sv << options.fps << " fps (no audio)"sv;
    return std::make_unique<ndi_output_t>(exe, std::move(options));
  }
}  // namespace platf::ndi_output
