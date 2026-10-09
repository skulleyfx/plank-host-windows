/**
 * @file src/platform/windows/ndi_output.cpp
 * @brief Publishes the host's screens as NDI sources on the LAN.
 *
 * Design notes
 *
 * - The NDI runtime is loaded with LoadLibrary at run time and only five C
 *   entry points are resolved (see ndi_runtime.h for why: the host is GPL-3 and
 *   the NDI SDK is not).
 * - Capture reuses the host's own Desktop Duplication RAM backend
 *   (platf::display with mem_type_e::system), driven by this file's own
 *   capture loop. That backend already copies the GPU frame into a CPU staging
 *   texture and hands back a BGRA buffer, handles display mode changes and
 *   desktop switches by returning capture_e::reinit/error, and paces itself to
 *   the configured frame rate.
 * - NDI uses its OWN display instance and thread, separate from any PLANK
 *   streaming session. A PLANK session starts and stops its capture with the
 *   client; NDI has to run with nobody connected. Separate Desktop Duplication
 *   sessions of the same output are allowed, so the PLANK stream is never
 *   touched, blocked or slowed by this code: no shared locks, no shared D3D
 *   device, no shared frame pool.
 */
// standard includes
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// platform includes
// clang-format off
#include <Windows.h>
// clang-format on

// local includes
#include "ndi_output.h"
#include "ndi_runtime.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/plank_ndi.h"
#include "src/video.h"
#include "utf_utils.h"

using namespace std::literals;

namespace platf::ndi_output {
  namespace {
    namespace nabi = platf::ndi_abi;

    /// How often the supervisor looks for added or removed displays.
    constexpr auto rescan_interval = 30s;
    /// Rescan sooner when no display could be enumerated (lock screen, mode change).
    constexpr auto rescan_interval_empty = 3s;

    std::string env_utf8(const char *name) {
      const auto wide_name = utf_utils::from_utf8(name);
      std::wstring buffer(512, L'\0');
      DWORD length = GetEnvironmentVariableW(wide_name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
      if (length > buffer.size()) {
        buffer.resize(length);
        length = GetEnvironmentVariableW(wide_name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
      }
      if (length == 0 || length >= buffer.size()) {
        return {};
      }
      buffer.resize(length);
      return utf_utils::to_utf8(buffer);
    }

    std::string computer_name() {
      wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] {};
      DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
      if (GetComputerNameW(buffer, &size) && size > 0) {
        return utf_utils::to_utf8(std::wstring {buffer, size});
      }
      return env_utf8("COMPUTERNAME");
    }

    /**
     * @brief The loaded NDI runtime and the few entry points we use.
     */
    struct runtime_t {
      HMODULE module {};
      nabi::initialize_fn initialize {};
      nabi::destroy_fn destroy {};
      nabi::send_create_fn send_create {};
      nabi::send_destroy_fn send_destroy {};
      nabi::send_video_v2_fn send_video_v2 {};
      bool initialized {};

      runtime_t() = default;
      runtime_t(const runtime_t &) = delete;
      runtime_t &operator=(const runtime_t &) = delete;

      ~runtime_t() {
        if (initialized && destroy) {
          destroy();
        }
        if (module) {
          FreeLibrary(module);
        }
      }

      /**
       * @brief Find and load the runtime. Returns false when it is not installed
       * or is too old / broken to use.
       */
      bool load() {
        for (const auto &path : plank::ndi::runtime_candidates(env_utf8)) {
          const auto wide = utf_utils::from_utf8(path);
          const bool absolute = path.find('\\') != std::string::npos;
          // Absolute paths load from their own directory; the bare name is only
          // searched in the application and system directories, never in the
          // current directory or PATH.
          module = LoadLibraryExW(wide.c_str(), nullptr, absolute ? LOAD_WITH_ALTERED_SEARCH_PATH : LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
          if (!module) {
            continue;
          }
          initialize = reinterpret_cast<nabi::initialize_fn>(GetProcAddress(module, "NDIlib_initialize"));
          destroy = reinterpret_cast<nabi::destroy_fn>(GetProcAddress(module, "NDIlib_destroy"));
          send_create = reinterpret_cast<nabi::send_create_fn>(GetProcAddress(module, "NDIlib_send_create"));
          send_destroy = reinterpret_cast<nabi::send_destroy_fn>(GetProcAddress(module, "NDIlib_send_destroy"));
          send_video_v2 = reinterpret_cast<nabi::send_video_v2_fn>(GetProcAddress(module, "NDIlib_send_send_video_v2"));
          if (initialize && destroy && send_create && send_destroy && send_video_v2) {
            BOOST_LOG(info) << "NDI runtime loaded from "sv << path;
            // NDIlib_initialize returns false on CPUs the runtime does not support.
            if (!initialize()) {
              BOOST_LOG(warning) << "NDI output is on but the NDI runtime refused to initialize (unsupported CPU?)"sv;
              return false;
            }
            initialized = true;
            return true;
          }
          BOOST_LOG(warning) << "Found "sv << path << " but it does not export the expected NDI functions; ignoring it"sv;
          FreeLibrary(module);
          module = nullptr;
        }
        return false;
      }
    };

    /**
     * @brief State shared by the supervisor and capture threads.
     */
    struct shared_t {
      std::mutex mutex;
      std::condition_variable cv;
      std::atomic<bool> stop {false};

      /// Sleep up to `period`; returns true if `stop` or `worker_stop` was raised.
      bool wait(std::chrono::milliseconds period, const std::atomic<bool> &worker_stop) {
        std::unique_lock lock {mutex};
        cv.wait_for(lock, period, [&] {
          return stop.load() || worker_stop.load();
        });
        return stop.load() || worker_stop.load();
      }
    };

    /**
     * @brief Captures one screen and sends it as one NDI source.
     */
    class worker_t {
    public:
      worker_t(runtime_t &runtime, shared_t &shared, std::string capture_name, std::string source_name, int fps):
          runtime_ {runtime},
          shared_ {shared},
          capture_name_ {std::move(capture_name)},
          source_name_ {std::move(source_name)},
          fps_ {fps} {
        thread_ = std::thread([this] {
          try {
            run();
          } catch (const std::exception &e) {
            BOOST_LOG(error) << "NDI output for "sv << capture_name_ << " stopped: "sv << e.what();
          } catch (...) {
            BOOST_LOG(error) << "NDI output for "sv << capture_name_ << " stopped on an unknown error"sv;
          }
        });
      }

      worker_t(const worker_t &) = delete;
      worker_t &operator=(const worker_t &) = delete;

      ~worker_t() {
        request_stop();
        if (thread_.joinable()) {
          thread_.join();
        }
      }

      void request_stop() {
        {
          std::lock_guard lock {shared_.mutex};
          stop_ = true;
        }
        shared_.cv.notify_all();
      }

      const std::string &capture_name() const {
        return capture_name_;
      }

    private:
      bool should_stop() const {
        return stop_.load() || shared_.stop.load();
      }

      void run() {
        platf::set_thread_name("ndi::capture");

        // The source is published as soon as the sender exists, even while the
        // desktop cannot be captured (lock screen, display change), so it does
        // not vanish from receivers' source lists.
        nabi::send_create_t create {};
        create.p_ndi_name = source_name_.c_str();
        create.p_groups = nullptr;
        create.clock_video = false;  // we pace ourselves from the capture loop
        create.clock_audio = false;
        auto sender = runtime_.send_create(&create);
        if (!sender) {
          BOOST_LOG(error) << "NDI could not create the source '"sv << source_name_ << '\'';
          return;
        }
        BOOST_LOG(info) << "NDI source '"sv << source_name_ << "' published for "sv << capture_name_
                        << " at up to "sv << fps_ << " fps"sv;

        bool reported_unavailable = false;
        while (!should_stop()) {
          video::config_t config {};
          config.framerate = fps_;
          config.framerateX100 = 0;
          config.capture_source = video::capture_source_e::ddup;  // no capture border, predictable

          auto display = platf::display(platf::mem_type_e::system, capture_name_, config);
          if (!display) {
            if (!reported_unavailable) {
              BOOST_LOG(info) << "NDI output: "sv << capture_name_ << " cannot be captured right now (locked or changing mode?); retrying"sv;
              reported_unavailable = true;
            }
            if (wait(2s)) {
              break;
            }
            continue;
          }
          reported_unavailable = false;

          const auto status = capture_loop(sender, display);
          display.reset();

          if (should_stop()) {
            break;
          }
          BOOST_LOG(info) << "NDI output: capture of "sv << capture_name_ << " paused (status "sv
                          << static_cast<int>(status) << "); restarting"sv;
          if (wait(1s)) {
            break;
          }
        }

        runtime_.send_destroy(sender);
        BOOST_LOG(info) << "NDI source '"sv << source_name_ << "' stopped"sv;
      }

      bool wait(std::chrono::milliseconds period) {
        return shared_.wait(period, stop_);
      }

      platf::capture_e capture_loop(nabi::send_instance_t sender, const std::shared_ptr<platf::display_t> &display) {
        // One buffer is enough: sends are synchronous, so by the time the
        // capture backend asks for a free image the previous one is done with.
        std::shared_ptr<platf::img_t> buffer;
        bool have_frame = false;
        bool dirty = false;
        auto last_send = std::chrono::steady_clock::now() - 1h;

        auto pull = [&](std::shared_ptr<platf::img_t> &out) -> bool {
          if (should_stop()) {
            out.reset();
            return false;
          }
          if (!buffer) {
            buffer = display->alloc_img();
          }
          out = buffer;
          return static_cast<bool>(out);
        };

        auto push = [&](std::shared_ptr<platf::img_t> &&img, bool captured) -> bool {
          if (should_stop()) {
            return false;
          }
          if (captured && img) {
            have_frame = true;
          }
          if (!have_frame || !buffer) {
            return true;
          }

          const auto now = std::chrono::steady_clock::now();
          if (plank::ndi::should_send(captured, dirty, now - last_send, fps_)) {
            send(sender, *buffer);
            last_send = now;
            dirty = false;
          } else if (captured) {
            dirty = true;
          }
          return true;
        };

        bool cursor = true;
        return display->capture(push, pull, &cursor);
      }

      void send(nabi::send_instance_t sender, const platf::img_t &img) {
        if (!img.data || img.width <= 0 || img.height <= 0 || img.pixel_pitch != 4 || img.row_pitch < img.width * 4) {
          return;
        }
        nabi::video_frame_v2_t frame {};
        frame.xres = img.width;
        frame.yres = img.height;
        frame.FourCC = nabi::fourcc_bgrx;
        frame.frame_rate_N = fps_;
        frame.frame_rate_D = 1;
        frame.picture_aspect_ratio = static_cast<float>(img.width) / static_cast<float>(img.height);
        frame.frame_format_type = nabi::frame_format_progressive;
        frame.timecode = nabi::timecode_synthesize;
        frame.p_data = img.data;
        frame.line_stride_in_bytes = img.row_pitch;
        frame.p_metadata = nullptr;
        // Synchronous: returns once the runtime has taken its copy, so the
        // buffer can be reused immediately.
        runtime_.send_video_v2(sender, &frame);
      }

      runtime_t &runtime_;
      shared_t &shared_;
      std::string capture_name_;
      std::string source_name_;
      int fps_;
      std::atomic<bool> stop_ {false};
      std::thread thread_;
    };

    /**
     * @brief Owns the runtime, the supervisor thread and the per-screen workers.
     */
    class ndi_output_t: public platf::deinit_t {
    public:
      explicit ndi_output_t(std::unique_ptr<runtime_t> runtime):
          runtime_ {std::move(runtime)} {
        supervisor_ = std::thread([this] {
          try {
            supervise();
          } catch (const std::exception &e) {
            BOOST_LOG(error) << "NDI output supervisor stopped: "sv << e.what();
          } catch (...) {
            BOOST_LOG(error) << "NDI output supervisor stopped on an unknown error"sv;
          }
        });
      }

      ~ndi_output_t() override {
        {
          std::lock_guard lock {shared_.mutex};
          shared_.stop = true;
        }
        shared_.cv.notify_all();
        if (supervisor_.joinable()) {
          supervisor_.join();
        }
        workers_.clear();  // joins the capture threads before the runtime is unloaded
      }

    private:
      void supervise() {
        platf::set_thread_name("ndi::supervisor");
        const auto computer = computer_name();
        const int fps = plank::ndi::clamp_fps(config::ndi.fps);
        const auto scope = config::ndi.all_outputs ? plank::ndi::scope_e::all : plank::ndi::scope_e::primary;
        const std::atomic<bool> never {false};

        std::vector<std::string> current;
        while (!shared_.stop.load()) {
          std::vector<plank::ndi::output_ref> refs;
          for (const auto &info : platf::display_infos(platf::mem_type_e::system)) {
            refs.push_back({info.capture_name, info.x, info.y, info.primary});
          }
          const auto selected = plank::ndi::select_outputs(std::move(refs), scope);

          std::vector<std::string> names;
          for (const auto &ref : selected) {
            names.push_back(ref.capture_name);
          }

          if (!selected.empty() && names != current) {
            workers_.clear();  // stops and joins the old set
            current = names;
            const int count = static_cast<int>(selected.size());
            for (int i = 0; i < count; ++i) {
              workers_.push_back(std::make_unique<worker_t>(
                *runtime_,
                shared_,
                selected[i].capture_name,
                plank::ndi::source_name(config::ndi.source_name, computer, i + 1, count),
                fps
              ));
            }
          }

          const std::chrono::milliseconds pause = selected.empty() ? rescan_interval_empty : rescan_interval;
          shared_.wait(pause, never);
        }
      }

      std::unique_ptr<runtime_t> runtime_;
      shared_t shared_;
      std::vector<std::unique_ptr<worker_t>> workers_;
      std::thread supervisor_;
    };
  }  // namespace

  std::unique_ptr<platf::deinit_t> start() {
    if (!config::ndi.enabled) {
      return nullptr;
    }

    auto runtime = std::make_unique<runtime_t>();
    if (!runtime->load()) {
      BOOST_LOG(warning) << "NDI output is on but the NDI runtime is not installed; install NDI Tools"sv;
      return nullptr;
    }

    BOOST_LOG(info) << "NDI output is on: publishing "sv
                    << (config::ndi.all_outputs ? "all screens"sv : "the primary screen"sv)
                    << " at up to "sv << plank::ndi::clamp_fps(config::ndi.fps) << " fps (no audio)"sv;
    return std::make_unique<ndi_output_t>(std::move(runtime));
  }
}  // namespace platf::ndi_output
