/**
 * @file tools/plank-ndi.cpp
 * @brief Helper process that publishes the machine's screens as NDI sources.
 *
 * Why a separate process:
 * - DXGI Desktop Duplication refuses a second duplication of an output from the
 *   same process, and Sunshine.exe already duplicates the output for the PLANK
 *   stream. A different process may duplicate it as well (up to four at once),
 *   so NDI and a live PLANK stream coexist.
 * - The host is GPL-3 and the NDI runtime is proprietary. This helper is the
 *   only code that loads the NDI runtime DLL, at run time and only from this
 *   process; nothing from the NDI SDK is bundled, linked or copied (see
 *   src/platform/windows/ndi_runtime.h).
 *
 * Lifetime: Sunshine.exe starts this program with the same token, session and
 * window station, and keeps its stdin pipe open. When that pipe closes (the host
 * stopped us, or died) the helper shuts down. Options arrive on the command
 * line (see plank::ndi::parse_helper_args). Log lines go to stderr, which the
 * host forwards to its own log.
 *
 * Exit codes: 0 normal stop, 2 NDI runtime not installed, 3 internal fault that
 * a restart should cure, 64 bad arguments.
 */
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <Windows.h>
#include <d3d11.h>
#include <dxgi1_5.h>
// clang-format on

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "src/platform/windows/ndi_runtime.h"
#include "src/plank_ndi.h"

using namespace std::literals;
namespace nabi = platf::ndi_abi;
namespace pn = plank::ndi;

namespace {
  // ---------------------------------------------------------------- logging
  std::mutex log_mutex;

  void log_line(const std::string &text) {
    std::lock_guard lock {log_mutex};
    std::fprintf(stderr, "%s\n", text.c_str());
    std::fflush(stderr);
  }

  std::string to_utf8(const std::wstring &wide) {
    if (wide.empty()) {
      return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), out.data(), size, nullptr, nullptr);
    return out;
  }

  std::wstring to_wide(const std::string &utf8) {
    if (utf8.empty()) {
      return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), size);
    return out;
  }

  std::string env_utf8(const char *name) {
    const auto wide_name = to_wide(name);
    std::wstring buffer(1024, L'\0');
    DWORD length = GetEnvironmentVariableW(wide_name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
      return {};
    }
    buffer.resize(length);
    return to_utf8(buffer);
  }

  std::string computer_name() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size) && size > 0) {
      return to_utf8(std::wstring {buffer, size});
    }
    return env_utf8("COMPUTERNAME");
  }

  // ------------------------------------------------------------ small COM RAII
  template<class T>
  class com_ptr {
  public:
    com_ptr() = default;
    com_ptr(const com_ptr &) = delete;
    com_ptr &operator=(const com_ptr &) = delete;
    ~com_ptr() {
      reset();
    }
    void reset() {
      if (ptr_) {
        ptr_->Release();
        ptr_ = nullptr;
      }
    }
    T **put() {
      reset();
      return &ptr_;
    }
    void **put_void() {
      return reinterpret_cast<void **>(put());
    }
    T *get() const {
      return ptr_;
    }
    T *operator->() const {
      return ptr_;
    }
    explicit operator bool() const {
      return ptr_ != nullptr;
    }

  private:
    T *ptr_ = nullptr;
  };

  // ------------------------------------------------------------ NDI runtime
  struct runtime_t {
    HMODULE module {};
    nabi::initialize_fn initialize {};
    nabi::destroy_fn destroy {};
    nabi::send_create_fn send_create {};
    nabi::send_destroy_fn send_destroy {};
    nabi::send_video_v2_fn send_video_v2 {};
    bool initialized {};

    /// Load the runtime from a fully qualified path only. The flags make Windows
    /// resolve the DLL's own dependencies from its directory and the default
    /// system locations, never from the current directory or PATH.
    bool load() {
      for (const auto &path : pn::runtime_candidates(env_utf8)) {
        module = LoadLibraryExW(to_wide(path).c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!module) {
          continue;
        }
        initialize = reinterpret_cast<nabi::initialize_fn>(GetProcAddress(module, "NDIlib_initialize"));
        destroy = reinterpret_cast<nabi::destroy_fn>(GetProcAddress(module, "NDIlib_destroy"));
        send_create = reinterpret_cast<nabi::send_create_fn>(GetProcAddress(module, "NDIlib_send_create"));
        send_destroy = reinterpret_cast<nabi::send_destroy_fn>(GetProcAddress(module, "NDIlib_send_destroy"));
        send_video_v2 = reinterpret_cast<nabi::send_video_v2_fn>(GetProcAddress(module, "NDIlib_send_send_video_v2"));
        if (initialize && destroy && send_create && send_destroy && send_video_v2) {
          log_line("NDI runtime loaded from " + path);
          if (!initialize()) {
            log_line("NDI runtime refused to initialize (unsupported CPU?)");
            return false;
          }
          initialized = true;
          return true;
        }
        log_line("Found " + path + " but it does not export the expected NDI functions; ignoring it");
        FreeLibrary(module);
        module = nullptr;
      }
      return false;
    }
  };

  // ------------------------------------------------------------ shared state
  struct shared_t {
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> stop {false};

    void request_stop() {
      {
        std::lock_guard lock {mutex};
        stop = true;
      }
      cv.notify_all();
    }

    /// Wait until `deadline`, a stop request, or `worker_stop`. True if stopping.
    bool wait_until(std::chrono::steady_clock::time_point deadline, const std::atomic<bool> &worker_stop) {
      std::unique_lock lock {mutex};
      cv.wait_until(lock, deadline, [&] {
        return stop.load() || worker_stop.load();
      });
      return stop.load() || worker_stop.load();
    }

    bool wait_for(std::chrono::milliseconds period, const std::atomic<bool> &worker_stop) {
      return wait_until(std::chrono::steady_clock::now() + period, worker_stop);
    }

    /// Raise a per-worker stop flag and wake every waiter.
    void stop_worker(std::atomic<bool> &flag) {
      {
        std::lock_guard lock {mutex};
        flag = true;
      }
      cv.notify_all();
    }
  };

  // ---------------------------------------------------------- display set
  struct screen_t {
    std::wstring device_name;  ///< GDI name, also the DXGI output DeviceName.
    int x {}, y {}, width {}, height {};
    bool primary {};
  };

  /// Enumerate attached displays with plain GDI calls. Unlike a DuplicateOutput
  /// probe this never touches Desktop Duplication, so it cannot disturb PLANK.
  std::vector<screen_t> enumerate_screens() {
    std::vector<screen_t> screens;
    for (DWORD i = 0;; ++i) {
      DISPLAY_DEVICEW device {};
      device.cb = sizeof(device);
      if (!EnumDisplayDevicesW(nullptr, i, &device, 0)) {
        break;
      }
      if (!(device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) || (device.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER)) {
        continue;
      }
      DEVMODEW mode {};
      mode.dmSize = sizeof(mode);
      if (!EnumDisplaySettingsExW(device.DeviceName, ENUM_CURRENT_SETTINGS, &mode, 0) || mode.dmPelsWidth == 0 || mode.dmPelsHeight == 0) {
        continue;
      }
      screens.push_back({device.DeviceName, mode.dmPosition.x, mode.dmPosition.y, static_cast<int>(mode.dmPelsWidth), static_cast<int>(mode.dmPelsHeight), (device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0});
    }
    return screens;
  }

  std::string signature(const std::vector<screen_t> &screens) {
    std::string out;
    for (const auto &s : screens) {
      out += to_utf8(s.device_name) + '@' + std::to_string(s.x) + ',' + std::to_string(s.y) + ' ' + std::to_string(s.width) + 'x' + std::to_string(s.height) + (s.primary ? "P;" : ";");
    }
    return out;
  }

  // ---------------------------------------------------------- desktops
  /// Name of the desktop currently receiving input, or empty when it cannot be
  /// opened (which is treated as "secure": fail closed).
  std::wstring input_desktop_name() {
    HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!desktop) {
      return {};
    }
    wchar_t name[128] {};
    DWORD needed = 0;
    if (!GetUserObjectInformationW(desktop, UOI_NAME, name, sizeof(name), &needed)) {
      name[0] = L'\0';
    }
    CloseDesktop(desktop);
    return name;
  }

  /// The lock screen, sign-in screen and UAC prompts live on the Winlogon desktop.
  bool secure_desktop_active() {
    const auto name = input_desktop_name();
    return name.empty() || _wcsicmp(name.c_str(), L"Default") != 0;
  }

  /// Attach this thread to the desktop that currently receives input, as the
  /// host's own capture does (syncThreadDesktop in misc.cpp).
  void sync_thread_desktop() {
    HDESK desktop = OpenInputDesktop(DF_ALLOWOTHERACCOUNTHOOK, FALSE, GENERIC_ALL);
    if (!desktop) {
      return;
    }
    SetThreadDesktop(desktop);
    CloseDesktop(desktop);
  }

  // ---------------------------------------------------------- duplication
  std::string hex(HRESULT hr) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%08lX", static_cast<unsigned long>(hr));
    return buffer;
  }

  struct duplication_t {
    com_ptr<ID3D11Device> device;
    com_ptr<ID3D11DeviceContext> context;
    com_ptr<IDXGIOutputDuplication> dup;
    com_ptr<ID3D11Texture2D> staging;
    D3D11_TEXTURE2D_DESC staging_desc {};

    /// Returns an empty string on success, otherwise a reason.
    std::string init(const std::wstring &device_name) {
      com_ptr<IDXGIFactory1> factory;
      if (FAILED(CreateDXGIFactory1(IID_IDXGIFactory1, factory.put_void()))) {
        return "CreateDXGIFactory1 failed";
      }

      com_ptr<IDXGIAdapter1> adapter;
      com_ptr<IDXGIOutput> output;
      bool found = false;
      for (UINT a = 0; !found && factory->EnumAdapters1(a, adapter.put()) != DXGI_ERROR_NOT_FOUND; ++a) {
        for (UINT o = 0; adapter->EnumOutputs(o, output.put()) != DXGI_ERROR_NOT_FOUND; ++o) {
          DXGI_OUTPUT_DESC desc;
          if (SUCCEEDED(output->GetDesc(&desc)) && desc.AttachedToDesktop && device_name == desc.DeviceName) {
            found = true;
            break;
          }
        }
      }
      if (!found) {
        return "output not found";
      }

      const D3D_FEATURE_LEVEL levels[] {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0};
      HRESULT hr = D3D11CreateDevice(adapter.get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, 0, levels, ARRAYSIZE(levels), D3D11_SDK_VERSION, device.put(), nullptr, context.put());
      if (FAILED(hr)) {
        return "D3D11CreateDevice failed 0x" + hex(hr);
      }

      // Asking for BGRA8 only makes Windows hand over an SDR picture even when
      // HDR is switched on, which is what NDI receivers expect.
      com_ptr<IDXGIOutput5> output5;
      if (SUCCEEDED(output->QueryInterface(IID_IDXGIOutput5, output5.put_void()))) {
        const DXGI_FORMAT formats[] {DXGI_FORMAT_B8G8R8A8_UNORM};
        hr = output5->DuplicateOutput1(device.get(), 0, 1, formats, dup.put());
      } else {
        com_ptr<IDXGIOutput1> output1;
        if (FAILED(output->QueryInterface(IID_IDXGIOutput1, output1.put_void()))) {
          return "IDXGIOutput1 unavailable";
        }
        hr = output1->DuplicateOutput(device.get(), dup.put());
      }
      if (FAILED(hr)) {
        return "DuplicateOutput failed 0x" + hex(hr);
      }
      return {};
    }
  };

  // ---------------------------------------------------------- one screen
  class worker_t {
  public:
    worker_t(runtime_t &runtime, shared_t &shared, screen_t screen, std::string source_name, std::string groups, int fps):
        runtime_ {runtime},
        shared_ {shared},
        screen_ {std::move(screen)},
        source_name_ {std::move(source_name)},
        groups_ {std::move(groups)},
        fps_ {fps} {
      thread_ = std::thread([this] {
        try {
          run();
        } catch (const std::exception &e) {
          log_line(std::string {"worker stopped: "} + e.what());
        } catch (...) {
          log_line("worker stopped on an unknown error");
        }
        done_ = true;
      });
    }

    worker_t(const worker_t &) = delete;
    worker_t &operator=(const worker_t &) = delete;

    ~worker_t() {
      // stop_all() joins finished workers; one that never finished is left
      // running (detached) because the process is about to exit.
      if (thread_.joinable()) {
        thread_.detach();
      }
    }

    void request_stop() {
      shared_.stop_worker(stop_);
    }
    bool finished() const {
      return done_;
    }
    void join() {
      if (thread_.joinable()) {
        thread_.join();
      }
    }

  private:
    bool stopping() const {
      return stop_.load() || shared_.stop.load();
    }
    bool wait_for(std::chrono::milliseconds period) {
      return shared_.wait_for(period, stop_);
    }

    void run() {
      // Publish the source right away so it stays in receivers' lists while
      // the desktop is locked or being switched.
      nabi::send_create_t create {};
      create.p_ndi_name = source_name_.c_str();
      create.p_groups = groups_.empty() ? nullptr : groups_.c_str();
      create.clock_video = false;  // paced by the capture loop below
      create.clock_audio = false;
      auto sender = runtime_.send_create(&create);
      if (!sender) {
        log_line("NDI could not create the source '" + source_name_ + "'");
        return;
      }
      log_line("NDI source '" + source_name_ + "' published for " + to_utf8(screen_.device_name) + " at up to " + std::to_string(fps_) + " fps");

      int failures = 0;
      bool reported_paused = false;
      bool reported_secure = false;
      while (!stopping()) {
        // Lock screen, sign-in and UAC: show black, never the real picture.
        if (secure_desktop_active()) {
          if (!reported_secure) {
            log_line("Secure desktop is active; sending black for " + source_name_);
            reported_secure = true;
          }
          send_black(sender);
          if (wait_for(pn::idle_resend_interval)) {
            break;
          }
          continue;
        }
        if (reported_secure) {
          log_line("Secure desktop is gone; resuming capture for " + source_name_);
          reported_secure = false;
        }

        sync_thread_desktop();
        duplication_t d;
        const auto reason = d.init(screen_.device_name);
        if (!reason.empty()) {
          if (!reported_paused) {
            log_line("Cannot capture " + to_utf8(screen_.device_name) + " right now (" + reason + "); retrying with backoff");
            reported_paused = true;
          }
          if (wait_for(pn::backoff_delay(failures++))) {
            break;
          }
          continue;
        }

        bool got_frame = false;
        const bool ended_normally = capture_session(d, sender, got_frame);
        if (got_frame) {
          failures = 0;
          reported_paused = false;
        }
        if (ended_normally || stopping()) {
          continue;
        }
        // Access lost (mode change, desktop switch, GPU reset) or an error.
        if (!reported_paused) {
          log_line("Capture of " + to_utf8(screen_.device_name) + " was interrupted; restarting with backoff");
          reported_paused = true;
        }
        if (wait_for(pn::backoff_delay(failures++))) {
          break;
        }
      }

      runtime_.send_destroy(sender);
      log_line("NDI source '" + source_name_ + "' stopped");
    }

    /// Capture until the duplication is lost, the secure desktop appears, or we
    /// are stopped. Returns true when that was because of the secure desktop or
    /// a stop (not an error).
    bool capture_session(duplication_t &d, nabi::send_instance_t sender, bool &got_frame) {
      const auto interval = pn::frame_interval(fps_);
      auto last_send = std::chrono::steady_clock::now() - 1h;
      bool have_frame = false;

      while (!stopping()) {
        if (secure_desktop_active()) {
          return true;
        }

        // Let changes accumulate until the next frame is due; DDA then hands
        // over the newest picture, so a 60 Hz desktop costs one copy per send.
        if (shared_.wait_until(last_send + interval, stop_)) {
          return true;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto idle_left = std::chrono::duration_cast<std::chrono::milliseconds>(last_send + pn::idle_resend_interval - now);
        const UINT timeout_ms = static_cast<UINT>(std::clamp<long long>(idle_left.count(), 1, 100));

        DXGI_OUTDUPL_FRAME_INFO info {};
        com_ptr<IDXGIResource> resource;
        const HRESULT hr = d.dup->AcquireNextFrame(timeout_ms, &info, resource.put());
        bool fresh = false;
        if (hr == S_OK) {
          if (info.LastPresentTime.QuadPart != 0 || info.AccumulatedFrames != 0) {
            com_ptr<ID3D11Texture2D> texture;
            if (SUCCEEDED(resource->QueryInterface(IID_ID3D11Texture2D, texture.put_void()))) {
              D3D11_TEXTURE2D_DESC desc;
              texture->GetDesc(&desc);
              if (desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM && desc.Format != DXGI_FORMAT_B8G8R8X8_UNORM) {
                d.dup->ReleaseFrame();
                log_line("Unsupported desktop format " + std::to_string(desc.Format) + "; HDR output is not supported");
                return false;
              }
              if (!d.staging || d.staging_desc.Width != desc.Width || d.staging_desc.Height != desc.Height || d.staging_desc.Format != desc.Format) {
                D3D11_TEXTURE2D_DESC staging {};
                staging.Width = desc.Width;
                staging.Height = desc.Height;
                staging.MipLevels = 1;
                staging.ArraySize = 1;
                staging.Format = desc.Format;
                staging.SampleDesc.Count = 1;
                staging.Usage = D3D11_USAGE_STAGING;
                staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                if (FAILED(d.device->CreateTexture2D(&staging, nullptr, d.staging.put()))) {
                  d.dup->ReleaseFrame();
                  log_line("Could not create the staging texture");
                  return false;
                }
                d.staging_desc = staging;
              }
              d.context->CopyResource(d.staging.get(), texture.get());
              have_frame = true;
              fresh = true;
            }
          }
          d.dup->ReleaseFrame();
        } else if (hr != DXGI_ERROR_WAIT_TIMEOUT) {
          // DXGI_ERROR_ACCESS_LOST (mode change, desktop switch) and anything else.
          return false;
        }

        if (have_frame && pn::should_send(fresh, false, std::chrono::steady_clock::now() - last_send, fps_)) {
          D3D11_MAPPED_SUBRESOURCE mapped {};
          if (FAILED(d.context->Map(d.staging.get(), 0, D3D11_MAP_READ, 0, &mapped))) {
            return false;
          }
          send_frame(sender, static_cast<const std::uint8_t *>(mapped.pData), static_cast<int>(d.staging_desc.Width), static_cast<int>(d.staging_desc.Height), static_cast<int>(mapped.RowPitch));
          d.context->Unmap(d.staging.get(), 0);
          last_send = std::chrono::steady_clock::now();
          got_frame = true;
        }
      }
      return true;
    }

    void send_frame(nabi::send_instance_t sender, const std::uint8_t *data, int width, int height, int stride) {
      nabi::video_frame_v2_t frame {};
      frame.xres = width;
      frame.yres = height;
      frame.FourCC = nabi::fourcc_bgrx;  // 8-bit BGR, fourth byte ignored
      frame.frame_rate_N = fps_;
      frame.frame_rate_D = 1;
      frame.picture_aspect_ratio = static_cast<float>(width) / static_cast<float>(height);
      frame.frame_format_type = nabi::frame_format_progressive;
      frame.timecode = nabi::timecode_synthesize;
      frame.p_data = const_cast<std::uint8_t *>(data);
      frame.line_stride_in_bytes = stride;
      // Synchronous: returns once the runtime has its own copy.
      runtime_.send_video_v2(sender, &frame);
    }

    void send_black(nabi::send_instance_t sender) {
      const int width = screen_.width;
      const int height = screen_.height;
      const auto size = static_cast<std::size_t>(width) * height * 4;
      if (black_.size() != size) {
        black_.assign(size, 0);
      }
      send_frame(sender, black_.data(), width, height, width * 4);
    }

    runtime_t &runtime_;
    shared_t &shared_;
    screen_t screen_;
    std::string source_name_;
    std::string groups_;
    int fps_;
    std::atomic<bool> stop_ {false};
    std::atomic<bool> done_ {false};
    std::thread thread_;
    std::vector<std::uint8_t> black_;
  };

  /// Ask every worker to stop and wait up to `limit` for all of them.
  /// Returns false when a worker did not finish (it is then left running).
  bool stop_all(std::vector<std::unique_ptr<worker_t>> &workers, std::chrono::milliseconds limit) {
    for (auto &w : workers) {
      w->request_stop();
    }
    const auto deadline = std::chrono::steady_clock::now() + limit;
    bool all_done = false;
    while (!all_done && std::chrono::steady_clock::now() < deadline) {
      all_done = std::all_of(workers.begin(), workers.end(), [](auto &w) {
        return w->finished();
      });
      if (!all_done) {
        std::this_thread::sleep_for(20ms);
      }
    }
    all_done = std::all_of(workers.begin(), workers.end(), [](auto &w) {
      return w->finished();
    });
    if (all_done) {
      for (auto &w : workers) {
        w->join();
      }
    }
    return all_done;
  }

  /// The host holds our stdin pipe open. EOF means it stopped us or died.
  void watch_stdin(shared_t &shared) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    if (in == nullptr || in == INVALID_HANDLE_VALUE || GetFileType(in) != FILE_TYPE_PIPE) {
      return;  // started by hand: stop with Ctrl-C
    }
    std::thread([in, &shared] {
      char buffer[64];
      DWORD got = 0;
      while (ReadFile(in, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
      }
      shared.request_stop();
    }).detach();
  }

  shared_t *g_shared = nullptr;

  BOOL WINAPI console_handler(DWORD) {
    if (g_shared) {
      g_shared->request_stop();
    }
    return TRUE;
  }
}  // namespace

int main(int argc, char *argv[]) {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }
  const auto options = pn::parse_helper_args(args);
  if (!options) {
    log_line("plank-ndi: bad arguments");
    return 64;
  }

  // Real pixel sizes on high-DPI displays, as dxgi-info and the host do.
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

  runtime_t runtime;
  if (!runtime.load()) {
    log_line("NDI output is on but the NDI runtime is not installed; install NDI Tools");
    return 2;
  }

  shared_t shared;
  g_shared = &shared;
  SetConsoleCtrlHandler(console_handler, TRUE);
  watch_stdin(shared);

  const auto computer = computer_name();
  std::vector<std::unique_ptr<worker_t>> workers;
  std::string current_signature;
  int exit_code = 0;
  bool leaked = false;

  while (!shared.stop.load()) {
    const auto screens = enumerate_screens();
    const auto sig = signature(screens);

    if (sig != current_signature && !screens.empty()) {
      if (!workers.empty()) {
        log_line("Display layout changed; restarting NDI sources");
        if (!stop_all(workers, 3s)) {
          leaked = true;
          exit_code = 3;  // let the host start a fresh process
          break;
        }
        workers.clear();
      }
      current_signature = sig;

      std::vector<pn::output_ref> refs;
      for (const auto &s : screens) {
        refs.push_back({to_utf8(s.device_name), s.x, s.y, s.primary});
      }
      const auto selected = pn::select_outputs(std::move(refs), options->scope);
      const int count = static_cast<int>(selected.size());
      for (int i = 0; i < count; ++i) {
        const auto it = std::find_if(screens.begin(), screens.end(), [&](const screen_t &s) {
          return to_utf8(s.device_name) == selected[i].capture_name;
        });
        workers.push_back(std::make_unique<worker_t>(runtime, shared, *it, pn::source_name(options->name, computer, i + 1, count), options->groups, options->fps));
      }
    }

    // Plain GDI polling; never a DuplicateOutput probe.
    shared.wait_for(2s, std::atomic<bool> {false});
  }

  if (!stop_all(workers, 3s)) {
    leaked = true;
  }
  if (leaked) {
    // A thread is still inside the NDI runtime or DXGI. Do not unload anything
    // underneath it; the process exit reclaims everything.
    log_line("plank-ndi: a capture thread did not stop in time; exiting without unloading the NDI runtime");
    std::fflush(stderr);
    ExitProcess(exit_code);
  }
  workers.clear();
  if (runtime.initialized) {
    runtime.destroy();
  }
  if (runtime.module) {
    FreeLibrary(runtime.module);
  }
  log_line("plank-ndi: stopped");
  return exit_code;
}
