/**
 * @file src/platform/windows/input.cpp
 * @brief Definitions for input handling on Windows.
 */
#ifndef DOXYGEN
  #define WINVER 0x0A00
#endif
#ifdef DOXYGEN
  /**
   * @def CALLBACK
   * @brief Windows callback calling convention marker.
   */
  #define CALLBACK
#endif

// platform includes
#include <Windows.h>

// standard includes
#include <algorithm>
#include <memory>
#include <thread>
#include <vector>

// local includes
#include "misc.h"
#include "src/config.h"
#include "src/globals.h"
#include "src/logging.h"
#include "src/platform/common.h"
#include "src/platform/virtualhid_input.h"

namespace platf {
  using namespace std::literals;

  /**
   * @brief Global virtual input device handles shared by clients.
   */
  struct input_raw_t {
    virtualhid::input_context_t virtualhid;  ///< libvirtualhid input context.
  };

  input_t input() {
    return input_t {new input_raw_t {}};
  }



  virtualhid::input_context_t &virtualhid::get_input_context(input_t &input) {
    return input->virtualhid;
  }

  std::optional<util::point_t> get_mouse_loc(input_t & /*input*/) {
    POINT p;
    if (!GetCursorPos(&p)) {
      return std::nullopt;
    }

    return util::point_t {
      (double) p.x,
      (double) p.y
    };
  }

  /**
   * @brief Per-client virtual devices for touch and pen input.
   */
  struct client_input_raw_t: public client_input_t {
    /**
     * @brief Create per-client raw input devices for touch and pen events.
     *
     * @param input Platform input backend that receives the event.
     */
    explicit client_input_raw_t(input_t &input):
        virtualhid {input->virtualhid} {}

    virtualhid::client_context_t virtualhid;  ///< libvirtualhid client context.
  };

  /**
   * @brief Allocates a context to store per-client input data.
   * @param input The global input context.
   * @return A unique pointer to a per-client input data context.
   */
  std::unique_ptr<client_input_t> allocate_client_input_context(input_t &input) {
    return std::make_unique<client_input_raw_t>(input);
  }

  virtualhid::client_context_t &virtualhid::get_client_context(client_input_t *input) {
    return static_cast<client_input_raw_t *>(input)->virtualhid;
  }

















  void freeInput(input_raw_t *input) {
    std::default_delete<input_raw_t> {}(input);
  }


  /**
   * @brief Returns the supported platform capabilities to advertise to the client.
   * @return Capability flags.
   */
  platform_caps::caps_t get_capabilities() {
    platform_caps::caps_t caps = 0;

    // PLANK's product scope excludes gamepad/controller input, so this host
    // must not advertise controller capability to clients (AGENTS.md).

    const auto runtime = virtualhid::create_runtime();
    if (runtime) {
      const auto &capabilities = runtime->capabilities();
      if (capabilities.supports_pen_tablet) {
        caps |= platform_caps::pen_touch;
      }
    } else {
      BOOST_LOG(warning) << "Unable to create libvirtualhid runtime for pen capability detection"sv;
    }

    // Pointer shape and position are sampled with GetCursorInfo; see
    // win_cursor_capture() below.
    caps |= platform_caps::local_cursor;

    return caps;
  }

  bool win_cursor_query(win_cursor_position_t &position) {
    CURSORINFO info {};
    info.cbSize = sizeof(info);
    if (!GetCursorInfo(&info)) {
      return false;
    }
    const int origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    position.desktop_width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    position.desktop_height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    position.x = info.ptScreenPos.x - origin_x;
    position.y = info.ptScreenPos.y - origin_y;
    const bool showing = (info.flags & CURSOR_SHOWING) != 0 && info.hCursor != nullptr;
    position.shape = showing ? reinterpret_cast<std::uintptr_t>(info.hCursor) : 0;
    return position.desktop_width > 0 && position.desktop_height > 0;
  }

  namespace {
    /**
     * @brief Render a cursor onto a solid background into a 32-bpp top-down DIB.
     */
    bool render_cursor(HCURSOR cursor, int width, int height, COLORREF background,
                       std::vector<std::uint8_t> &out) {
      HDC screen = GetDC(nullptr);
      if (!screen) {
        return false;
      }
      HDC dc = CreateCompatibleDC(screen);
      ReleaseDC(nullptr, screen);
      if (!dc) {
        return false;
      }
      BITMAPINFO bmi {};
      bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
      bmi.bmiHeader.biWidth = width;
      bmi.bmiHeader.biHeight = -height;  // top-down
      bmi.bmiHeader.biPlanes = 1;
      bmi.bmiHeader.biBitCount = 32;
      bmi.bmiHeader.biCompression = BI_RGB;
      void *bits = nullptr;
      HBITMAP bitmap = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
      if (!bitmap || !bits) {
        DeleteDC(dc);
        return false;
      }
      const auto previous = SelectObject(dc, bitmap);
      RECT rect {0, 0, width, height};
      HBRUSH brush = CreateSolidBrush(background);
      FillRect(dc, &rect, brush);
      DeleteObject(brush);
      const bool drawn = DrawIconEx(dc, 0, 0, cursor, width, height, 0, nullptr, DI_NORMAL) != 0;
      out.assign(static_cast<std::uint8_t *>(bits),
                 static_cast<std::uint8_t *>(bits) + static_cast<std::size_t>(width) * height * 4U);
      SelectObject(dc, previous);
      DeleteObject(bitmap);
      DeleteDC(dc);
      return drawn;
    }
  }  // namespace

  bool win_cursor_capture(win_cursor_image_t &image) {
    CURSORINFO info {};
    info.cbSize = sizeof(info);
    if (!GetCursorInfo(&info)) {
      return false;
    }
    const auto shape = reinterpret_cast<std::uintptr_t>(info.hCursor);
    const bool showing = (info.flags & CURSOR_SHOWING) != 0 && info.hCursor != nullptr;
    if (!showing) {
      // A transparent 1x1 image carries "hidden" on the wire.
      image.pixels.assign(4, 0);
      image.width = image.height = 1;
      image.hotspot_x = image.hotspot_y = 0;
      image.visible = false;
      image.serial = 0;
      return true;
    }

    ICONINFO icon {};
    if (!GetIconInfo(info.hCursor, &icon)) {
      return false;
    }
    BITMAP bitmap {};
    int width = 0;
    int height = 0;
    if (icon.hbmColor && GetObject(icon.hbmColor, sizeof(bitmap), &bitmap)) {
      width = bitmap.bmWidth;
      height = bitmap.bmHeight;
    } else if (icon.hbmMask && GetObject(icon.hbmMask, sizeof(bitmap), &bitmap)) {
      // Monochrome cursors stack the AND and XOR masks vertically.
      width = bitmap.bmWidth;
      height = bitmap.bmHeight / 2;
    }
    if (icon.hbmColor) {
      DeleteObject(icon.hbmColor);
    }
    if (icon.hbmMask) {
      DeleteObject(icon.hbmMask);
    }
    if (width <= 0 || height <= 0) {
      return false;
    }

    // Drawing on black gives premultiplied colour; the black/white difference
    // gives coverage. This handles alpha, masked and monochrome cursors alike.
    std::vector<std::uint8_t> on_black;
    std::vector<std::uint8_t> on_white;
    if (!render_cursor(info.hCursor, width, height, RGB(0, 0, 0), on_black) ||
        !render_cursor(info.hCursor, width, height, RGB(255, 255, 255), on_white)) {
      return false;
    }
    image.pixels.resize(on_black.size());
    for (std::size_t i = 0; i < on_black.size(); i += 4) {
      int coverage = 0;
      for (int c = 0; c < 3; ++c) {
        coverage = std::max(coverage, 255 - (on_white[i + c] - on_black[i + c]));
      }
      const auto alpha = static_cast<std::uint8_t>(std::clamp(coverage, 0, 255));
      for (int c = 0; c < 3; ++c) {
        image.pixels[i + c] = std::min(on_black[i + c], alpha);
      }
      image.pixels[i + 3] = alpha;
    }
    image.width = width;
    image.height = height;
    image.hotspot_x = std::clamp(static_cast<int>(icon.xHotspot), 0, width - 1);
    image.hotspot_y = std::clamp(static_cast<int>(icon.yHotspot), 0, height - 1);
    image.visible = true;
    image.serial = shape;
    return true;
  }
}  // namespace platf
