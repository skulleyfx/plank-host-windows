/**
 * @file src/session/display_arrange_win32.cpp
 * @brief Windows implementation of display arrangement.
 *
 * ChangeDisplaySettingsEx() with CDS_UPDATEREGISTRY | CDS_NORESET queues a
 * change per display, and a final call with no device applies them together.
 * That is the only way to place two displays at exact positions; asking
 * Windows to "extend" leaves the arrangement to its own judgement, which can
 * overlap displays of different sizes.
 */
#include "display_arrange.h"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "src/logging.h"
#include "src/platform/common.h"

namespace plank::display_arrange {
  namespace {
    using namespace std::literals;
    namespace pt = boost::property_tree;

    std::filesystem::path state_file() {
      return platf::appdata() / "display-layout.json";
    }

    std::string narrow(const wchar_t *text) {
      if (text == nullptr || *text == L'\0') {
        return {};
      }
      const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
      if (size <= 1) {
        return {};
      }
      std::string result(static_cast<std::size_t>(size - 1), '\0');
      WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), size, nullptr, nullptr);
      return result;
    }

    std::wstring widen(const std::string &text) {
      if (text.empty()) {
        return {};
      }
      const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring result(static_cast<std::size_t>(size), L'\0');
      MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
      return result;
    }

    /**
     * @brief Queue one display's position and mode without applying it yet.
     */
    bool queue_display(const display_mode_t &display, bool primary) {
      DEVMODEW mode {};
      mode.dmSize = sizeof(mode);
      const std::wstring name = widen(display.name);
      if (!EnumDisplaySettingsExW(name.c_str(), ENUM_CURRENT_SETTINGS, &mode, 0)) {
        BOOST_LOG(warning) << "Couldn't read the current mode of "sv << display.name;
        return false;
      }

      mode.dmPelsWidth = display.width;
      mode.dmPelsHeight = display.height;
      mode.dmPosition.x = display.x;
      mode.dmPosition.y = display.y;
      mode.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_POSITION;
      if (display.refresh_hz != 0) {
        mode.dmDisplayFrequency = display.refresh_hz;
        mode.dmFields |= DM_DISPLAYFREQUENCY;
      }

      DWORD flags = CDS_UPDATEREGISTRY | CDS_NORESET;
      if (primary) {
        flags |= CDS_SET_PRIMARY;
      }
      const LONG result = ChangeDisplaySettingsExW(name.c_str(), &mode, nullptr, flags, nullptr);
      if (result != DISP_CHANGE_SUCCESSFUL) {
        BOOST_LOG(warning) << "Windows refused "sv << display.width << 'x' << display.height
                           << " at "sv << display.x << ',' << display.y << " on "sv << display.name
                           << " (code "sv << result << ')';
        return false;
      }
      return true;
    }

    bool apply_queued_changes() {
      const LONG result = ChangeDisplaySettingsExW(nullptr, nullptr, nullptr, 0, nullptr);
      if (result != DISP_CHANGE_SUCCESSFUL) {
        BOOST_LOG(warning) << "Windows refused the display arrangement (code "sv << result << ')';
        return false;
      }
      return true;
    }
  }  // namespace

  std::vector<display_mode_t> current_layout() {
    std::vector<display_mode_t> layout;

    DISPLAY_DEVICEW device {};
    device.cb = sizeof(device);
    for (DWORD index = 0; EnumDisplayDevicesW(nullptr, index, &device, 0); ++index) {
      device.cb = sizeof(device);
      if (!(device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) {
        continue;
      }

      DEVMODEW mode {};
      mode.dmSize = sizeof(mode);
      if (!EnumDisplaySettingsExW(device.DeviceName, ENUM_CURRENT_SETTINGS, &mode, 0)) {
        continue;
      }

      display_mode_t entry;
      entry.name = narrow(device.DeviceName);
      entry.x = mode.dmPosition.x;
      entry.y = mode.dmPosition.y;
      entry.width = mode.dmPelsWidth;
      entry.height = mode.dmPelsHeight;
      entry.refresh_hz = mode.dmDisplayFrequency;
      entry.primary = (device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
      layout.push_back(std::move(entry));
    }

    std::sort(std::begin(layout), std::end(layout), [](const auto &left, const auto &right) {
      return std::tie(left.x, left.y) < std::tie(right.x, right.y);
    });
    return layout;
  }

  bool apply_side_by_side(const display_mode_t &left, const display_mode_t &right) {
    display_mode_t placed_left = left;
    placed_left.x = 0;
    placed_left.y = 0;

    display_mode_t placed_right = right;
    placed_right.x = static_cast<int>(left.width);
    placed_right.y = 0;

    BOOST_LOG(info) << "Arranging the host displays: "sv << placed_left.name << ' '
                    << placed_left.width << 'x' << placed_left.height << " at 0,0 and "sv
                    << placed_right.name << ' ' << placed_right.width << 'x' << placed_right.height
                    << " at "sv << placed_right.x << ",0"sv;

    if (!queue_display(placed_left, true) || !queue_display(placed_right, false)) {
      // Drop anything already queued.
      ChangeDisplaySettingsExW(nullptr, nullptr, nullptr, 0, nullptr);
      return false;
    }
    return apply_queued_changes();
  }

  bool restore_layout(const std::vector<display_mode_t> &layout) {
    if (layout.empty()) {
      return false;
    }
    bool queued = false;
    for (const auto &display : layout) {
      queued = queue_display(display, display.primary) || queued;
    }
    if (!queued) {
      return false;
    }
    return apply_queued_changes();
  }

  void save_saved_layout(const std::vector<display_mode_t> &layout) {
    const auto path = state_file();
    if (layout.empty()) {
      std::error_code error;
      std::filesystem::remove(path, error);
      return;
    }

    pt::ptree root;
    pt::ptree displays;
    for (const auto &display : layout) {
      pt::ptree entry;
      entry.put("name", display.name);
      entry.put("x", display.x);
      entry.put("y", display.y);
      entry.put("width", display.width);
      entry.put("height", display.height);
      entry.put("refresh_hz", display.refresh_hz);
      entry.put("primary", display.primary);
      displays.push_back({"", entry});
    }
    root.add_child("displays", displays);

    try {
      std::ofstream file {path, std::ios::binary | std::ios::trunc};
      pt::write_json(file, root);
    } catch (const std::exception &error) {
      BOOST_LOG(warning) << "Couldn't save the display arrangement: "sv << error.what();
    }
  }

  std::vector<display_mode_t> saved_layout() {
    std::vector<display_mode_t> layout;
    const auto path = state_file();
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
      return layout;
    }

    try {
      pt::ptree root;
      std::ifstream file {path, std::ios::binary};
      pt::read_json(file, root);
      for (const auto &[key, entry] : root.get_child("displays")) {
        display_mode_t display;
        display.name = entry.get<std::string>("name", "");
        display.x = entry.get<int>("x", 0);
        display.y = entry.get<int>("y", 0);
        display.width = entry.get<unsigned>("width", 0);
        display.height = entry.get<unsigned>("height", 0);
        display.refresh_hz = entry.get<unsigned>("refresh_hz", 0);
        display.primary = entry.get<bool>("primary", false);
        if (!display.name.empty() && display.width != 0 && display.height != 0) {
          layout.push_back(std::move(display));
        }
      }
    } catch (const std::exception &failure) {
      BOOST_LOG(warning) << "Couldn't read the saved display arrangement: "sv << failure.what();
      layout.clear();
    }
    return layout;
  }

  void restore_saved_layout_if_any() {
    const auto layout = saved_layout();
    if (layout.empty()) {
      return;
    }
    BOOST_LOG(info) << "Restoring the display arrangement left by an earlier PLANK session"sv;
    restore_layout(layout);
    save_saved_layout({});
  }
}  // namespace plank::display_arrange
