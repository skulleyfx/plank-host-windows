/**
 * @file src/session/display_fallback.h
 * @brief Choose which display and mode serve a one-screen request.
 *
 * A client asks for a resolution the primary display may refuse; a display
 * emulator often supports far fewer modes than a monitor does. Rather than fail
 * the session, the host walks a fixed fallback order. The order is pure logic,
 * kept free of Windows types so it can be tested anywhere.
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "display_arrange.h"

namespace plank::display_arrange {

  /**
   * @brief One mode a display can be set to.
   */
  struct mode_option_t {
    unsigned width {};
    unsigned height {};
    unsigned refresh_hz {};  ///< 0 when unknown.

    bool operator==(const mode_option_t &) const = default;
  };

  /**
   * @brief A streamable display and every mode it reports.
   */
  struct display_modes_t {
    std::string name;  ///< GDI device name.
    mode_option_t current;  ///< Mode in use now.
    std::vector<mode_option_t> modes;  ///< Supported modes, any order.
  };

  /**
   * @brief Which step of the fallback order produced a choice.
   */
  enum class fallback_reason_t {
    requested_mode,  ///< Requested mode on the preferred display.
    other_display,  ///< Requested mode on a different display.
    nearest_same_aspect,  ///< Closest smaller mode with the requested aspect ratio.
    nearest_smaller,  ///< Largest mode that fits inside the request.
    nearest_any,  ///< Nothing fits inside the request; smallest bigger mode.
  };

  /**
   * @brief One display and mode worth trying.
   */
  struct mode_choice_t {
    std::size_t display_index {};  ///< Index into the displays given.
    mode_option_t mode;
    fallback_reason_t reason {fallback_reason_t::requested_mode};
  };

  constexpr std::string_view fallback_reason_name(fallback_reason_t reason) {
    switch (reason) {
      case fallback_reason_t::requested_mode:
        return "requested mode on the preferred display";
      case fallback_reason_t::other_display:
        return "requested mode on another display (it becomes the primary for this session)";
      case fallback_reason_t::nearest_same_aspect:
        return "nearest smaller mode with the requested aspect ratio";
      case fallback_reason_t::nearest_smaller:
        return "largest mode that fits inside the request";
      case fallback_reason_t::nearest_any:
        return "smallest mode larger than the request";
    }
    return "unknown";
  }

  namespace fallback_detail {
    inline std::uint64_t area(const mode_option_t &mode) {
      return static_cast<std::uint64_t>(mode.width) * mode.height;
    }

    inline unsigned distance(unsigned left, unsigned right) {
      return left > right ? left - right : right - left;
    }

    /**
     * @brief Mode of the given size with the refresh rate nearest the wanted one.
     *
     * Ties go to the higher rate.
     */
    inline std::vector<mode_option_t>::const_iterator pick_refresh(
      const std::vector<mode_option_t> &modes,
      unsigned width,
      unsigned height,
      unsigned wanted_hz
    ) {
      auto best = modes.end();
      for (auto it = modes.begin(); it != modes.end(); ++it) {
        if (it->width != width || it->height != height) {
          continue;
        }
        if (best == modes.end()) {
          best = it;
          continue;
        }
        const auto it_distance = distance(it->refresh_hz, wanted_hz);
        const auto best_distance = distance(best->refresh_hz, wanted_hz);
        if (it_distance < best_distance ||
            (it_distance == best_distance && it->refresh_hz > best->refresh_hz)) {
          best = it;
        }
      }
      return best;
    }

    inline bool same_aspect(unsigned w1, unsigned h1, unsigned w2, unsigned h2) {
      return static_cast<std::uint64_t>(w1) * h2 == static_cast<std::uint64_t>(w2) * h1;
    }
  }  // namespace fallback_detail

  /**
   * @brief Every display and mode to try for a request, best first.
   *
   * Order: the requested mode on the preferred display; the requested mode on
   * each other display; then substitutes on the preferred display, preferring
   * the same aspect ratio, then the largest mode that fits inside the request,
   * then the smallest mode that does not. The caller applies the first entry
   * and moves to the next when Windows still refuses it. An empty list means
   * nothing can be offered at all.
   *
   * @param displays Streamable displays with their supported modes.
   * @param preferred Index of the display a one-screen session normally uses.
   * @param width Requested width.
   * @param height Requested height.
   * @param refresh_hz Requested refresh rate, 0 to keep each display's own.
   * @return Candidates in the order to try.
   */
  inline std::vector<mode_choice_t> rank_mode_candidates(
    const std::vector<display_modes_t> &displays,
    std::size_t preferred,
    unsigned width,
    unsigned height,
    unsigned refresh_hz
  ) {
    std::vector<mode_choice_t> ranked;
    if (displays.empty() || preferred >= displays.size() || width == 0 || height == 0) {
      return ranked;
    }

    const auto add_exact = [&](std::size_t index, fallback_reason_t reason) {
      const auto &display = displays[index];
      const unsigned wanted = refresh_hz != 0 ? refresh_hz : display.current.refresh_hz;
      const auto found = fallback_detail::pick_refresh(display.modes, width, height, wanted);
      if (found != display.modes.end()) {
        ranked.push_back({index, *found, reason});
      }
    };

    add_exact(preferred, fallback_reason_t::requested_mode);
    for (std::size_t index = 0; index < displays.size(); ++index) {
      if (index != preferred) {
        add_exact(index, fallback_reason_t::other_display);
      }
    }

    // Substitutes on the preferred display, one candidate per distinct size.
    const auto &display = displays[preferred];
    const unsigned wanted = refresh_hz != 0 ? refresh_hz : display.current.refresh_hz;
    std::vector<mode_option_t> sizes;
    for (const auto &mode : display.modes) {
      if (mode.width == 0 || mode.height == 0 || (mode.width == width && mode.height == height)) {
        continue;
      }
      const bool seen = std::any_of(sizes.begin(), sizes.end(), [&mode](const auto &known) {
        return known.width == mode.width && known.height == mode.height;
      });
      if (!seen) {
        sizes.push_back(mode);
      }
    }

    std::vector<mode_option_t> same_aspect;
    std::vector<mode_option_t> smaller;
    std::vector<mode_option_t> bigger;
    for (const auto &size : sizes) {
      if (size.width <= width && size.height <= height) {
        if (fallback_detail::same_aspect(size.width, size.height, width, height)) {
          same_aspect.push_back(size);
        } else {
          smaller.push_back(size);
        }
      } else {
        bigger.push_back(size);
      }
    }
    const auto larger_first = [](const mode_option_t &left, const mode_option_t &right) {
      return fallback_detail::area(left) > fallback_detail::area(right);
    };
    std::sort(same_aspect.begin(), same_aspect.end(), larger_first);
    std::sort(smaller.begin(), smaller.end(), larger_first);
    // Smallest first: the least overshoot.
    std::sort(bigger.begin(), bigger.end(), [&](const auto &left, const auto &right) {
      return larger_first(right, left);
    });

    const auto add_size = [&](const mode_option_t &size, fallback_reason_t reason) {
      const auto found = fallback_detail::pick_refresh(display.modes, size.width, size.height, wanted);
      if (found != display.modes.end()) {
        ranked.push_back({preferred, *found, reason});
      }
    };
    for (const auto &size : same_aspect) {
      add_size(size, fallback_reason_t::nearest_same_aspect);
    }
    for (const auto &size : smaller) {
      add_size(size, fallback_reason_t::nearest_smaller);
    }
    for (const auto &size : bigger) {
      add_size(size, fallback_reason_t::nearest_any);
    }
    return ranked;
  }

  /**
   * @brief Arrangement with one display made the Windows primary.
   *
   * The primary sits at 0,0, so every other display shifts with it. A display
   * left of the new primary stays left of it; one to its right moves with its
   * edge; anything else goes beside it. None overlaps it after the resize.
   *
   * @param layout Current arrangement.
   * @param target Index in @p layout of the display becoming the primary.
   * @param width New width of that display.
   * @param height New height of that display.
   * @return The arrangement to apply.
   */
  inline std::vector<display_mode_t> primary_switch_layout(
    const std::vector<display_mode_t> &layout,
    std::size_t target,
    unsigned width,
    unsigned height
  ) {
    std::vector<display_mode_t> result = layout;
    if (target >= layout.size()) {
      return result;
    }
    const int origin_x = layout[target].x;
    const int origin_y = layout[target].y;
    const int old_width = static_cast<int>(layout[target].width);
    for (std::size_t index = 0; index < result.size(); ++index) {
      auto &display = result[index];
      display.primary = index == target;
      if (index == target) {
        display.x = 0;
        display.y = 0;
        display.width = width;
        display.height = height;
        continue;
      }
      const bool was_left = layout[index].x + static_cast<int>(layout[index].width) <= origin_x;
      const bool was_right = layout[index].x >= origin_x + old_width;
      if (was_left) {
        display.x = layout[index].x - origin_x;
        display.y = layout[index].y - origin_y;
      } else if (was_right) {
        display.x = layout[index].x - origin_x + (static_cast<int>(width) - old_width);
        display.y = layout[index].y - origin_y;
      } else {
        // Stacked or overlapping: put it beside the new primary.
        display.x = static_cast<int>(width);
        display.y = 0;
      }
    }
    return result;
  }

}  // namespace plank::display_arrange
