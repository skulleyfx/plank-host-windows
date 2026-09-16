/**
 * @file src/session/display_arrange.h
 * @brief Arrange the host's displays for a session, and put them back.
 *
 * A two-screen session needs the workstation's two displays side by side at
 * the resolutions the client asked for. Windows is told the exact position of
 * each display, because leaving the arrangement to Windows can overlap them.
 *
 * The previous arrangement is written to disk before anything changes, so it
 * can be restored at the end of the session, or at the next host start if the
 * host died mid-session.
 */
#pragma once

#include <string>
#include <vector>

namespace plank::display_arrange {

  /**
   * @brief One display's place on the desktop.
   */
  struct display_mode_t {
    std::string name;  ///< GDI device name, e.g. \\.\DISPLAY1.
    int x {};  ///< Left edge.
    int y {};  ///< Top edge.
    unsigned width {};  ///< Width in pixels.
    unsigned height {};  ///< Height in pixels.
    unsigned refresh_hz {};  ///< Refresh rate, 0 when unknown.
    bool primary {};  ///< Whether this display is the Windows primary.
  };

  /**
   * @brief Displays currently attached to the desktop, left to right.
   *
   * Virtual displays from other remote-desktop software are included; callers
   * that stream physical screens filter them out.
   *
   * @return Attached displays.
   */
  std::vector<display_mode_t> current_layout();

  /**
   * @brief Put two displays side by side at the requested resolutions.
   *
   * The left display becomes the Windows primary at (0,0) and the right one
   * starts exactly where the left ends, which is what the client expects when
   * it splits the picture between two monitors.
   *
   * @param left Left display name and resolution.
   * @param right Right display name and resolution.
   * @return True when Windows applied the arrangement.
   */
  bool apply_side_by_side(const display_mode_t &left, const display_mode_t &right);

  /**
   * @brief Restore an arrangement captured by current_layout().
   *
   * @param layout Arrangement to restore.
   * @return True when Windows applied it.
   */
  bool restore_layout(const std::vector<display_mode_t> &layout);

  /**
   * @brief Remember an arrangement so it survives a host crash.
   *
   * @param layout Arrangement to save, or an empty list to forget.
   */
  void save_saved_layout(const std::vector<display_mode_t> &layout);

  /**
   * @brief Arrangement saved by save_saved_layout(), if any.
   *
   * @return Saved arrangement, empty when nothing was saved.
   */
  std::vector<display_mode_t> saved_layout();

  /**
   * @brief Restore and forget a saved arrangement left behind by a crash.
   *
   * Called when the host starts.
   */
  void restore_saved_layout_if_any();

}  // namespace plank::display_arrange
