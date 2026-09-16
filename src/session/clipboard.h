/**
 * @file src/session/clipboard.h
 * @brief Plain-text clipboard sharing between the host desktop and a client.
 *
 * Text only, in both directions. Images and files are deliberately not
 * shared: they are large, and a silent file transfer is not something a
 * remote-desktop session should do without asking.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace plank::clipboard {

  /// Longest text shared in either direction. Anything larger is ignored.
  constexpr std::size_t max_text_bytes = 60000;

  /**
   * @brief Read the host desktop clipboard if it changed since the last call.
   *
   * @param generation Caller's last seen generation; updated when text is returned.
   * @return UTF-8 text when the clipboard holds new text, otherwise nothing.
   */
  std::optional<std::string> poll_host_text(std::uint32_t &generation);

  /**
   * @brief Put text on the host desktop clipboard.
   *
   * The text is remembered so the next poll does not send it straight back
   * to the client that supplied it.
   *
   * @param text UTF-8 text from the client.
   * @return True when the clipboard was updated.
   */
  bool set_host_text(const std::string &text);

  /**
   * @brief Current host clipboard change counter.
   *
   * @return Counter value, or 0 where the platform has no clipboard support.
   */
  std::uint32_t host_generation();

}  // namespace plank::clipboard
