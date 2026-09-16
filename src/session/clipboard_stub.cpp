/**
 * @file src/session/clipboard_stub.cpp
 * @brief Clipboard sharing is implemented for Windows hosts only.
 */
#include "clipboard.h"

namespace plank::clipboard {
  std::optional<std::string> poll_host_text(std::uint32_t &) {
    return std::nullopt;
  }

  bool set_host_text(const std::string &) {
    return false;
  }

  std::uint32_t host_generation() {
    return 0;
  }
}  // namespace plank::clipboard
