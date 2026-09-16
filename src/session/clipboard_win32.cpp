/**
 * @file src/session/clipboard_win32.cpp
 * @brief Windows implementation of plain-text clipboard sharing.
 *
 * The host process runs inside the console session's window station, so it
 * reads and writes the same clipboard as the signed-in user's applications.
 * GetClipboardSequenceNumber() tells us when anything changed without
 * opening the clipboard on every poll.
 */
#include "clipboard.h"

#include <windows.h>

#include <mutex>
#include <string>

#include "src/logging.h"

namespace plank::clipboard {
  namespace {
    using namespace std::literals;

    constexpr int open_attempts = 5;
    constexpr DWORD open_retry_delay_ms = 20;

    std::mutex &state_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    /// Text this host last wrote, so it is not sent back to the client.
    std::string &last_written_text() {
      static std::string text;
      return text;
    }

    /**
     * @brief Open the clipboard, retrying while another application holds it.
     */
    bool open_clipboard() {
      for (int attempt = 0; attempt < open_attempts; ++attempt) {
        if (OpenClipboard(nullptr)) {
          return true;
        }
        Sleep(open_retry_delay_ms);
      }
      return false;
    }

    std::string narrow(const wchar_t *text, int length) {
      if (length <= 0) {
        return {};
      }
      const int size = WideCharToMultiByte(CP_UTF8, 0, text, length, nullptr, 0, nullptr, nullptr);
      if (size <= 0) {
        return {};
      }
      std::string result(static_cast<std::size_t>(size), '\0');
      WideCharToMultiByte(CP_UTF8, 0, text, length, result.data(), size, nullptr, nullptr);
      return result;
    }

    std::wstring widen(const std::string &text) {
      if (text.empty()) {
        return {};
      }
      const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      if (size <= 0) {
        return {};
      }
      std::wstring result(static_cast<std::size_t>(size), L'\0');
      MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
      return result;
    }
  }  // namespace

  std::optional<std::string> poll_host_text(std::uint32_t &generation) {
    const auto sequence = static_cast<std::uint32_t>(GetClipboardSequenceNumber());
    if (sequence == generation) {
      return std::nullopt;
    }
    generation = sequence;

    if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) {
      return std::nullopt;  // an image or files: not shared
    }
    if (!open_clipboard()) {
      BOOST_LOG(debug) << "Clipboard is busy; skipping this change"sv;
      return std::nullopt;
    }

    std::string text;
    if (HANDLE handle = GetClipboardData(CF_UNICODETEXT); handle != nullptr) {
      if (auto *wide = static_cast<const wchar_t *>(GlobalLock(handle)); wide != nullptr) {
        text = narrow(wide, static_cast<int>(wcsnlen(wide, max_text_bytes + 1)));
        GlobalUnlock(handle);
      }
    }
    CloseClipboard();

    if (text.empty()) {
      return std::nullopt;
    }
    if (text.size() > max_text_bytes) {
      BOOST_LOG(info) << "Host clipboard text is "sv << text.size()
                      << " bytes; too large to share"sv;
      return std::nullopt;
    }

    std::lock_guard lock {state_mutex()};
    if (text == last_written_text()) {
      return std::nullopt;  // this is the text the client just sent us
    }
    return text;
  }

  std::uint32_t host_generation() {
    return static_cast<std::uint32_t>(GetClipboardSequenceNumber());
  }

  bool set_host_text(const std::string &text) {
    if (text.empty() || text.size() > max_text_bytes) {
      return false;
    }
    const std::wstring wide = widen(text);
    if (wide.empty()) {
      return false;
    }

    const std::size_t bytes = (wide.size() + 1) * sizeof(wchar_t);
    HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (handle == nullptr) {
      return false;
    }
    if (auto *destination = static_cast<wchar_t *>(GlobalLock(handle)); destination != nullptr) {
      memcpy(destination, wide.c_str(), bytes);
      GlobalUnlock(handle);
    } else {
      GlobalFree(handle);
      return false;
    }

    if (!open_clipboard()) {
      GlobalFree(handle);
      BOOST_LOG(debug) << "Clipboard is busy; client text not applied"sv;
      return false;
    }
    EmptyClipboard();
    const bool applied = SetClipboardData(CF_UNICODETEXT, handle) != nullptr;
    CloseClipboard();
    if (!applied) {
      GlobalFree(handle);  // ownership stays with us when the call fails
      return false;
    }

    std::lock_guard lock {state_mutex()};
    last_written_text() = text;
    return true;
  }
}  // namespace plank::clipboard
