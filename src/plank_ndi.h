/**
 * @file src/plank_ndi.h
 * @brief Pure logic for the optional NDI screen output: option parsing,
 * source naming, output selection, frame pacing and runtime lookup order.
 *
 * Nothing here touches Windows or the NDI runtime so it can be unit tested on
 * any platform. The Windows glue lives in src/platform/windows/ndi_output.cpp.
 */
#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace plank::ndi {
  constexpr int min_fps = 1;
  constexpr int default_fps = 30;
  constexpr int max_fps = 60;

  /// An idle desktop produces no new frames. Resend the last one at this
  /// interval so receivers keep showing the source as live.
  constexpr std::chrono::milliseconds idle_resend_interval {500};

  /// Longest source name NDI accepts is 255 bytes; stay well inside it.
  constexpr std::size_t max_source_name_bytes = 200;

  enum class scope_e {
    primary,  ///< Only the primary display is published.
    all,  ///< Every capturable display is published.
  };

  namespace detail {
    inline std::string lower_trimmed(std::string_view text) {
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
      }
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
      }
      std::string result {text};
      std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return result;
    }
  }  // namespace detail

  /**
   * @brief Parse `ndi_output`. Accepts on/off plus the usual true/false/yes/no/1/0.
   * @return nullopt for anything else, so the caller keeps the default (off).
   */
  inline std::optional<bool> parse_enabled(std::string_view text) {
    const auto value = detail::lower_trimmed(text);
    if (value == "on" || value == "true" || value == "yes" || value == "1" || value == "enabled") {
      return true;
    }
    if (value == "off" || value == "false" || value == "no" || value == "0" || value == "disabled") {
      return false;
    }
    return std::nullopt;
  }

  /**
   * @brief Parse `ndi_outputs` (`primary` or `all`).
   */
  inline std::optional<scope_e> parse_scope(std::string_view text) {
    const auto value = detail::lower_trimmed(text);
    if (value == "primary") {
      return scope_e::primary;
    }
    if (value == "all") {
      return scope_e::all;
    }
    return std::nullopt;
  }

  /**
   * @brief Clamp `ndi_fps` to 1..60.
   */
  inline int clamp_fps(int fps) {
    return std::clamp(fps, min_fps, max_fps);
  }

  /**
   * @brief Build the published NDI source name for one screen.
   *
   * @param custom `ndi_source_name`, empty for the default.
   * @param computer Computer name, used by the default name.
   * @param index 1-based screen number.
   * @param count How many screens are being published.
   *
   * Default: "<computer> - Screen N". A custom name is used as is when a single
   * screen is published; with several screens " N" is appended so the sources
   * stay distinct. NDI itself prefixes the machine name on the network.
   */
  inline std::string source_name(std::string_view custom, std::string_view computer, int index, int count) {
    std::string base {custom};
    // Trim, and drop control characters that would confuse receivers.
    base.erase(std::remove_if(base.begin(), base.end(), [](unsigned char c) {
                 return c < 0x20 || c == 0x7f;
               }),
               base.end());
    while (!base.empty() && base.front() == ' ') {
      base.erase(base.begin());
    }
    while (!base.empty() && base.back() == ' ') {
      base.pop_back();
    }

    std::string name;
    if (base.empty()) {
      name = std::string {computer.empty() ? std::string_view {"PLANK"} : computer} + " - Screen " + std::to_string(index);
    } else if (count > 1) {
      name = base + " " + std::to_string(index);
    } else {
      name = base;
    }

    if (name.size() > max_source_name_bytes) {
      name.resize(max_source_name_bytes);
      // Do not leave half of a UTF-8 sequence at the end.
      while (!name.empty() && (static_cast<unsigned char>(name.back()) & 0xC0) == 0x80) {
        name.pop_back();
      }
      if (!name.empty() && static_cast<unsigned char>(name.back()) >= 0xC0) {
        name.pop_back();
      }
    }
    return name;
  }

  /// One capturable display, as far as output selection cares.
  struct output_ref {
    std::string capture_name;  ///< Name accepted by platf::display().
    int x {};  ///< Origin in desktop coordinates.
    int y {};
    bool primary {};
  };

  /**
   * @brief Order displays (primary first, then left to right, top to bottom)
   * and keep only the ones `scope` asks for. The order fixes the "Screen N"
   * numbering, so it must not depend on enumeration order.
   */
  inline std::vector<output_ref> select_outputs(std::vector<output_ref> outputs, scope_e scope) {
    std::stable_sort(outputs.begin(), outputs.end(), [](const output_ref &a, const output_ref &b) {
      if (a.primary != b.primary) {
        return a.primary;
      }
      if (a.x != b.x) {
        return a.x < b.x;
      }
      if (a.y != b.y) {
        return a.y < b.y;
      }
      return a.capture_name < b.capture_name;
    });
    if (scope == scope_e::primary && outputs.size() > 1) {
      outputs.resize(1);
    }
    return outputs;
  }

  /// Time between frames at `fps` (clamped).
  inline std::chrono::nanoseconds frame_interval(int fps) {
    return std::chrono::nanoseconds {1'000'000'000LL / clamp_fps(fps)};
  }

  /**
   * @brief Decide whether to send a frame now.
   *
   * @param new_frame True when the capture loop just delivered a changed frame,
   * false when it timed out because the desktop is idle.
   * @param dirty True when an earlier new frame was held back and has not been sent.
   * @param since_last_send Time since the previous send.
   * @param fps Configured `ndi_fps`.
   *
   * A new frame is sent unless it arrives in less than half a frame interval
   * after the last send (guards against bursts). A held-back frame goes out on
   * the next idle tick once a full interval has passed. An idle desktop is
   * refreshed every idle_resend_interval.
   */
  inline bool should_send(bool new_frame, bool dirty, std::chrono::nanoseconds since_last_send, int fps) {
    const auto interval = frame_interval(fps);
    if (new_frame) {
      return since_last_send >= interval / 2;
    }
    if (dirty) {
      return since_last_send >= interval;
    }
    return since_last_send >= idle_resend_interval;
  }

  /**
   * @brief True for a fully qualified Windows path (`C:\...` or `\\server\...`).
   * Relative NDI_RUNTIME_DIR values are refused: they would resolve against the
   * current directory, which a process running as SYSTEM must never trust.
   */
  inline bool is_absolute_windows_path(std::string_view path) {
    if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
      return true;
    }
    return path.size() >= 3 && path[0] == '\\' && path[1] == '\\';
  }

  /**
   * @brief DLL paths to try, in the order the NDI documentation gives: the
   * NDI_RUNTIME_DIR_V6 / V5 environment variables, then the standard install
   * locations. Environment values that are not absolute paths are skipped.
   *
   * The result holds full paths only. The caller must load them with
   * LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS and must
   * not fall back to a bare DLL name: that would search directories (the
   * application directory, for one) that an unprivileged user may be able to
   * write to.
   *
   * @param getenv Environment lookup; returns an empty string when unset.
   */
  inline std::vector<std::string> runtime_candidates(const std::function<std::string(const char *)> &getenv) {
    constexpr std::string_view dll = "Processing.NDI.Lib.x64.dll";
    std::vector<std::string> paths;
    auto add_dir = [&](std::string dir) {
      if (!is_absolute_windows_path(dir)) {
        return;
      }
      if (dir.back() != '\\' && dir.back() != '/') {
        dir += '\\';
      }
      paths.push_back(dir + std::string {dll});
    };

    for (const char *var : {"NDI_RUNTIME_DIR_V6", "NDI_RUNTIME_DIR_V5"}) {
      add_dir(getenv(var));
    }

    std::string program_files = getenv("ProgramFiles");
    if (!is_absolute_windows_path(program_files)) {
      program_files = "C:\\Program Files";
    }
    add_dir(program_files + "\\NDI\\NDI 6 Runtime\\v6");
    add_dir(program_files + "\\NDI\\NDI 6 Tools\\Runtime");
    add_dir(program_files + "\\NDI\\NDI 5 Runtime\\v5");
    add_dir(program_files + "\\NDI\\NDI 5 Tools\\Runtime");
    return paths;
  }

  /**
   * @brief Exponential backoff: 1 s, 2 s, 4 s ... capped at `cap`.
   * @param attempt Number of consecutive failures so far (0 gives the first delay).
   */
  inline std::chrono::milliseconds backoff_delay(int attempt, std::chrono::milliseconds cap = std::chrono::seconds {30}) {
    using namespace std::chrono_literals;
    auto delay = 1000ms;
    for (int i = 0; i < attempt && delay < cap; ++i) {
      delay *= 2;
    }
    return std::min<std::chrono::milliseconds>(delay, cap);
  }

  /**
   * @brief Quote one argument for a Windows command line (CommandLineToArgvW rules).
   */
  inline std::string quote_windows_arg(std::string_view arg) {
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string_view::npos) {
      return std::string {arg};
    }
    std::string out {'"'};
    std::size_t backslashes = 0;
    for (char c : arg) {
      if (c == '\\') {
        ++backslashes;
        continue;
      }
      if (c == '"') {
        out.append(backslashes * 2 + 1, '\\');
      } else {
        out.append(backslashes, '\\');
      }
      backslashes = 0;
      out += c;
    }
    out.append(backslashes * 2, '\\');
    out += '"';
    return out;
  }

  /// What the host passes to the plank-ndi helper on its command line.
  struct helper_options {
    int fps {default_fps};
    scope_e scope {scope_e::primary};
    std::string name;  ///< `ndi_source_name`; empty selects the default.
    std::string groups;  ///< `ndi_groups`; empty means the default NDI group.
  };

  /// Helper arguments (without argv[0]). Empty name/groups are left out.
  inline std::vector<std::string> build_helper_args(const helper_options &options) {
    std::vector<std::string> args {"--fps", std::to_string(clamp_fps(options.fps)), "--outputs", options.scope == scope_e::all ? "all" : "primary"};
    if (!options.name.empty()) {
      args.insert(args.end(), {"--name", options.name});
    }
    if (!options.groups.empty()) {
      args.insert(args.end(), {"--groups", options.groups});
    }
    return args;
  }

  /// Full command line: quoted executable path followed by the quoted arguments.
  inline std::string build_helper_command_line(std::string_view exe, const helper_options &options) {
    std::string line = quote_windows_arg(exe);
    for (const auto &arg : build_helper_args(options)) {
      line += ' ';
      line += quote_windows_arg(arg);
    }
    return line;
  }

  /// Parse the helper's arguments (without argv[0]); nullopt on anything unknown.
  inline std::optional<helper_options> parse_helper_args(const std::vector<std::string> &args) {
    helper_options options;
    for (std::size_t i = 0; i < args.size(); i += 2) {
      if (i + 1 >= args.size()) {
        return std::nullopt;
      }
      const auto &key = args[i];
      const auto &value = args[i + 1];
      if (key == "--fps") {
        try {
          std::size_t used = 0;
          const int fps = std::stoi(value, &used);
          if (used != value.size()) {
            return std::nullopt;
          }
          options.fps = clamp_fps(fps);
        } catch (...) {
          return std::nullopt;
        }
      } else if (key == "--outputs") {
        const auto scope = parse_scope(value);
        if (!scope) {
          return std::nullopt;
        }
        options.scope = *scope;
      } else if (key == "--name") {
        options.name = value;
      } else if (key == "--groups") {
        options.groups = value;
      } else {
        return std::nullopt;
      }
    }
    return options;
  }
}  // namespace plank::ndi
