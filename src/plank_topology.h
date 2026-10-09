/**
 * @file src/plank_topology.h
 * @brief Versioned PLANK display-layout negotiation primitives.
 */
#pragma once

#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace plank::topology {
  constexpr int maximum_virtual_canvas_width = 8192;
  constexpr std::uint32_t protocol_version = 13;
  constexpr std::uint32_t feature_output_topology = 0x1;
  constexpr std::uint32_t feature_selected_output = 0x2;
  constexpr std::uint32_t feature_unified_absolute_input = 0x4;
  constexpr std::uint32_t feature_scaled_span = 0x8;
  constexpr std::uint32_t feature_topology_generation = 0x10;
  constexpr std::uint32_t feature_host_layout_metadata = 0x20;
  constexpr std::uint32_t feature_composite_source_regions = 0x40;
  constexpr std::uint32_t feature_host_layout_binding = 0x80;
  constexpr std::uint32_t feature_independent_virtual_modes = 0x100;
  constexpr std::uint32_t feature_dynamic_host_layout = 0x200;
  constexpr std::uint32_t feature_temporary_physical_layout = 0x400;
  constexpr std::uint32_t feature_capture_source_selection = 0x800;
  constexpr std::uint32_t feature_encoder_backend_selection = 0x1000;
  constexpr std::uint32_t feature_nvfbc_hevc10_nvenc = 0x2000;
  constexpr std::uint32_t feature_fixed_transport_mtu = 0x4000;
  constexpr std::uint32_t feature_session_takeover = 0x8000;
  constexpr std::uint32_t feature_desktop_handoff_notice = 0x10000;
  constexpr std::uint32_t feature_authenticated_desktop_stage = 0x20000;
  constexpr std::uint32_t feature_worker_instance = 0x40000;
  // 0x80000 - 0x200000 are reserved by client builds for capture and macOS bits.
  constexpr std::uint32_t feature_clipboard_sync = 0x400000;
  // Windows hosts shared plain text under this bit in their own unframed
  // format before adopting the framed clipboard-sync protocol; the old name
  // stays until that switch lands.
  constexpr std::uint32_t feature_clipboard_text = feature_clipboard_sync;
#if (defined(__linux__) && defined(SUNSHINE_BUILD_X11)) || defined(_WIN32)
  constexpr std::uint32_t feature_platform_clipboard_sync = feature_clipboard_sync;
#else
  constexpr std::uint32_t feature_platform_clipboard_sync = 0;
#endif
  // Windows hosts join two outputs into one canvas only for clients that ask.
  constexpr std::uint32_t feature_two_screen_capture = 0x800000;
  // The client may ask the host to fit the encoder to its link per session.
  constexpr std::uint32_t feature_adaptive_bitrate = 0x1000000;
  constexpr std::uint32_t feature_flags =
    feature_output_topology |
    feature_selected_output |
    feature_unified_absolute_input |
    feature_scaled_span |
    feature_topology_generation |
    feature_host_layout_metadata |
    feature_composite_source_regions |
    feature_host_layout_binding |
    feature_independent_virtual_modes |
    feature_dynamic_host_layout |
    feature_temporary_physical_layout |
    feature_capture_source_selection |
    feature_encoder_backend_selection |
    feature_nvfbc_hevc10_nvenc |
    feature_fixed_transport_mtu |
    feature_session_takeover |
    feature_desktop_handoff_notice |
    feature_authenticated_desktop_stage |
    feature_worker_instance |
    feature_platform_clipboard_sync |
    feature_two_screen_capture |
    feature_adaptive_bitrate;

  /**
   * @brief How a Windows host decides to publish one screen instead of all.
   */
  enum class one_screen_mode {
    automatic,  ///< One screen only for clients without the two-screen capability.
    always,  ///< One screen for every client.
    never,  ///< Never narrow automatically; the manual one-screen file still applies.
  };

  constexpr one_screen_mode parse_one_screen_mode(std::string_view value) {
    if (value == "always") return one_screen_mode::always;
    if (value == "never") return one_screen_mode::never;
    return one_screen_mode::automatic;
  }

  /**
   * @brief Decide whether a client is shown only the primary output.
   *
   * @param mode The one_screen host setting.
   * @param override_file Whether the manual one-screen file exists. It forces
   *        one screen for everyone, whatever the setting.
   * @param client_flags The client's feature bits, or nullopt when the host
   *        does not know the client yet (an unidentified topology request).
   * @param output_count Outputs that would otherwise be published.
   * @return True when only the primary output should be published and captured.
   */
  constexpr bool publish_single_output(
    one_screen_mode mode,
    bool override_file,
    std::optional<std::uint32_t> client_flags,
    std::size_t output_count
  ) {
    if (output_count < 2) return false;
    if (override_file || mode == one_screen_mode::always) return true;
    if (mode == one_screen_mode::never || !client_flags) return false;
    return (*client_flags & feature_two_screen_capture) == 0;
  }

  /**
   * @brief Decide whether a launch must be refused so the client re-reads the topology.
   *
   * The client laid out the topology the host published for the flags it had
   * remembered for that client (nullopt when the client was unknown). If the
   * launch's own flags would have produced a different publication, picture and
   * mouse mapping would disagree, so the client refreshes and retries. The host
   * records the new flags first, so the retry sees equal publications and passes.
   *
   * @param previous_flags Flags remembered before this launch, or nullopt.
   * @param launch_flags Flags this launch declares.
   * @return True when the launch should answer 409 refresh-and-retry.
   */
  constexpr bool launch_needs_topology_refresh(
    one_screen_mode mode,
    bool override_file,
    std::optional<std::uint32_t> previous_flags,
    std::uint32_t launch_flags,
    std::size_t output_count
  ) {
    return publish_single_output(mode, override_file, previous_flags, output_count) !=
           publish_single_output(mode, override_file, launch_flags, output_count);
  }

  /**
   * @brief Decide whether a launch that did not succeed must give the host displays back.
   *
   * The display lease is otherwise released only when a stream ends, and a failed launch
   * starts none, so every account would get 423 until the host restarted. A 425 or a
   * topology refresh means the client retries against the changed displays, so those
   * keep the lease (a timer returns it if the client gives up).
   *
   * @param lease_held_by_launch Whether this launch applied a display transition or holds the account's lease.
   * @param status_code The HTTP-style status the launch is about to answer with.
   * @param client_retries Whether the outcome tells the client to retry against the changed displays.
   * @return True when the lease must be released now.
   */
  constexpr bool should_release_display_lease_on_launch_exit(
    bool lease_held_by_launch,
    int status_code,
    bool client_retries
  ) {
    return lease_held_by_launch && status_code != 200 && !client_retries;
  }

  /**
   * @brief Decide whether the lease timer should restore the displays when it fires.
   *
   * @param lease_held Whether a lease is still held.
   * @param stream_started Whether a stream activated the lease since it was acquired.
   * @param armed_generation Generation of the lease the timer was armed for.
   * @param current_generation Generation of the lease held now.
   * @param launch_pending Whether an accepted launch (a 200 answer) still owns native setup.
   * @return True when the displays must be restored.
   */
  constexpr bool lease_timer_should_release(
    bool lease_held,
    bool stream_started,
    std::uint64_t armed_generation,
    std::uint64_t current_generation,
    bool launch_pending = false
  ) {
    return lease_held && !stream_started && armed_generation == current_generation && !launch_pending;
  }

  /**
   * @brief Decide whether the lease timer should wait another period instead of restoring.
   *
   * True when the lease is still current and unstarted but an accepted launch is setting up
   * its media session, so restoring the displays now would pull them out from under it.
   */
  constexpr bool lease_timer_should_rearm(
    bool lease_held,
    bool stream_started,
    std::uint64_t armed_generation,
    std::uint64_t current_generation,
    bool launch_pending
  ) {
    return lease_held && !stream_started && armed_generation == current_generation && launch_pending;
  }

  constexpr bool valid_quic_udp_payload_mtu(std::uint32_t mtu) {
    return mtu >= 1200 && mtu <= 65527;
  }

  enum class layout_error {
    none,
    invalid_request,
    mismatch,
    unhealthy,
  };

  struct mode_size {
    int width;
    int height;
  };

  constexpr mode_size virtual_mode_size(std::string_view mode) {
    if (mode == "1024x2160") return {1024, 2160};
    if (mode == "1280x2160") return {1280, 2160};
    if (mode == "1920x1080") return {1920, 1080};
    if (mode == "1920x1200") return {1920, 1200};
    if (mode == "2560x1440") return {2560, 1440};
    if (mode == "2560x1600") return {2560, 1600};
    if (mode == "2560x2160") return {2560, 2160};
    if (mode == "3440x1440") return {3440, 1440};
    if (mode == "3840x1600") return {3840, 1600};
    if (mode == "3840x2160") return {3840, 2160};
    if (mode == "4096x2160") return {4096, 2160};
    if (mode == "5120x2160") return {5120, 2160};
    return {0, 0};
  }

  /**
   * @brief Size from a generic "WIDTHxHEIGHT" string.
   *
   * Unlike virtual_mode_size() this accepts any size, because a host that
   * substitutes a mode the display supports records it as plain text, and the
   * substitute need not be one of the sizes a client can ask for.
   *
   * @return The size, or {0, 0} when the text is not exactly two decimal
   *         numbers around an 'x', or either is zero or above 16384.
   */
  constexpr mode_size parse_mode_size(std::string_view mode) {
    constexpr int maximum_dimension = 16384;
    int values[2] {0, 0};
    int index = 0;
    bool digits = false;
    for (const char c : mode) {
      if (c >= '0' && c <= '9') {
        values[index] = values[index] * 10 + (c - '0');
        if (values[index] > maximum_dimension) return {0, 0};
        digits = true;
      } else if (c == 'x' && index == 0 && digits) {
        index = 1;
        digits = false;
      } else {
        return {0, 0};
      }
    }
    if (index != 1 || !digits || values[0] == 0 || values[1] == 0) return {0, 0};
    return {values[0], values[1]};
  }

  constexpr bool valid_layout(std::string_view layout) {
    return layout == "physical" ||
           layout == "single" ||
           layout == "dual-horizontal";
  }

  constexpr bool layout_allowed_by_startup_layout(
    std::string_view layout,
    std::string_view startup_layout
  ) {
    if (!valid_layout(layout) || !valid_layout(startup_layout)) return false;
    return startup_layout == "physical" || layout != "physical";
  }

  constexpr bool valid_virtual_mode(std::string_view mode) {
    const auto size = virtual_mode_size(mode);
    return size.width > 0 && size.height > 0;
  }

  constexpr bool valid_encoding_tuple(
    std::string_view capture_source,
    std::string_view encoder_backend,
    std::string_view encoding_mode
  ) {
    if (encoder_backend == "software-cuda") {
      if (capture_source == "nvfbc") {
        return encoding_mode == "h264-8-422-software" ||
               encoding_mode == "h264-8-444-software" ||
               encoding_mode == "h264-10-422-software" ||
               encoding_mode == "h264-10-444-software";
      }
      return capture_source == "x11-native10" &&
             encoding_mode == "h264-10-444-software";
    }
    if (encoder_backend == "nvenc-direct") {
      if (capture_source == "nvfbc") {
        return encoding_mode == "h264-8-444-nvenc" ||
               encoding_mode == "hevc-8-444-nvenc" ||
               encoding_mode == "hevc-8-420-nvenc" ||
               encoding_mode == "hevc-10-444-nvenc";
      }
      return capture_source == "x11-native10" &&
             encoding_mode == "hevc-10-444-nvenc";
    }
    return false;
  }

  constexpr bool valid_virtual_layout_modes(
    std::string_view layout,
    std::string_view mode_1,
    std::string_view mode_2
  ) {
    const auto first = virtual_mode_size(mode_1);
    if (layout == "single") {
      return first.width > 0 && first.height > 0 && mode_2.empty();
    }
    if (layout != "dual-horizontal") return false;
    const auto second = virtual_mode_size(mode_2);
    return first.width > 0 && first.height > 0 &&
           second.width > 0 && second.height > 0 &&
           first.width + second.width <= maximum_virtual_canvas_width;
  }

  constexpr layout_error validate_layout_binding(
    std::string_view requested_layout,
    std::string_view requested_mode_1,
    std::string_view requested_mode_2,
    std::string_view actual_layout,
    std::string_view actual_mode_1,
    std::string_view actual_mode_2,
    std::size_t output_count
  ) {
    if (!valid_layout(requested_layout) ||
        (requested_layout == "physical" &&
         (!requested_mode_1.empty() || !requested_mode_2.empty())) ||
        (requested_layout != "physical" &&
         !valid_virtual_layout_modes(
           requested_layout, requested_mode_1, requested_mode_2
         ))) {
      return layout_error::invalid_request;
    }
    if (requested_layout != actual_layout ||
        requested_mode_1 != actual_mode_1 ||
        requested_mode_2 != actual_mode_2) {
      return layout_error::mismatch;
    }
    if ((actual_layout == "single" && output_count != 1) ||
        (actual_layout == "dual-horizontal" && output_count != 2) ||
        (actual_layout == "physical" && output_count == 0)) {
      return layout_error::unhealthy;
    }
    return layout_error::none;
  }

  /**
   * @brief Bounded most-recently-used map from a client key to its feature bits.
   *
   * Lets the host remember what each client declared at launch so a later
   * topology request, which carries no feature bits, can be answered for it.
   */
  class client_flag_store {
  public:
    static constexpr std::size_t max_entries = 256;

    std::optional<std::uint32_t> lookup(std::string_view key) const {
      const auto found = std::find_if(entries_.begin(), entries_.end(), [key](const auto &entry) {
        return entry.first == key;
      });
      if (found == entries_.end()) return std::nullopt;
      return found->second;
    }

    /**
     * @return True when the stored contents changed and need saving.
     */
    bool record(std::string_view key, std::uint32_t flags) {
      if (key.empty()) return false;
      const auto found = std::find_if(entries_.begin(), entries_.end(), [key](const auto &entry) {
        return entry.first == key;
      });
      if (found != entries_.end()) {
        if (found->second == flags && found == entries_.begin()) return false;
        const bool same = found->second == flags;
        std::pair<std::string, std::uint32_t> entry {found->first, flags};
        entries_.erase(found);
        entries_.insert(entries_.begin(), std::move(entry));
        // Recency alone is only saved when it changes which entry is oldest.
        return !same;
      }
      entries_.insert(entries_.begin(), {std::string {key}, flags});
      if (entries_.size() > max_entries) entries_.resize(max_entries);
      return true;
    }

    std::size_t size() const { return entries_.size(); }

    nlohmann::json to_json() const {
      auto list = nlohmann::json::array();
      for (const auto &[key, flags] : entries_) {
        list.push_back({{"key", key}, {"flags", flags}});
      }
      return {{"version", 1}, {"clients", list}};
    }

    /**
     * @brief Parse a saved store. Anything malformed yields an empty or partial store.
     */
    static client_flag_store from_json(std::string_view text) {
      client_flag_store store;
      const auto document = nlohmann::json::parse(text.begin(), text.end(), nullptr, false);
      if (!document.is_object() || !document.contains("clients") || !document["clients"].is_array()) {
        return store;
      }
      for (const auto &item : document["clients"]) {
        if (store.entries_.size() >= max_entries) break;
        if (!item.is_object() || !item.contains("key") || !item["key"].is_string() ||
            !item.contains("flags") || !item["flags"].is_number_unsigned()) {
          continue;
        }
        const auto flags = item["flags"].get<std::uint64_t>();
        const auto key = item["key"].get<std::string>();
        if (flags > 0xFFFFFFFFULL || key.empty() || store.lookup(key)) continue;
        store.entries_.emplace_back(key, static_cast<std::uint32_t>(flags));
      }
      return store;
    }

  private:
    std::vector<std::pair<std::string, std::uint32_t>> entries_;  ///< Most recent first.
  };
}  // namespace plank::topology
