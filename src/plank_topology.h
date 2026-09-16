/**
 * @file src/plank_topology.h
 * @brief Versioned PLANK display-layout negotiation primitives.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

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
  constexpr std::uint32_t feature_clipboard_text = 0x400000;
  // Windows hosts join two outputs into one canvas only for clients that ask.
  constexpr std::uint32_t feature_two_screen_capture = 0x800000;
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
    feature_clipboard_text |
    feature_two_screen_capture;

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
}  // namespace plank::topology
