/**
 * @file src/platform/windows/ndi_runtime.h
 * @brief Minimal declarations for loading the NDI runtime DLL at run time.
 *
 * LICENSING: this host is GPL-3. The NDI SDK is proprietary, so it is NOT
 * vendored, bundled, or linked, and none of its headers are copied here. The
 * structs and enums below are our own declarations of the small slice of the
 * public NDI C ABI that the sender needs (NDIlib_send_create_t,
 * NDIlib_video_frame_v2_t and the FourCC / frame-format values). They mirror
 * the field order, field types and sizes of the public SDK so that the runtime
 * DLL, which the user installs separately (NDI Tools from ndi.video), can be
 * called through plain GetProcAddress pointers. Nothing else from the SDK is
 * used. If a future NDI major version changes this ABI the sender must be
 * revisited; the exported function names carry their own version suffixes
 * (for example `_v2`) precisely so the old layouts stay valid.
 */
#pragma once

#include <cstdint>

namespace platf::ndi_abi {
  /// NDIlib_send_instance_t: an opaque handle.
  using send_instance_t = void *;

  /// NDI_LIB_FOURCC(a, b, c, d): little-endian packing of four characters.
  constexpr std::uint32_t fourcc(char a, char b, char c, char d) {
    return static_cast<std::uint32_t>(static_cast<std::uint8_t>(a)) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(b)) << 8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(c)) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(d)) << 24);
  }

  /// NDIlib_FourCC_video_type_e (a C enum, 32 bits). Only BGRX is used: 8-bit
  /// B,G,R,X byte order with the fourth byte ignored, which is exactly what
  /// Windows desktop capture produces (its alpha byte is not meaningful).
  enum fourcc_video_e : std::uint32_t {
    fourcc_bgra = 'B' | ('G' << 8) | ('R' << 16) | ('A' << 24),
    fourcc_bgrx = 'B' | ('G' << 8) | ('R' << 16) | ('X' << 24),
  };

  /// NDIlib_frame_format_type_e (a C enum, 32 bits).
  enum frame_format_e : std::int32_t {
    frame_format_progressive = 1,
  };

  /// NDIlib_send_timecode_synthesize == INT64_MAX: let the runtime stamp frames.
  constexpr std::int64_t timecode_synthesize = INT64_MAX;

  /// NDIlib_send_create_t. `bool` is the C99 _Bool of the SDK (1 byte).
  struct send_create_t {
    const char *p_ndi_name;  ///< Source name, UTF-8.
    const char *p_groups;  ///< Comma separated groups, or null for the default group.
    bool clock_video;  ///< If true the runtime paces send_video to the frame rate.
    bool clock_audio;  ///< Same for audio (unused here).
  };

  /// NDIlib_video_frame_v2_t.
  struct video_frame_v2_t {
    int xres;
    int yres;
    std::uint32_t FourCC;  ///< NDIlib_FourCC_video_type_e
    int frame_rate_N;
    int frame_rate_D;
    float picture_aspect_ratio;  ///< 0 selects square pixels.
    std::int32_t frame_format_type;  ///< NDIlib_frame_format_type_e
    std::int64_t timecode;
    std::uint8_t *p_data;
    union {
      int line_stride_in_bytes;  ///< For uncompressed formats.
      int data_size_in_bytes;  ///< For compressed formats.
    };
    const char *p_metadata;  ///< Null-terminated XML, or null.
    std::int64_t timestamp;  ///< Receiver-side field; ignored when sending.
  };

  // Guard the layout we rely on (LP64/LLP64 x64 Windows).
  static_assert(sizeof(send_create_t) == 24, "NDIlib_send_create_t layout");
  static_assert(sizeof(video_frame_v2_t) == 72, "NDIlib_video_frame_v2_t layout");

  // Entry points. The names are the exported symbols of Processing.NDI.Lib.x64.dll.
  using initialize_fn = bool (*)();
  using destroy_fn = void (*)();
  using send_create_fn = send_instance_t (*)(const send_create_t *);
  using send_destroy_fn = void (*)(send_instance_t);
  using send_video_v2_fn = void (*)(send_instance_t, const video_frame_v2_t *);
}  // namespace platf::ndi_abi
