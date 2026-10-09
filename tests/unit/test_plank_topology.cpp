/**
 * @file tests/unit/test_plank_topology.cpp
 * @brief Tests for exact PLANK host-layout binding.
 */
#include "src/plank_topology.h"

#include <gtest/gtest.h>

#include <string>

namespace topology = plank::topology;

TEST(PlankTopology, PublishesVersionThirteenFeatureContract) {
  EXPECT_EQ(topology::protocol_version, 13U);
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  EXPECT_EQ(topology::feature_flags, 0x47FFFFU);
  EXPECT_NE(topology::feature_flags & topology::feature_clipboard_sync, 0U);
#else
  EXPECT_EQ(topology::feature_flags, 0x7FFFFU);
  EXPECT_EQ(topology::feature_flags & topology::feature_clipboard_sync, 0U);
#endif
  EXPECT_NE(topology::feature_flags & topology::feature_nvfbc_hevc10_nvenc, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_fixed_transport_mtu, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_session_takeover, 0U);
  EXPECT_TRUE(topology::valid_virtual_mode("1024x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("2560x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("4096x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("5120x2160"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x720"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x1024"));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1024x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1280x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "4096x2160"
  ));
}

TEST(PlankTopology, AcceptsOnlyValidFixedQuicPayloadCeilings) {
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1200));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1344));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1452));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(65527));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(0));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(1199));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(65528));
}

TEST(PlankTopology, AcceptsOnlyExactEncodingTuples) {
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "h264-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-10-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-10-444-nvenc"
  ));

  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-8-444-software"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "ffmpeg-nvenc", "h264-8-444-nvenc"
  ));
}

TEST(PlankTopology, AcceptsExactQualifiedLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "", "", "physical", "", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "4096x2160", "", "single", "4096x2160", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1280x2160", 2),
            topology::layout_error::none);
}

TEST(PlankTopology, EnforcesAdministratorDisplayPolicy) {
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("physical", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "physical"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("physical", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "single"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("dual-vertical", "physical"));
}

TEST(PlankTopology, RejectsMismatchBeforeLaunchState) {
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1024x2160", 2),
            topology::layout_error::mismatch);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1024x2160", 2),
            topology::layout_error::mismatch);
}

TEST(PlankTopology, RejectsInvalidAndUnhealthyLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-vertical", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1280x2160", 2),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "1920x1080", "", "physical", "", "", 1),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080", "1280x2160",
              "dual-horizontal", "1920x1080", "1280x2160", 1),
            topology::layout_error::unhealthy);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "1280x2160",
              "single", "1920x1080", "", 1),
            topology::layout_error::invalid_request);
}

TEST(PlankTopology, ParsesOneScreenMode) {
  EXPECT_EQ(topology::parse_one_screen_mode("auto"), topology::one_screen_mode::automatic);
  EXPECT_EQ(topology::parse_one_screen_mode(""), topology::one_screen_mode::automatic);
  EXPECT_EQ(topology::parse_one_screen_mode("bogus"), topology::one_screen_mode::automatic);
  EXPECT_EQ(topology::parse_one_screen_mode("always"), topology::one_screen_mode::always);
  EXPECT_EQ(topology::parse_one_screen_mode("never"), topology::one_screen_mode::never);
}

TEST(PlankTopology, AutoNarrowsOnlyClientsLackingTwoScreenCapture) {
  using topology::one_screen_mode;
  const std::uint32_t legacy = topology::feature_flags & ~topology::feature_two_screen_capture;
  const std::uint32_t modern = topology::feature_flags;
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::automatic, false, legacy, 2));
  EXPECT_FALSE(topology::publish_single_output(one_screen_mode::automatic, false, modern, 2));
  // An unidentified client keeps the full list.
  EXPECT_FALSE(topology::publish_single_output(one_screen_mode::automatic, false, std::nullopt, 2));
  // A client that sent no feature bits at all is a legacy client.
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::automatic, false, 0U, 2));
  // One output never needs narrowing.
  EXPECT_FALSE(topology::publish_single_output(one_screen_mode::automatic, false, legacy, 1));
  EXPECT_FALSE(topology::publish_single_output(one_screen_mode::always, true, legacy, 1));
}

TEST(PlankTopology, OneScreenOverrides) {
  using topology::one_screen_mode;
  const std::uint32_t modern = topology::feature_flags;
  // The manual file forces one screen for everyone in every mode.
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::automatic, true, modern, 2));
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::never, true, modern, 2));
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::always, false, modern, 2));
  EXPECT_TRUE(topology::publish_single_output(one_screen_mode::always, false, std::nullopt, 2));
  // never turns the automatic behaviour off.
  EXPECT_FALSE(topology::publish_single_output(one_screen_mode::never, false, 0U, 2));
}

TEST(PlankTopology, ClientFlagStoreRemembersAndReportsChanges) {
  topology::client_flag_store store;
  EXPECT_FALSE(store.lookup("a").has_value());
  EXPECT_TRUE(store.record("a", 5));
  EXPECT_EQ(store.lookup("a"), 5U);
  EXPECT_FALSE(store.record("a", 5));
  EXPECT_TRUE(store.record("a", 6));
  EXPECT_EQ(store.lookup("a"), 6U);
  EXPECT_FALSE(store.record("", 1));
  EXPECT_EQ(store.size(), 1U);
}

TEST(PlankTopology, ClientFlagStoreEvictsOldest) {
  topology::client_flag_store store;
  for (std::size_t i = 0; i < topology::client_flag_store::max_entries; ++i) {
    store.record("k" + std::to_string(i), 1);
  }
  store.record("k0", 1);  // k0 becomes most recent; k1 is now oldest
  store.record("new", 2);
  EXPECT_EQ(store.size(), topology::client_flag_store::max_entries);
  EXPECT_TRUE(store.lookup("k0").has_value());
  EXPECT_FALSE(store.lookup("k1").has_value());
  EXPECT_EQ(store.lookup("new"), 2U);
}

TEST(PlankTopology, ClientFlagStoreRoundTripsAndToleratesCorruption) {
  topology::client_flag_store store;
  store.record("id:DOM\\amy|10.0.0.5", 0x7FFFFU);
  store.record("ip:10.0.0.9", 0U);
  const auto loaded = topology::client_flag_store::from_json(store.to_json().dump());
  EXPECT_EQ(loaded.size(), 2U);
  EXPECT_EQ(loaded.lookup("id:DOM\\amy|10.0.0.5"), 0x7FFFFU);
  EXPECT_EQ(loaded.lookup("ip:10.0.0.9"), 0U);
  EXPECT_EQ(topology::client_flag_store::from_json("").size(), 0U);
  EXPECT_EQ(topology::client_flag_store::from_json("{not json").size(), 0U);
  EXPECT_EQ(topology::client_flag_store::from_json("[1,2]").size(), 0U);
  const auto partial = topology::client_flag_store::from_json(
    R"({"clients":[{"key":"a","flags":-1},{"key":"b","flags":4294967296},{"key":"c","flags":7},{"flags":1},3]})");
  EXPECT_EQ(partial.size(), 1U);
  EXPECT_EQ(partial.lookup("c"), 7U);
}

TEST(PlankTopology, LaunchRefreshDecision) {
  using topology::one_screen_mode;
  const std::uint32_t legacy = topology::feature_flags & ~topology::feature_two_screen_capture;
  const std::uint32_t modern = topology::feature_flags;
  const auto refresh = [](one_screen_mode mode, bool file, std::optional<std::uint32_t> previous,
                          std::uint32_t launch, std::size_t outputs) {
    return topology::launch_needs_topology_refresh(mode, file, previous, launch, outputs);
  };
  // Unknown client that will be narrowed laid out both screens: refresh.
  EXPECT_TRUE(refresh(one_screen_mode::automatic, false, std::nullopt, legacy, 2));
  // Unknown client that keeps the full list already saw it: proceed.
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, std::nullopt, modern, 2));
  // Same flags twice always passes, so the retry cannot loop.
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, legacy, legacy, 2));
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, modern, modern, 2));
  // Flags differ but the publication is the same (forced one screen, never, 1 output).
  EXPECT_FALSE(refresh(one_screen_mode::automatic, true, modern, legacy, 2));
  EXPECT_FALSE(refresh(one_screen_mode::always, false, modern, legacy, 2));
  EXPECT_FALSE(refresh(one_screen_mode::never, false, modern, legacy, 2));
  // Flags differ and so does the publication, in both directions.
  EXPECT_TRUE(refresh(one_screen_mode::automatic, false, modern, legacy, 2));
  EXPECT_TRUE(refresh(one_screen_mode::automatic, false, legacy, modern, 2));
  // A single-output host never refreshes.
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, std::nullopt, legacy, 1));
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, modern, legacy, 1));
  EXPECT_FALSE(refresh(one_screen_mode::automatic, false, legacy, modern, 1));
}
