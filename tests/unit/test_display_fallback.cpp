/**
 * @file tests/unit/test_display_fallback.cpp
 * @brief Tests for the one-screen display and mode fallback order.
 */
#include "src/session/display_fallback.h"

#include <gtest/gtest.h>

namespace da = plank::display_arrange;
using da::fallback_reason_t;
using da::mode_option_t;

namespace {
  da::display_modes_t display(std::string name, mode_option_t current, std::vector<mode_option_t> modes) {
    return {std::move(name), current, std::move(modes)};
  }

  // The 2026-10-03 failure: an emulator that tops out at 2560x1440 beside a
  // monitor that does 2560x1600.
  const std::vector<mode_option_t> emulator_modes {
    {1920, 1080, 60}, {1920, 1200, 60}, {2560, 1440, 60}, {1280, 720, 60}, {1024, 768, 60},
  };
  const std::vector<mode_option_t> monitor_modes {
    {1920, 1080, 60}, {2560, 1600, 60}, {2560, 1440, 60},
  };
}  // namespace

TEST(DisplayFallback, RequestedModeOnPreferredDisplayWins) {
  const std::vector<da::display_modes_t> displays {
    display("\\\\.\\DISPLAY1", {1920, 1080, 60}, emulator_modes),
    display("\\\\.\\DISPLAY2", {1920, 1080, 60}, monitor_modes),
  };
  const auto ranked = da::rank_mode_candidates(displays, 0, 2560, 1440, 0);
  ASSERT_FALSE(ranked.empty());
  EXPECT_EQ(ranked[0].display_index, 0U);
  EXPECT_EQ(ranked[0].reason, fallback_reason_t::requested_mode);
  EXPECT_EQ(ranked[0].mode, (mode_option_t {2560, 1440, 60}));
}

TEST(DisplayFallback, OtherDisplayServesTheRequestedModeNext) {
  const std::vector<da::display_modes_t> displays {
    display("\\\\.\\DISPLAY1", {1920, 1080, 60}, emulator_modes),
    display("\\\\.\\DISPLAY2", {1920, 1080, 60}, monitor_modes),
  };
  const auto ranked = da::rank_mode_candidates(displays, 0, 2560, 1600, 0);
  ASSERT_FALSE(ranked.empty());
  EXPECT_EQ(ranked[0].display_index, 1U);
  EXPECT_EQ(ranked[0].reason, fallback_reason_t::other_display);
  EXPECT_EQ(ranked[0].mode, (mode_option_t {2560, 1600, 60}));
  // The substitutes on the preferred display follow it.
  ASSERT_GT(ranked.size(), 1U);
  EXPECT_EQ(ranked[1].display_index, 0U);
}

TEST(DisplayFallback, NearestSameAspectBeforeLargestThatFits) {
  const std::vector<da::display_modes_t> displays {
    display("\\\\.\\DISPLAY1", {1920, 1080, 60}, emulator_modes),
  };
  // 2560x1600 is 16:10. 1920x1200 is the only 16:10 mode, so it beats the
  // larger 2560x1440.
  const auto ranked = da::rank_mode_candidates(displays, 0, 2560, 1600, 0);
  ASSERT_GE(ranked.size(), 3U);
  EXPECT_EQ(ranked[0].mode, (mode_option_t {1920, 1200, 60}));
  EXPECT_EQ(ranked[0].reason, fallback_reason_t::nearest_same_aspect);
  EXPECT_EQ(ranked[1].mode, (mode_option_t {2560, 1440, 60}));
  EXPECT_EQ(ranked[1].reason, fallback_reason_t::nearest_smaller);
  EXPECT_EQ(ranked[2].mode, (mode_option_t {1920, 1080, 60}));
}

TEST(DisplayFallback, SmallestLargerModeWhenNothingFits) {
  const std::vector<da::display_modes_t> displays {
    display("a", {3840, 2160, 60}, {{3840, 2160, 60}, {2560, 1440, 60}}),
  };
  const auto ranked = da::rank_mode_candidates(displays, 0, 1280, 720, 0);
  ASSERT_EQ(ranked.size(), 2U);
  EXPECT_EQ(ranked[0].mode, (mode_option_t {2560, 1440, 60}));
  EXPECT_EQ(ranked[0].reason, fallback_reason_t::nearest_any);
}

TEST(DisplayFallback, KeepsRefreshRateWhenPossible) {
  const std::vector<da::display_modes_t> displays {
    display("a", {1920, 1080, 120}, {{1920, 1080, 60}, {1920, 1080, 120}, {2560, 1440, 60}, {2560, 1440, 144}}),
  };
  // Own refresh (120) is the target when none is requested.
  auto ranked = da::rank_mode_candidates(displays, 0, 2560, 1440, 0);
  ASSERT_FALSE(ranked.empty());
  EXPECT_EQ(ranked[0].mode.refresh_hz, 144U);  // nearest to 120 is 144 (24) vs 60 (60)
  ranked = da::rank_mode_candidates(displays, 0, 2560, 1440, 60);
  EXPECT_EQ(ranked[0].mode.refresh_hz, 60U);
  // A substitute size also keeps the closest refresh.
  ranked = da::rank_mode_candidates(displays, 0, 2560, 1600, 60);
  ASSERT_FALSE(ranked.empty());
  EXPECT_EQ(ranked[0].mode, (mode_option_t {2560, 1440, 60}));
}

TEST(DisplayFallback, NothingToOfferGivesEmptyList) {
  EXPECT_TRUE(da::rank_mode_candidates({}, 0, 1920, 1080, 0).empty());
  const std::vector<da::display_modes_t> none {display("a", {}, {})};
  EXPECT_TRUE(da::rank_mode_candidates(none, 0, 1920, 1080, 0).empty());
  EXPECT_TRUE(da::rank_mode_candidates(none, 5, 1920, 1080, 0).empty());
  EXPECT_TRUE(da::rank_mode_candidates(none, 0, 0, 1080, 0).empty());
}

TEST(DisplayFallback, PrimarySwitchMovesDisplaysWithoutOverlap) {
  const std::vector<da::display_mode_t> layout {
    {"\\\\.\\DISPLAY1", 0, 0, 1920, 1080, 60, true},
    {"\\\\.\\DISPLAY2", 1920, 0, 1920, 1080, 60, false},
  };
  const auto switched = da::primary_switch_layout(layout, 1, 2560, 1600);
  ASSERT_EQ(switched.size(), 2U);
  EXPECT_TRUE(switched[1].primary);
  EXPECT_FALSE(switched[0].primary);
  EXPECT_EQ(switched[1].x, 0);
  EXPECT_EQ(switched[1].y, 0);
  EXPECT_EQ(switched[1].width, 2560U);
  EXPECT_EQ(switched[1].height, 1600U);
  // DISPLAY1 was left of DISPLAY2, so it stays left, touching the new primary.
  EXPECT_EQ(switched[0].x, -1920);
  EXPECT_EQ(switched[0].y, 0);
}

TEST(DisplayFallback, PrimarySwitchKeepsRightDisplayBesideResizedPrimary) {
  const std::vector<da::display_mode_t> layout {
    {"a", 0, 0, 1920, 1080, 60, true},
    {"b", 1920, 0, 1920, 1080, 60, false},
  };
  const auto switched = da::primary_switch_layout(layout, 0, 2560, 1440);
  EXPECT_EQ(switched[0].x, 0);
  EXPECT_EQ(switched[1].x, 2560);
  EXPECT_FALSE(switched[1].primary);
}
