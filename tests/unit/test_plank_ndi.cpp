/**
 * @file tests/unit/test_plank_ndi.cpp
 * @brief Tests the pure logic behind the optional NDI screen output.
 */

#include "src/plank_ndi.h"

#include <map>

#include "../tests_common.h"

using namespace std::chrono_literals;
namespace ndi = plank::ndi;

TEST(PlankNdi, ParsesEnabled) {
  EXPECT_EQ(ndi::parse_enabled("on"), true);
  EXPECT_EQ(ndi::parse_enabled("  ON "), true);
  EXPECT_EQ(ndi::parse_enabled("true"), true);
  EXPECT_EQ(ndi::parse_enabled("off"), false);
  EXPECT_EQ(ndi::parse_enabled("Off"), false);
  EXPECT_EQ(ndi::parse_enabled("0"), false);
  EXPECT_FALSE(ndi::parse_enabled("maybe").has_value());
  EXPECT_FALSE(ndi::parse_enabled("").has_value());
}

TEST(PlankNdi, ParsesScope) {
  EXPECT_EQ(ndi::parse_scope("primary"), ndi::scope_e::primary);
  EXPECT_EQ(ndi::parse_scope(" ALL"), ndi::scope_e::all);
  EXPECT_FALSE(ndi::parse_scope("both").has_value());
}

TEST(PlankNdi, ClampsFps) {
  EXPECT_EQ(ndi::clamp_fps(30), 30);
  EXPECT_EQ(ndi::clamp_fps(144), 60);
  EXPECT_EQ(ndi::clamp_fps(0), 1);
  EXPECT_EQ(ndi::clamp_fps(-5), 1);
}

TEST(PlankNdi, SourceNames) {
  EXPECT_EQ(ndi::source_name("", "DOOM", 1, 1), "DOOM - Screen 1");
  EXPECT_EQ(ndi::source_name("", "DOOM", 2, 3), "DOOM - Screen 2");
  EXPECT_EQ(ndi::source_name("", "", 1, 1), "PLANK - Screen 1");
  EXPECT_EQ(ndi::source_name("Colour Review", "DOOM", 1, 1), "Colour Review");
  EXPECT_EQ(ndi::source_name("Colour Review", "DOOM", 2, 2), "Colour Review 2");
  EXPECT_EQ(ndi::source_name("   ", "DOOM", 1, 1), "DOOM - Screen 1");
  EXPECT_EQ(ndi::source_name("  Edit\tBay ", "DOOM", 1, 1), "EditBay");
}

TEST(PlankNdi, SourceNameIsBounded) {
  const std::string long_name(500, 'a');
  EXPECT_EQ(ndi::source_name(long_name, "DOOM", 1, 1).size(), ndi::max_source_name_bytes);

  // A multi-byte character straddling the limit must not be cut in half.
  std::string utf8(ndi::max_source_name_bytes - 1, 'a');
  utf8 += "\xC3\xA9\xC3\xA9";
  const auto name = ndi::source_name(utf8, "DOOM", 1, 1);
  EXPECT_EQ(name.size(), ndi::max_source_name_bytes - 1);
}

TEST(PlankNdi, SelectsOutputsInStableOrder) {
  std::vector<ndi::output_ref> outputs {
    {"\\\\.\\DISPLAY3", 3840, 0, false},
    {"\\\\.\\DISPLAY2", -2560, 0, false},
    {"\\\\.\\DISPLAY1", 0, 0, true},
  };

  const auto all = ndi::select_outputs(outputs, ndi::scope_e::all);
  ASSERT_EQ(all.size(), 3u);
  EXPECT_EQ(all[0].capture_name, "\\\\.\\DISPLAY1");
  EXPECT_EQ(all[1].capture_name, "\\\\.\\DISPLAY2");
  EXPECT_EQ(all[2].capture_name, "\\\\.\\DISPLAY3");

  const auto primary = ndi::select_outputs(outputs, ndi::scope_e::primary);
  ASSERT_EQ(primary.size(), 1u);
  EXPECT_EQ(primary[0].capture_name, "\\\\.\\DISPLAY1");

  EXPECT_TRUE(ndi::select_outputs({}, ndi::scope_e::all).empty());
}

TEST(PlankNdi, FrameInterval) {
  EXPECT_EQ(ndi::frame_interval(30), 33'333'333ns);
  EXPECT_EQ(ndi::frame_interval(60), 16'666'666ns);
  EXPECT_EQ(ndi::frame_interval(1000), ndi::frame_interval(60));
}

TEST(PlankNdi, PacingSendsNewFramesAtConfiguredRate) {
  // 30 fps: interval 33.3 ms.
  EXPECT_TRUE(ndi::should_send(true, false, 33ms, 30));
  EXPECT_TRUE(ndi::should_send(true, false, 17ms, 30));
  EXPECT_FALSE(ndi::should_send(true, false, 5ms, 30));
}

TEST(PlankNdi, PacingFlushesHeldBackFrameOnIdle) {
  EXPECT_FALSE(ndi::should_send(false, true, 20ms, 30));
  EXPECT_TRUE(ndi::should_send(false, true, 34ms, 30));
}

TEST(PlankNdi, PacingRefreshesIdleDesktop) {
  EXPECT_FALSE(ndi::should_send(false, false, 200ms, 30));
  EXPECT_TRUE(ndi::should_send(false, false, 500ms, 30));
  EXPECT_TRUE(ndi::should_send(false, false, 5s, 30));
}

TEST(PlankNdi, RuntimeLookupOrder) {
  std::map<std::string, std::string> env {
    {"NDI_RUNTIME_DIR_V6", "C:\\NDI\\v6"},
    {"NDI_RUNTIME_DIR_V5", "D:\\NDI5\\"},
    {"ProgramFiles", "E:\\PF"},
  };
  const auto paths = ndi::runtime_candidates([&](const char *name) {
    auto it = env.find(name);
    return it == env.end() ? std::string {} : it->second;
  });

  ASSERT_GE(paths.size(), 7u);
  EXPECT_EQ(paths[0], "C:\\NDI\\v6\\Processing.NDI.Lib.x64.dll");
  EXPECT_EQ(paths[1], "D:\\NDI5\\Processing.NDI.Lib.x64.dll");
  EXPECT_EQ(paths[2], "E:\\PF\\NDI\\NDI 6 Runtime\\v6\\Processing.NDI.Lib.x64.dll");
  EXPECT_EQ(paths.back(), "Processing.NDI.Lib.x64.dll");
}

TEST(PlankNdi, RuntimeLookupWithoutEnvironment) {
  const auto paths = ndi::runtime_candidates([](const char *) {
    return std::string {};
  });
  ASSERT_FALSE(paths.empty());
  EXPECT_EQ(paths.front(), "C:\\Program Files\\NDI\\NDI 6 Runtime\\v6\\Processing.NDI.Lib.x64.dll");
}
