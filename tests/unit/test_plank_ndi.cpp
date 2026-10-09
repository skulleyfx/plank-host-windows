/**
 * @file tests/unit/test_plank_ndi.cpp
 * @brief Tests the pure logic behind the optional NDI screen output.
 */

#include "src/plank_ndi.h"

#include <map>
#include <vector>

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

  ASSERT_EQ(paths.size(), 6u);
  EXPECT_EQ(paths[0], "C:\\NDI\\v6\\Processing.NDI.Lib.x64.dll");
  EXPECT_EQ(paths[1], "D:\\NDI5\\Processing.NDI.Lib.x64.dll");
  EXPECT_EQ(paths[2], "E:\\PF\\NDI\\NDI 6 Runtime\\v6\\Processing.NDI.Lib.x64.dll");
  for (const auto &path : paths) {
    EXPECT_TRUE(ndi::is_absolute_windows_path(path));  // never a bare DLL name
  }
}

TEST(PlankNdi, RuntimeLookupWithoutEnvironment) {
  const auto paths = ndi::runtime_candidates([](const char *) {
    return std::string {};
  });
  ASSERT_FALSE(paths.empty());
  EXPECT_EQ(paths.front(), "C:\\Program Files\\NDI\\NDI 6 Runtime\\v6\\Processing.NDI.Lib.x64.dll");
}

TEST(PlankNdi, RuntimeLookupRejectsRelativeEnvironmentPaths) {
  std::map<std::string, std::string> env {
    {"NDI_RUNTIME_DIR_V6", "..\\evil"},
    {"NDI_RUNTIME_DIR_V5", "relative\\dir"},
    {"ProgramFiles", "not absolute"},
  };
  const auto paths = ndi::runtime_candidates([&](const char *name) {
    auto it = env.find(name);
    return it == env.end() ? std::string {} : it->second;
  });
  ASSERT_FALSE(paths.empty());
  for (const auto &path : paths) {
    EXPECT_TRUE(path.rfind("C:\\Program Files\\NDI\\", 0) == 0);
  }
  EXPECT_TRUE(ndi::is_absolute_windows_path("\\\\server\\share"));
  EXPECT_FALSE(ndi::is_absolute_windows_path("C:relative"));
  EXPECT_FALSE(ndi::is_absolute_windows_path(""));
}

TEST(PlankNdi, BackoffDoublesToCap) {
  EXPECT_EQ(ndi::backoff_delay(0), 1000ms);
  EXPECT_EQ(ndi::backoff_delay(1), 2000ms);
  EXPECT_EQ(ndi::backoff_delay(4), 16000ms);
  EXPECT_EQ(ndi::backoff_delay(5), 30000ms);
  EXPECT_EQ(ndi::backoff_delay(100), 30000ms);
  EXPECT_EQ(ndi::backoff_delay(3, 5s), 5000ms);
}

TEST(PlankNdi, QuotesWindowsArguments) {
  EXPECT_EQ(ndi::quote_windows_arg("abc"), "abc");
  EXPECT_EQ(ndi::quote_windows_arg(""), "\"\"");
  EXPECT_EQ(ndi::quote_windows_arg("a b"), "\"a b\"");
  EXPECT_EQ(ndi::quote_windows_arg("a\"b"), "\"a\\\"b\"");
  EXPECT_EQ(ndi::quote_windows_arg("C:\\dir with space\\"), "\"C:\\dir with space\\\\\"");
}

TEST(PlankNdi, HelperArgsRoundTrip) {
  ndi::helper_options options;
  options.fps = 24;
  options.scope = ndi::scope_e::all;
  options.name = "Colour \"Review\"";
  options.groups = "review,edit";

  const auto args = ndi::build_helper_args(options);
  const auto parsed = ndi::parse_helper_args(args);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->fps, 24);
  EXPECT_EQ(parsed->scope, ndi::scope_e::all);
  EXPECT_EQ(parsed->name, options.name);
  EXPECT_EQ(parsed->groups, "review,edit");
}

TEST(PlankNdi, HelperArgsDefaultsAndErrors) {
  const auto defaults = ndi::parse_helper_args({});
  ASSERT_TRUE(defaults.has_value());
  EXPECT_EQ(defaults->fps, 30);
  EXPECT_EQ(defaults->scope, ndi::scope_e::primary);

  EXPECT_FALSE(ndi::parse_helper_args({"--fps"}).has_value());
  EXPECT_FALSE(ndi::parse_helper_args({"--fps", "abc"}).has_value());
  EXPECT_FALSE(ndi::parse_helper_args({"--outputs", "some"}).has_value());
  EXPECT_FALSE(ndi::parse_helper_args({"--bogus", "1"}).has_value());
  EXPECT_EQ(ndi::parse_helper_args({"--fps", "500"})->fps, 60);

  // Empty name and groups are not passed at all.
  EXPECT_EQ(ndi::build_helper_args(ndi::helper_options {}).size(), 4u);
}

TEST(PlankNdi, HelperCommandLineIsQuoted) {
  ndi::helper_options options;
  options.name = "My Screen";
  EXPECT_EQ(ndi::build_helper_command_line("C:\\Program Files\\PLANK\\tools\\plank-ndi.exe", options),
            "\"C:\\Program Files\\PLANK\\tools\\plank-ndi.exe\" --fps 30 --outputs primary --name \"My Screen\"");
}
