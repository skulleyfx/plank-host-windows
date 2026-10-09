/**
 * @file tests/unit/test_resume_window.cpp
 * @brief Test src/auth/resume_window.h.
 */
// test includes
#include "../tests_common.h"

// local includes
#include <src/auth/resume_window.h>

using plank::auth::resume_ticket_valid;

namespace {
  constexpr std::int64_t signin = 1'000'000;
  constexpr std::int64_t minute = 60;
  constexpr std::int64_t hour = 3600;
}  // namespace

TEST(ResumeWindowTest, ValidWithinWindowOfLastActivity) {
  EXPECT_TRUE(resume_ticket_valid(signin + 5 * minute, signin, signin, 10, 12));
  EXPECT_TRUE(resume_ticket_valid(signin + 10 * minute, signin, signin, 10, 12));
  EXPECT_FALSE(resume_ticket_valid(signin + 10 * minute + 1, signin, signin, 10, 12));
}

TEST(ResumeWindowTest, WindowSlidesFromLastActivityNotSignin) {
  // Three hours into a session, last activity a minute ago: a drop now resumes.
  const auto activity = signin + 3 * hour;
  EXPECT_TRUE(resume_ticket_valid(activity + minute, signin, activity, 10, 12));
  // Ten minutes after the session ended it no longer does.
  EXPECT_FALSE(resume_ticket_valid(activity + 11 * minute, signin, activity, 10, 12));
}

TEST(ResumeWindowTest, AbsoluteCapCountsFromSignin) {
  const auto activity = signin + 12 * hour - minute;
  EXPECT_TRUE(resume_ticket_valid(activity + minute, signin, activity, 10, 12));
  EXPECT_FALSE(resume_ticket_valid(signin + 12 * hour + 1, signin, signin + 12 * hour, 10, 12));
  // Fresh activity cannot outlive the cap.
  EXPECT_FALSE(resume_ticket_valid(signin + 13 * hour, signin, signin + 13 * hour, 10, 12));
}

TEST(ResumeWindowTest, DisabledWhenWindowOrCapIsNotPositive) {
  EXPECT_FALSE(resume_ticket_valid(signin, signin, signin, 0, 12));
  EXPECT_FALSE(resume_ticket_valid(signin, signin, signin, -1, 12));
  EXPECT_FALSE(resume_ticket_valid(signin, signin, signin, 10, 0));
}
