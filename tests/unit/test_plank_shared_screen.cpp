/**
 * @file tests/unit/test_plank_shared_screen.cpp
 * @brief Tests PLANK shared screen roles, admission, consent and the control token.
 */

#include "src/plank_shared_screen.h"

#include <chrono>
#include <string>
#include <vector>

#include "../tests_common.h"

namespace {
  namespace ss = plank::shared_screen;
  using token_t = ss::control_token_t;
  using result_e = token_t::result_e;

  ss::admission_input_t good_input() {
    ss::admission_input_t in;
    in.enabled = true;
    in.protocol_matches = true;
    in.client_features = ss::feature_shared_screen;
    in.controller_running = true;
    in.viewer_count = 0;
    in.max_viewers = 2;
    in.launch_matches = true;
    return in;
  }

  ss::stream_shape_t base_shape() {
    ss::stream_shape_t s;
    s.width = 1920;
    s.height = 1080;
    s.fps = 60;
    s.video_format = 1;
    s.dynamic_range = 0;
    s.chroma = 0;
    s.encoder_csc_mode = 0;
    s.audio_channels = 2;
    s.audio_packet_duration = 5;
    s.high_quality_audio = false;
    return s;
  }
}  // namespace

TEST(PlankSharedScreen, ParsesRole) {
  EXPECT_EQ(ss::parse_role(""), ss::role_e::controller);
  EXPECT_EQ(ss::parse_role("controller"), ss::role_e::controller);
  EXPECT_EQ(ss::parse_role("viewer"), ss::role_e::viewer);
  EXPECT_FALSE(ss::parse_role("garbage").has_value());
  EXPECT_FALSE(ss::parse_role("Viewer").has_value());
  EXPECT_FALSE(ss::parse_role("CONTROLLER").has_value());
  EXPECT_FALSE(ss::parse_role(" viewer").has_value());
}

TEST(PlankSharedScreen, NamesRole) {
  EXPECT_EQ(ss::role_name(ss::role_e::controller), "controller");
  EXPECT_EQ(ss::role_name(ss::role_e::viewer), "viewer");
}

TEST(PlankSharedScreen, ShapeMatchIsEmpty) {
  EXPECT_TRUE(ss::shape_mismatch(base_shape(), base_shape()).empty());
}

TEST(PlankSharedScreen, ShapeMismatchNamesField) {
  const auto c = base_shape();

  auto v = c;
  v.width = 1280;
  EXPECT_EQ(ss::shape_mismatch(c, v), "resolution");
  v = c;
  v.height = 720;
  EXPECT_EQ(ss::shape_mismatch(c, v), "resolution");

  v = c;
  v.fps = 30;
  EXPECT_EQ(ss::shape_mismatch(c, v), "frame rate");

  v = c;
  v.video_format = 0;
  EXPECT_EQ(ss::shape_mismatch(c, v), "video format");
  v = c;
  v.dynamic_range = 1;
  EXPECT_EQ(ss::shape_mismatch(c, v), "video format");
  v = c;
  v.chroma = 1;
  EXPECT_EQ(ss::shape_mismatch(c, v), "video format");
  v = c;
  v.encoder_csc_mode = 3;
  EXPECT_EQ(ss::shape_mismatch(c, v), "video format");

  v = c;
  v.audio_channels = 6;
  EXPECT_EQ(ss::shape_mismatch(c, v), "audio format");
  v = c;
  v.audio_packet_duration = 10;
  EXPECT_EQ(ss::shape_mismatch(c, v), "audio format");
  v = c;
  v.high_quality_audio = true;
  EXPECT_EQ(ss::shape_mismatch(c, v), "audio format");
}

TEST(PlankSharedScreen, ShapeMismatchReportsFirstInOrder) {
  const auto c = base_shape();
  auto v = c;
  v.high_quality_audio = true;
  v.chroma = 1;
  EXPECT_EQ(ss::shape_mismatch(c, v), "video format");
  v.fps = 30;
  EXPECT_EQ(ss::shape_mismatch(c, v), "frame rate");
  v.width = 640;
  EXPECT_EQ(ss::shape_mismatch(c, v), "resolution");
}

TEST(PlankSharedScreen, AdmitsViewerWhenAllGood) {
  const auto a = ss::admit_viewer(good_input());
  EXPECT_EQ(a.status, 200);
  EXPECT_TRUE(a.admitted());
  EXPECT_TRUE(a.message.empty());
}

TEST(PlankSharedScreen, AdmissionRefusals) {
  auto in = good_input();
  in.enabled = false;
  auto a = ss::admit_viewer(in);
  EXPECT_EQ(a.status, 403);
  EXPECT_FALSE(a.admitted());
  EXPECT_FALSE(a.message.empty());

  in = good_input();
  in.protocol_matches = false;
  a = ss::admit_viewer(in);
  EXPECT_EQ(a.status, 400);
  EXPECT_FALSE(a.admitted());

  in = good_input();
  in.client_features = 0;
  EXPECT_EQ(ss::admit_viewer(in).status, 400);
  in.client_features = 0x2000000;
  EXPECT_EQ(ss::admit_viewer(in).status, 400);
  in.client_features = 0xFFFFFFFFu;
  EXPECT_EQ(ss::admit_viewer(in).status, 200);

  in = good_input();
  in.controller_running = false;
  EXPECT_EQ(ss::admit_viewer(in).status, 409);

  in = good_input();
  in.viewer_count = in.max_viewers;
  EXPECT_EQ(ss::admit_viewer(in).status, 409);
  in.viewer_count = in.max_viewers + 3;
  EXPECT_EQ(ss::admit_viewer(in).status, 409);

  in = good_input();
  in.viewer_count = in.max_viewers - 1;
  EXPECT_TRUE(ss::admit_viewer(in).admitted());

  in = good_input();
  in.launch_matches = false;
  EXPECT_EQ(ss::admit_viewer(in).status, 409);
}

TEST(PlankSharedScreen, AdmissionMessagesAreDistinct) {
  auto in = good_input();
  in.controller_running = false;
  const auto none = ss::admit_viewer(in).message;
  in = good_input();
  in.viewer_count = in.max_viewers;
  const auto full = ss::admit_viewer(in).message;
  in = good_input();
  in.launch_matches = false;
  const auto differ = ss::admit_viewer(in).message;
  EXPECT_NE(none, full);
  EXPECT_NE(none, differ);
  EXPECT_NE(full, differ);
}

TEST(PlankSharedScreen, AdmissionZeroMaxViewersRefuses) {
  auto in = good_input();
  in.max_viewers = 0;
  EXPECT_EQ(ss::admit_viewer(in).status, 409);
}

TEST(PlankSharedScreen, AdmissionCheckPrecedence) {
  // Everything wrong: disabled wins.
  ss::admission_input_t in;
  EXPECT_EQ(ss::admit_viewer(in).status, 403);

  // Enabled, protocol/feature wrong beats the 409 reasons.
  in.enabled = true;
  EXPECT_EQ(ss::admit_viewer(in).status, 400);

  // Valid request, no controller beats full and launch mismatch.
  in.protocol_matches = true;
  in.client_features = ss::feature_shared_screen;
  in.viewer_count = 5;
  in.max_viewers = 1;
  auto a = ss::admit_viewer(in);
  EXPECT_EQ(a.status, 409);
  EXPECT_EQ(a.message, ss::admit_viewer([&] {
                          auto x = good_input();
                          x.controller_running = false;
                          return x;
                        }()).message);

  // Controller running: full beats launch mismatch.
  in.controller_running = true;
  a = ss::admit_viewer(in);
  EXPECT_EQ(a.status, 409);
  auto full_in = good_input();
  full_in.viewer_count = full_in.max_viewers;
  EXPECT_EQ(a.message, ss::admit_viewer(full_in).message);

  // Room available: launch mismatch is the last check.
  in.viewer_count = 0;
  in.max_viewers = 2;
  a = ss::admit_viewer(in);
  EXPECT_EQ(a.status, 409);
  auto mismatch_in = good_input();
  mismatch_in.launch_matches = false;
  EXPECT_EQ(a.message, ss::admit_viewer(mismatch_in).message);

  in.launch_matches = true;
  EXPECT_TRUE(ss::admit_viewer(in).admitted());
}

TEST(PlankSharedScreen, ConsentDecisions) {
  using ss::consent_e;
  // enabled=false always refuses.
  for (int bits = 0; bits < 8; ++bits) {
    EXPECT_EQ(ss::decide_consent(false, bits & 1, bits & 2, bits & 4), consent_e::refuse) << bits;
  }
  // same_account beats admin and approval availability.
  for (int bits = 0; bits < 4; ++bits) {
    EXPECT_EQ(ss::decide_consent(true, true, bits & 1, bits & 2), consent_e::admit) << bits;
  }
  // admin override without same account, regardless of approval UI.
  EXPECT_EQ(ss::decide_consent(true, false, true, false), consent_e::admit_admin_silently);
  EXPECT_EQ(ss::decide_consent(true, false, true, true), consent_e::admit_admin_silently);
  // stranger
  EXPECT_EQ(ss::decide_consent(true, false, false, true), consent_e::ask_owner);
  EXPECT_EQ(ss::decide_consent(true, false, false, false), consent_e::refuse);
}

TEST(PlankSharedScreen, AdminAuditLineText) {
  EXPECT_EQ(ss::admin_audit_line("chris", "observe", true), "PLANK admin observe: chris started");
  EXPECT_EQ(ss::admin_audit_line("chris", "observe", false), "PLANK admin observe: chris ended");
  EXPECT_EQ(ss::admin_audit_line("SKULLEY\\casey", "takeover", true), "PLANK admin takeover: SKULLEY\\casey started");
  EXPECT_EQ(ss::admin_audit_line("SKULLEY\\casey", "takeover", false), "PLANK admin takeover: SKULLEY\\casey ended");
}

TEST(PlankSharedScreen, KeyframeRequestRateLimit) {
  using clock = std::chrono::steady_clock;
  const auto interval = std::chrono::milliseconds(500);
  const auto t0 = clock::now() + std::chrono::hours(1);

  // Never requested: always allowed, even at "now" == epoch.
  EXPECT_TRUE(ss::keyframe_request_allowed(clock::time_point {}, t0, interval));
  EXPECT_TRUE(ss::keyframe_request_allowed(clock::time_point {}, clock::time_point {}, interval));

  EXPECT_FALSE(ss::keyframe_request_allowed(t0, t0, interval));
  EXPECT_FALSE(ss::keyframe_request_allowed(t0, t0 + std::chrono::milliseconds(499), interval));
  EXPECT_TRUE(ss::keyframe_request_allowed(t0, t0 + interval, interval));
  EXPECT_TRUE(ss::keyframe_request_allowed(t0, t0 + std::chrono::milliseconds(501), interval));
  EXPECT_TRUE(ss::keyframe_request_allowed(t0, t0 + std::chrono::seconds(10), interval));
}

TEST(PlankSharedScreen, TokenInitialState) {
  token_t t {1};
  EXPECT_EQ(t.owner(), 1u);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_TRUE(t.accepts_input(1));
  EXPECT_FALSE(t.accepts_input(2));
  EXPECT_FALSE(t.accepts_input(0));
}

TEST(PlankSharedScreen, TokenRequestRules) {
  token_t t {1};
  EXPECT_EQ(t.request(1), result_e::not_allowed);  // owner
  EXPECT_EQ(t.request(0), result_e::not_allowed);
  EXPECT_EQ(t.pending(), 0u);

  EXPECT_EQ(t.request(2), result_e::ok);
  EXPECT_EQ(t.pending(), 2u);
  EXPECT_EQ(t.request(3), result_e::busy);
  EXPECT_EQ(t.pending(), 2u);
  EXPECT_EQ(t.request(2), result_e::ok);  // same viewer re-request
  EXPECT_EQ(t.pending(), 2u);
  EXPECT_FALSE(t.accepts_input(2));  // not until granted
  EXPECT_TRUE(t.accepts_input(1));
}

TEST(PlankSharedScreen, TokenHolderCannotRequest) {
  token_t t {1};
  t.request(2);
  t.grant(1);
  EXPECT_EQ(t.holder(), 2u);
  EXPECT_EQ(t.request(2), result_e::not_allowed);  // already holds
  EXPECT_EQ(t.request(1), result_e::not_allowed);  // owner
}

TEST(PlankSharedScreen, TokenGrant) {
  token_t t {1};
  EXPECT_EQ(t.grant(1), result_e::nothing_pending);
  t.request(2);
  EXPECT_EQ(t.grant(2), result_e::not_allowed);  // non-owner
  EXPECT_EQ(t.grant(3), result_e::not_allowed);
  EXPECT_EQ(t.grant(0), result_e::not_allowed);
  EXPECT_EQ(t.pending(), 2u);
  EXPECT_EQ(t.holder(), 1u);

  EXPECT_EQ(t.grant(1), result_e::ok);
  EXPECT_EQ(t.holder(), 2u);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_TRUE(t.accepts_input(2));
  EXPECT_FALSE(t.accepts_input(1));
}

TEST(PlankSharedScreen, TokenDeny) {
  token_t t {1};
  EXPECT_EQ(t.deny(1), result_e::nothing_pending);
  t.request(2);
  EXPECT_EQ(t.deny(2), result_e::not_allowed);
  EXPECT_EQ(t.deny(0), result_e::not_allowed);
  EXPECT_EQ(t.pending(), 2u);
  EXPECT_EQ(t.deny(1), result_e::ok);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_TRUE(t.accepts_input(1));
  // Denied viewer may ask again.
  EXPECT_EQ(t.request(2), result_e::ok);
}

TEST(PlankSharedScreen, TokenTakeBack) {
  token_t t {1};
  // Owner take_back with nothing to take back is still ok.
  EXPECT_EQ(t.take_back(1), result_e::ok);
  EXPECT_EQ(t.holder(), 1u);

  t.request(2);
  t.grant(1);
  t.request(3);
  EXPECT_EQ(t.pending(), 3u);
  EXPECT_EQ(t.take_back(2), result_e::not_allowed);  // holder viewer
  EXPECT_EQ(t.take_back(3), result_e::not_allowed);
  EXPECT_EQ(t.take_back(0), result_e::not_allowed);
  EXPECT_EQ(t.holder(), 2u);

  EXPECT_EQ(t.take_back(1), result_e::ok);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_TRUE(t.accepts_input(1));
  EXPECT_FALSE(t.accepts_input(2));
}

TEST(PlankSharedScreen, TokenHolderLeavingReturnsControlToOwner) {
  token_t t {1};
  t.request(2);
  t.grant(1);
  t.leave(2);
  EXPECT_EQ(t.owner(), 1u);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_TRUE(t.accepts_input(1));
  EXPECT_FALSE(t.accepts_input(2));
}

TEST(PlankSharedScreen, TokenPendingRequesterLeavingClearsPending) {
  token_t t {1};
  t.request(2);
  t.leave(2);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_EQ(t.grant(1), result_e::nothing_pending);
  // Another viewer can now ask.
  EXPECT_EQ(t.request(3), result_e::ok);
}

TEST(PlankSharedScreen, TokenUnrelatedLeaveChangesNothing) {
  token_t t {1};
  t.request(2);
  t.leave(5);
  t.leave(0);
  EXPECT_EQ(t.owner(), 1u);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_EQ(t.pending(), 2u);
}

TEST(PlankSharedScreen, TokenOwnerLeavingEndsShare) {
  token_t t {1};
  t.request(2);
  t.leave(1);
  EXPECT_EQ(t.owner(), 0u);
  EXPECT_EQ(t.holder(), 0u);
  EXPECT_EQ(t.pending(), 0u);
  EXPECT_FALSE(t.accepts_input(0));
  EXPECT_FALSE(t.accepts_input(1));
  EXPECT_FALSE(t.accepts_input(2));
  EXPECT_EQ(t.request(2), result_e::not_allowed);
  EXPECT_EQ(t.grant(0), result_e::not_allowed);
  EXPECT_EQ(t.take_back(0), result_e::not_allowed);
}

TEST(PlankSharedScreen, TokenOwnerLeavingWhileViewerHolds) {
  token_t t {1};
  t.request(2);
  t.grant(1);
  t.leave(1);
  EXPECT_EQ(t.owner(), 0u);
  EXPECT_EQ(t.holder(), 0u);
  EXPECT_FALSE(t.accepts_input(2));
}

TEST(PlankSharedScreen, TokenAdminTakeover) {
  token_t t {1};
  t.request(5);
  EXPECT_EQ(t.admin_takeover(0), result_e::not_allowed);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_EQ(t.pending(), 5u);

  // Another admin's takeover does not clear someone else's pending request.
  EXPECT_EQ(t.admin_takeover(6), result_e::ok);
  EXPECT_EQ(t.holder(), 6u);
  EXPECT_EQ(t.pending(), 5u);
  EXPECT_TRUE(t.accepts_input(6));
  EXPECT_FALSE(t.accepts_input(1));

  // Taking over with your own pending request clears it.
  EXPECT_EQ(t.admin_takeover(5), result_e::ok);
  EXPECT_EQ(t.holder(), 5u);
  EXPECT_EQ(t.pending(), 0u);
}

TEST(PlankSharedScreen, TokenOwnerTakesBackAfterAdminTakeover) {
  token_t t {1};
  EXPECT_EQ(t.admin_takeover(9), result_e::ok);
  EXPECT_FALSE(t.accepts_input(1));
  EXPECT_EQ(t.take_back(1), result_e::ok);
  EXPECT_EQ(t.holder(), 1u);
  EXPECT_TRUE(t.accepts_input(1));
  EXPECT_FALSE(t.accepts_input(9));
}

TEST(PlankSharedScreen, HeldInputReleasesEverythingStillDown) {
  using held = plank::shared_screen::held_input_t;
  held input;
  const std::uint8_t key_a_down[] {0x00, 0x41, held::press, 0x02, 0x07};
  const std::uint8_t key_b_down[] {0x00, 0x42, held::press, 0x00, 0x00};
  const std::uint8_t key_b_up[] {0x00, 0x42, held::release, 0x00, 0x00};
  const std::uint8_t left_down[] {1, held::press};
  const std::uint8_t right_down[] {3, held::press};
  const std::uint8_t right_up[] {3, held::release};
  input.record(held::keyboard_type, key_a_down, sizeof(key_a_down));
  input.record(held::keyboard_type, key_b_down, sizeof(key_b_down));
  input.record(held::keyboard_type, key_b_up, sizeof(key_b_up));
  input.record(held::mouse_button_type, left_down, sizeof(left_down));
  input.record(held::mouse_button_type, right_down, sizeof(right_down));
  input.record(held::mouse_button_type, right_up, sizeof(right_up));
  EXPECT_FALSE(input.empty());

  const auto releases = input.take_releases();
  ASSERT_EQ(releases.size(), 2u);
  EXPECT_EQ(releases[0].type, held::keyboard_type);
  EXPECT_EQ(releases[0].payload, (std::vector<std::uint8_t> {0x00, 0x41, held::release, 0x00, 0x07}));
  EXPECT_EQ(releases[1].type, held::mouse_button_type);
  EXPECT_EQ(releases[1].payload, (std::vector<std::uint8_t> {1, held::release}));
  EXPECT_TRUE(input.empty());
  EXPECT_TRUE(input.take_releases().empty());
}

TEST(PlankSharedScreen, HeldInputIgnoresOtherTypesAndShortPayloads) {
  using held = plank::shared_screen::held_input_t;
  held input;
  const std::uint8_t motion[] {0, 1, 0, 2, 0, 3, 0, 4};
  const std::uint8_t short_key[] {0x00, 0x41, held::press};
  const std::uint8_t short_button[] {1};
  input.record(1, motion, sizeof(motion));
  input.record(held::keyboard_type, short_key, sizeof(short_key));
  input.record(held::mouse_button_type, short_button, sizeof(short_button));
  EXPECT_TRUE(input.empty());
}

TEST(PlankSharedScreen, KeyframeBudgetDropsAViewerThatKeepsAsking) {
  plank::shared_screen::keyframe_budget_t budget;
  const auto start = std::chrono::steady_clock::now();
  for (int request = 0; request < 10; ++request) {
    EXPECT_TRUE(budget.allow(start + std::chrono::seconds {request}, std::chrono::seconds {20}, 10));
  }
  EXPECT_FALSE(budget.allow(start + std::chrono::seconds {11}, std::chrono::seconds {20}, 10));
  // A new window starts afresh.
  EXPECT_TRUE(budget.allow(start + std::chrono::seconds {40}, std::chrono::seconds {20}, 10));
}
