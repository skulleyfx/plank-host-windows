/**
 * @file tests/unit/test_plank_shared_screen_messages.cpp
 * @brief Tests the PLANK shared screen event wire format.
 */

#include "src/plank_shared_screen_messages.h"

#include <cstdint>
#include <string>

#include "../tests_common.h"

namespace messages = plank::shared_screen::messages;

TEST(PlankSharedScreenMessages, EncodesJoinRequest) {
  const auto json = nlohmann::json::parse(messages::join_request(7, "SKULLEYFX\\casey"));
  EXPECT_EQ(json["t"], "join_request");
  EXPECT_EQ(json["id"], 7);
  EXPECT_EQ(json["account"], "SKULLEYFX\\casey");
}

TEST(PlankSharedScreenMessages, EncodesCancelControlRequestAndState) {
  EXPECT_EQ(nlohmann::json::parse(messages::request_cancel(3, "join"))["t"], "request_cancel");
  EXPECT_EQ(nlohmann::json::parse(messages::request_cancel(3, "control"))["kind"], "control");
  EXPECT_EQ(nlohmann::json::parse(messages::request_cancel(3, "join"))["id"], 3);
  const auto request = nlohmann::json::parse(messages::control_request(9, "alan"));
  EXPECT_EQ(request["t"], "control_request");
  EXPECT_EQ(request["id"], 9);
  EXPECT_EQ(request["account"], "alan");
  const auto state = nlohmann::json::parse(messages::control_state(true, "granted"));
  EXPECT_EQ(state["t"], "control_state");
  EXPECT_EQ(state["has_control"], true);
  EXPECT_EQ(state["reason"], "granted");
}

TEST(PlankSharedScreenMessages, EncodesWatchersIncludingEmptyList) {
  const auto empty = nlohmann::json::parse(messages::watchers({}));
  EXPECT_EQ(empty["t"], "watchers");
  ASSERT_TRUE(empty["viewers"].is_array());
  EXPECT_TRUE(empty["viewers"].empty());

  const auto two = nlohmann::json::parse(messages::watchers({{1, "casey", false}, {2, "chris", true}}));
  ASSERT_EQ(two["viewers"].size(), 2u);
  EXPECT_EQ(two["viewers"][0]["id"], 1);
  EXPECT_EQ(two["viewers"][0]["account"], "casey");
  EXPECT_EQ(two["viewers"][0]["control"], false);
  EXPECT_EQ(two["viewers"][1]["control"], true);
}

TEST(PlankSharedScreenMessages, InvalidUtf8AccountStillEncodes) {
  const std::string bad {"bad\xff"};
  EXPECT_TRUE(nlohmann::json::parse(messages::join_request(1, bad)).is_object());
}

TEST(PlankSharedScreenMessages, ParsesAnswers) {
  const auto join = messages::parse_client(R"({"t":"join_answer","id":4,"allow":true})");
  ASSERT_TRUE(join);
  EXPECT_EQ(join->type, messages::client_type_e::join_answer);
  EXPECT_EQ(join->id, 4u);
  EXPECT_TRUE(join->allow);

  const auto control = messages::parse_client(R"({"t":"control_answer","id":5,"allow":false})");
  ASSERT_TRUE(control);
  EXPECT_EQ(control->type, messages::client_type_e::control_answer);
  EXPECT_EQ(control->id, 5u);
  EXPECT_FALSE(control->allow);
}

TEST(PlankSharedScreenMessages, ParsesSimpleMessages) {
  const auto kick = messages::parse_client(R"({"t":"kick","id":12})");
  ASSERT_TRUE(kick);
  EXPECT_EQ(kick->type, messages::client_type_e::kick);
  EXPECT_EQ(kick->id, 12u);
  EXPECT_EQ(messages::parse_client(R"({"t":"take_back"})")->type, messages::client_type_e::take_back);
  EXPECT_EQ(messages::parse_client(R"({"t":"control_request"})")->type, messages::client_type_e::control_request);
  EXPECT_EQ(messages::parse_client(R"({"t":"control_release"})")->type, messages::client_type_e::control_release);
}

TEST(PlankSharedScreenMessages, RejectsMalformedMessages) {
  EXPECT_FALSE(messages::parse_client(""));
  EXPECT_FALSE(messages::parse_client("not json"));
  EXPECT_FALSE(messages::parse_client("[1,2]"));
  EXPECT_FALSE(messages::parse_client(R"({"id":1})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":5})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"something_new"})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":4})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","allow":true})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":0,"allow":true})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":-1,"allow":true})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":4294967296,"allow":true})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":"4","allow":true})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"join_answer","id":4,"allow":1})"));
  EXPECT_FALSE(messages::parse_client(R"({"t":"kick"})"));
  EXPECT_FALSE(messages::parse_client(std::string(messages::max_message_bytes + 1, ' ')));
}

TEST(PlankSharedScreenMessages, RolesMaySendOnlyTheirOwnMessages) {
  using type = messages::client_type_e;
  for (const auto controller_only : {type::join_answer, type::kick, type::control_answer, type::take_back}) {
    EXPECT_TRUE(messages::allowed_from(controller_only, false));
    EXPECT_FALSE(messages::allowed_from(controller_only, true));
  }
  for (const auto viewer_only : {type::control_request, type::control_release}) {
    EXPECT_TRUE(messages::allowed_from(viewer_only, true));
    EXPECT_FALSE(messages::allowed_from(viewer_only, false));
  }
}

TEST(PlankSharedScreenMessages, OnlyKeyAndButtonPressesReclaimControl) {
  constexpr std::uint8_t keyboard = 5;
  constexpr std::uint8_t button = 2;
  constexpr std::uint8_t motion = 1;
  constexpr std::uint8_t press = 1;
  constexpr std::uint8_t release = 0;
  const std::uint8_t button_press[] {1, press};
  const std::uint8_t button_release[] {1, release};
  const std::uint8_t key_press[] {0, 0x41, press, 0, 0};
  const std::uint8_t key_release[] {0, 0x41, release, 0, 0};
  const std::uint8_t move[] {0, 1, 0, 2, 0, 3, 0, 4};
  EXPECT_TRUE(messages::owner_input_reclaims(button, button_press, sizeof(button_press), keyboard, button, press));
  EXPECT_FALSE(messages::owner_input_reclaims(button, button_release, sizeof(button_release), keyboard, button, press));
  EXPECT_TRUE(messages::owner_input_reclaims(keyboard, key_press, sizeof(key_press), keyboard, button, press));
  EXPECT_FALSE(messages::owner_input_reclaims(keyboard, key_release, sizeof(key_release), keyboard, button, press));
  EXPECT_FALSE(messages::owner_input_reclaims(motion, move, sizeof(move), keyboard, button, press));
  EXPECT_FALSE(messages::owner_input_reclaims(button, button_press, 1, keyboard, button, press));
  EXPECT_FALSE(messages::owner_input_reclaims(keyboard, key_press, 2, keyboard, button, press));
}
