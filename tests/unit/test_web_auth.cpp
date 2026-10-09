#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <pwd.h>
#include <unistd.h>

#include "src/auth/web_auth.h"

namespace auth = plank::auth;

namespace {
  struct fake_state_t {
    std::uint64_t transaction_id = 0;
    std::string username;
    std::string remote_host;
    std::vector<std::string> responses;
    int destroyed = 0;
  };

  class fake_conversation_t: public auth::conversation_i {
  public:
    explicit fake_conversation_t(std::shared_ptr<fake_state_t> state):
        state_ {std::move(state)} {
    }

    ~fake_conversation_t() override {
      ++state_->destroyed;
    }

    auth::step_t begin(std::uint64_t transaction_id, std::string_view username,
                       std::string_view remote_host) override {
      state_->transaction_id = transaction_id;
      state_->username = username;
      state_->remote_host = remote_host;
      return {
        auth::step_t::state_e::challenge,
        {{1, "Password: "}},
        auth::phase_e::authenticate,
        0,
      };
    }

    auth::step_t respond(std::vector<std::string> responses) override {
      state_->responses = std::move(responses);
      return {
        auth::step_t::state_e::authenticated,
        {},
        auth::phase_e::authenticated,
        0,
      };
    }

  private:
    std::shared_ptr<fake_state_t> state_;
  };
}  // namespace

TEST(WebAuthManager, BindsConversationAndTokenToRemotePeer) {
  auto state = std::make_shared<fake_state_t>();
  std::vector<std::string> random_values {"conversation", "token"};
  auth::web_auth_manager_t manager {
    [state]() { return std::make_unique<fake_conversation_t>(state); },
    [&random_values](std::size_t) {
      std::string value = random_values.front();
      random_values.erase(random_values.begin());
      return value;
    },
  };

  const auto challenge = manager.begin("test-user", "198.51.100.250");
  ASSERT_EQ(challenge.state, auth::step_t::state_e::challenge);
  EXPECT_EQ(challenge.conversation_id, "conversation");
  ASSERT_EQ(challenge.prompts.size(), 1);
  EXPECT_EQ(challenge.prompts.front().text, "Password: ");
  EXPECT_NE(state->transaction_id, 0);
  EXPECT_EQ(state->username, "test-user");
  EXPECT_EQ(state->remote_host, "198.51.100.250");

  EXPECT_EQ(manager.respond("conversation", "198.51.100.99", {"wrong-peer"}).state,
            auth::step_t::state_e::denied);
  const auto success = manager.respond("conversation", "198.51.100.250", {"secret"});
  EXPECT_EQ(success.state, auth::step_t::state_e::authenticated);
  EXPECT_EQ(success.session_token, "token");
  ASSERT_EQ(state->responses.size(), 1);
  EXPECT_EQ(state->responses.front(), "secret");
  EXPECT_TRUE(manager.authorize("token", "198.51.100.250"));
  EXPECT_FALSE(manager.authorize("token", "198.51.100.99"));
  ASSERT_TRUE(manager.identity("token", "198.51.100.250"));
  EXPECT_EQ(*manager.identity("token", "198.51.100.250"), "test-user");
  EXPECT_FALSE(manager.identity("token", "198.51.100.99"));
  EXPECT_FALSE(manager.claim("token", "198.51.100.99"));
  auto session = manager.claim("token", "198.51.100.250");
  ASSERT_TRUE(session);
  EXPECT_EQ(manager.claim("token", "198.51.100.250"), session);
  EXPECT_EQ(*manager.identity("token", "198.51.100.250"), "test-user");
  manager.cancel("token");
  EXPECT_FALSE(manager.authorize("token", "198.51.100.250"));
  EXPECT_EQ(state->destroyed, 0);
  session.reset();
  EXPECT_EQ(state->destroyed, 1);
}

TEST(WebAuthManager, CannotReclaimSessionAfterTheLastStreamEnds) {
  auto state = std::make_shared<fake_state_t>();
  std::vector<std::string> random_values {"conversation", "token"};
  auth::web_auth_manager_t manager {
    [state]() { return std::make_unique<fake_conversation_t>(state); },
    [&random_values](std::size_t) {
      auto value = random_values.front();
      random_values.erase(random_values.begin());
      return value;
    },
  };

  ASSERT_EQ(manager.begin("test-user", "client").state,
            auth::step_t::state_e::challenge);
  ASSERT_EQ(manager.respond("conversation", "client", {"secret"}).state,
            auth::step_t::state_e::authenticated);
  {
    auto session = manager.claim("token", "client");
    ASSERT_TRUE(session);
  }
  EXPECT_EQ(state->destroyed, 1);
  EXPECT_FALSE(manager.authorize("token", "client"));
  EXPECT_FALSE(manager.claim("token", "client"));
}

TEST(WebAuthManager, ExpiresPendingConversation) {
  auto state = std::make_shared<fake_state_t>();
  auto now = auth::web_auth_manager_t::clock_t::time_point {};
  auth::web_auth_manager_t manager {
    [state]() { return std::make_unique<fake_conversation_t>(state); },
    [](std::size_t) { return "conversation"; },
    [&now]() { return now; },
    std::chrono::seconds {2},
    std::chrono::seconds {3},
  };
  ASSERT_EQ(manager.begin("test-user", "client").state,
            auth::step_t::state_e::challenge);
  now += std::chrono::seconds {3};
  manager.expire();
  EXPECT_EQ(state->destroyed, 1);
  EXPECT_EQ(manager.respond("conversation", "client", {"secret"}).state,
            auth::step_t::state_e::denied);
}

TEST(WebAuthManager, GeneratesSecureIdentifiersWithinBounds) {
  EXPECT_TRUE(auth::secure_random_hex(0).empty());
  EXPECT_TRUE(auth::secure_random_hex(65).empty());
  const auto value = auth::secure_random_hex(32);
  EXPECT_EQ(value.size(), 64);
  EXPECT_TRUE(value.find_first_not_of("0123456789abcdef") == std::string::npos);
}

TEST(WebAuthManager, ResolvesOnlyValidOperatingSystemAccounts) {
  const passwd *account = getpwuid(geteuid());
  ASSERT_NE(account, nullptr);
  ASSERT_NE(account->pw_name, nullptr);
  EXPECT_EQ(auth::account_uid(account->pw_name), account->pw_uid);
  EXPECT_FALSE(auth::account_uid("__plank_missing_account__"));
  EXPECT_FALSE(auth::account_uid(""));

  std::string embedded_nul {account->pw_name};
  embedded_nul.push_back('\0');
  embedded_nul.append("another-account");
  EXPECT_FALSE(auth::account_uid(embedded_nul));
}

namespace {
  /**
   * @brief Conversation whose response blocks until released, like a DUO wait.
   */
  class blocking_conversation_t: public auth::conversation_i {
  public:
    struct gate_t {
      std::mutex mutex;
      std::condition_variable changed;
      bool entered = false;
      bool released = false;
      int responses = 0;
    };

    explicit blocking_conversation_t(std::shared_ptr<gate_t> gate):
        gate_ {std::move(gate)} {
    }

    auth::step_t begin(std::uint64_t, std::string_view, std::string_view) override {
      return {auth::step_t::state_e::challenge, {{4, "Waiting"}}, auth::phase_e::authenticate, 0};
    }

    auth::step_t respond(std::vector<std::string>) override {
      std::unique_lock lock {gate_->mutex};
      ++gate_->responses;
      gate_->entered = true;
      gate_->changed.notify_all();
      gate_->changed.wait(lock, [this] {
        return gate_->released;
      });
      return {auth::step_t::state_e::authenticated, {}, auth::phase_e::authenticated, 0};
    }

  private:
    std::shared_ptr<gate_t> gate_;
  };
}  // namespace

TEST(WebAuthManager, WaitingRoundOwnsItsConversationWithoutBlockingOthers) {
  auto gate = std::make_shared<blocking_conversation_t::gate_t>();
  int next = 0;
  auth::web_auth_manager_t manager {
    [gate]() { return std::make_unique<blocking_conversation_t>(gate); },
    [&next](std::size_t) { return "id-" + std::to_string(next++); },
  };
  const auto challenge = manager.begin("test-user", "client");
  ASSERT_EQ(challenge.state, auth::step_t::state_e::challenge);

  auth::web_auth_step_t waited;
  std::thread round([&] {
    waited = manager.respond(challenge.conversation_id, "client", {""});
  });
  {
    std::unique_lock lock {gate->mutex};
    ASSERT_TRUE(gate->changed.wait_for(lock, std::chrono::seconds {5}, [&] {
      return gate->entered;
    }));
  }

  // Other requests proceed while the round waits: the manager mutex is free.
  EXPECT_FALSE(manager.authorize("unknown-token", "client"));
  // A replayed or concurrent response for the waiting conversation is refused
  // and never reaches the conversation.
  EXPECT_EQ(manager.respond(challenge.conversation_id, "client", {""}).state,
            auth::step_t::state_e::denied);

  {
    std::lock_guard lock {gate->mutex};
    gate->released = true;
  }
  gate->changed.notify_all();
  round.join();

  EXPECT_EQ(waited.state, auth::step_t::state_e::authenticated);
  EXPECT_FALSE(waited.session_token.empty());
  EXPECT_TRUE(manager.authorize(waited.session_token, "client"));
  EXPECT_EQ(gate->responses, 1);
  // The conversation became a token, so its ID cannot complete a second sign-in.
  EXPECT_EQ(manager.respond(challenge.conversation_id, "client", {""}).state,
            auth::step_t::state_e::denied);
}

TEST(WebAuthManager, WaitingRoundsCountTowardTheConversationLimit) {
  auto gate = std::make_shared<blocking_conversation_t::gate_t>();
  int next = 0;
  auth::web_auth_manager_t manager {
    [gate]() { return std::make_unique<blocking_conversation_t>(gate); },
    [&next](std::size_t) { return "id-" + std::to_string(next++); },
  };
  std::vector<std::string> ids;
  for (int i = 0; i < 32; ++i) {
    const auto step = manager.begin("test-user", "client");
    ASSERT_EQ(step.state, auth::step_t::state_e::challenge);
    ids.push_back(step.conversation_id);
  }
  EXPECT_EQ(manager.begin("test-user", "client").state, auth::step_t::state_e::denied);

  std::thread round([&] {
    manager.respond(ids.front(), "client", {""});
  });
  {
    std::unique_lock lock {gate->mutex};
    ASSERT_TRUE(gate->changed.wait_for(lock, std::chrono::seconds {5}, [&] {
      return gate->entered;
    }));
  }
  // The waiting conversation is out of the map but still counts.
  EXPECT_EQ(manager.begin("test-user", "client").state, auth::step_t::state_e::denied);
  {
    std::lock_guard lock {gate->mutex};
    gate->released = true;
  }
  gate->changed.notify_all();
  round.join();
}
