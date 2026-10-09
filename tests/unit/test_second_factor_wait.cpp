/**
 * @file tests/unit/test_second_factor_wait.cpp
 * @brief Timing and state rules for an out-of-band second-factor wait.
 */
#include <chrono>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include "src/auth/second_factor_wait.h"

namespace fw = plank::auth::factor_wait;
using namespace std::chrono_literals;
using approval_e = fw::pending_approval_t::state_e;

TEST(SecondFactorWait, ClampsRoundBudgetBelowTheClientRequestTimeout) {
  EXPECT_EQ(fw::round_budget(fw::round_wait_default_ms), 3800ms);
  EXPECT_EQ(fw::round_wait_default_ms, 3800);
  EXPECT_EQ(fw::round_budget(4000), 4000ms);
  EXPECT_EQ(fw::round_budget(0), 500ms);
  EXPECT_EQ(fw::round_budget(-1), 500ms);
  EXPECT_EQ(fw::round_budget(6000), 4500ms);
  EXPECT_EQ(fw::round_budget(1500), 1500ms);
  // Every client abandons a request after 5 s.
  EXPECT_LT(fw::round_budget(1'000'000), 5000ms);
}

TEST(SecondFactorWait, ChargesEarlierWorkToTheRound) {
  const auto start = fw::clock_t::time_point {} + 100s;
  EXPECT_EQ(fw::round_remaining(start, start, 4000ms), 4000ms);
  EXPECT_EQ(fw::round_remaining(start, start + 1500ms, 4000ms), 2500ms);
  EXPECT_EQ(fw::round_remaining(start, start + 4000ms, 4000ms), 0ms);
  EXPECT_EQ(fw::round_remaining(start, start + 9s, 4000ms), 0ms);
}

TEST(SecondFactorWait, SixteenRoundClientCoversTheDuoPushLifetime) {
  // Alan's client allows 16 responses; the first carries the password and
  // the result of the 16th is never read, so 15 rounds wait on the push.
  constexpr int waiting_rounds = 15;
  // 15 x 3.8 s = 57 s: just under DUO's 60 s push lifetime, and the push is
  // sent during the first round, so nearly the whole lifetime is covered.
  EXPECT_GE(fw::client_coverage(waiting_rounds, fw::round_budget(fw::round_wait_default_ms)), 57s);
  // The default must leave room inside the client's 5 s timeout for a new
  // TCP + TLS handshake, the transfer and io-thread queueing (1.2 s here).
  EXPECT_LE(fw::round_budget(fw::round_wait_default_ms), 3800ms);
  // The previous fixed 1.5 s budget gave about 22 s.
  EXPECT_LT(fw::client_coverage(waiting_rounds, 1500ms), 25s);
  EXPECT_EQ(fw::client_coverage(-3, 4000ms), 0ms);
}

TEST(SecondFactorWait, FirstDecisionIsFinal) {
  fw::pending_approval_t approval {"Contacting DUO..."};
  EXPECT_EQ(approval.snapshot().state, approval_e::waiting);
  EXPECT_EQ(approval.snapshot().message, "Contacting DUO...");

  approval.progress("Push sent");
  EXPECT_EQ(approval.snapshot().message, "Push sent");

  EXPECT_FALSE(approval.settle(approval_e::waiting, "not a decision"));
  EXPECT_TRUE(approval.settle(approval_e::denied, "DUO denied: timeout", "The DUO push was not approved in time."));
  EXPECT_FALSE(approval.settle(approval_e::approved, "late approval"));
  approval.progress("ignored");

  const auto result = approval.snapshot();
  EXPECT_EQ(result.state, approval_e::denied);
  EXPECT_EQ(result.detail, "DUO denied: timeout");
  EXPECT_EQ(result.user_message, "The DUO push was not approved in time.");
  EXPECT_EQ(result.message, "Push sent");
}

TEST(SecondFactorWait, CancelDeniesAndStopsTheWorker) {
  fw::pending_approval_t approval;
  EXPECT_FALSE(approval.cancelled());
  approval.cancel();
  EXPECT_TRUE(approval.cancelled());
  EXPECT_EQ(approval.snapshot().state, approval_e::denied);
  // An approval arriving after the sign-in was abandoned cannot be used.
  EXPECT_FALSE(approval.settle(approval_e::approved, "approved after abandon"));
  EXPECT_EQ(approval.snapshot().state, approval_e::denied);
}

TEST(SecondFactorWait, WaitEndsAtTheDeadlineWhileUndecided) {
  fw::pending_approval_t approval {"waiting"};
  const auto before = fw::clock_t::now();
  const auto result = approval.wait_until(before + 50ms);
  EXPECT_EQ(result.state, approval_e::waiting);
  EXPECT_EQ(result.message, "waiting");
  EXPECT_GE(fw::clock_t::now() - before, 50ms);
}

TEST(SecondFactorWait, WaitWakesAsSoonAsTheWorkerDecides) {
  fw::pending_approval_t approval;
  std::thread worker([&approval] {
    std::this_thread::sleep_for(20ms);
    approval.settle(approval_e::approved, "DUO push approved");
  });
  const auto before = fw::clock_t::now();
  const auto result = approval.wait_until(before + 10s);
  worker.join();
  EXPECT_EQ(result.state, approval_e::approved);
  EXPECT_EQ(result.detail, "DUO push approved");
  EXPECT_LT(fw::clock_t::now() - before, 5s);
}

TEST(SecondFactorWait, WorkerSlotsAreBounded) {
  fw::worker_slots_t slots {2};
  EXPECT_TRUE(slots.wait_idle(0ms));
  EXPECT_TRUE(slots.try_acquire());
  EXPECT_TRUE(slots.try_acquire());
  EXPECT_FALSE(slots.try_acquire());
  EXPECT_EQ(slots.active(), 2u);
  EXPECT_FALSE(slots.wait_idle(10ms));

  slots.release();
  EXPECT_TRUE(slots.try_acquire());
  slots.release();
  slots.release();
  EXPECT_EQ(slots.active(), 0u);
  EXPECT_TRUE(slots.wait_idle(0ms));
  slots.release();  // an extra release never underflows
  EXPECT_EQ(slots.active(), 0u);
}

TEST(SecondFactorWait, RoundClockStartsAtRequestArrival) {
  // The budget is spent from arrival, so 700 ms of queueing and password
  // checking leaves 2800 ms of a 3500 ms budget, not the whole of it.
  const auto arrived = fw::clock_t::time_point {} + 50s;
  EXPECT_EQ(fw::round_remaining(arrived, arrived + 700ms, 3500ms), 2800ms);
  EXPECT_EQ(fw::round_remaining(arrived, arrived + 3600ms, 3500ms), 0ms);
}

TEST(SecondFactorWait, LimiterKeysAreCaseInsensitiveAndNeverEmpty) {
  EXPECT_EQ(fw::limiter_key("Alice"), fw::limiter_key("aLICE"));
  EXPECT_NE(fw::limiter_key("alice"), fw::limiter_key("bob"));
  EXPECT_FALSE(fw::limiter_key("").empty());
}

TEST(SecondFactorWait, OneAccountCannotTakeEverySlot) {
  fw::worker_slots_t slots {16, 2, 4};
  const auto alice = fw::limiter_key("Alice");
  const auto bob = fw::limiter_key("bob");
  const auto ip1 = fw::limiter_key("10.0.0.1");
  const auto ip2 = fw::limiter_key("10.0.0.2");

  EXPECT_TRUE(slots.try_acquire(alice, ip1));
  EXPECT_TRUE(slots.try_acquire(alice, ip1));
  EXPECT_FALSE(slots.try_acquire(alice, ip2));  // third for the account, from another address
  EXPECT_EQ(slots.active(), 2u);  // a refusal changes nothing
  EXPECT_EQ(slots.active_a(alice), 2u);
  EXPECT_EQ(slots.active_b(ip2), 0u);

  EXPECT_TRUE(slots.try_acquire(bob, ip2));  // others are unaffected
  slots.release(alice, ip1);
  EXPECT_TRUE(slots.try_acquire(alice, ip2));  // a release frees an account slot
  EXPECT_EQ(slots.active_a(alice), 2u);
}

TEST(SecondFactorWait, OneAddressCannotRunManyParallelGuesses) {
  fw::worker_slots_t slots {16, 2, 4};
  const auto ip = fw::limiter_key("10.0.0.1");
  for (int i = 0; i < 4; ++i) {
    EXPECT_TRUE(slots.try_acquire(fw::limiter_key("user" + std::to_string(i)), ip));
  }
  EXPECT_FALSE(slots.try_acquire(fw::limiter_key("user9"), ip));
  EXPECT_TRUE(slots.try_acquire(fw::limiter_key("user9"), fw::limiter_key("10.0.0.2")));
  EXPECT_EQ(slots.active_b(ip), 4u);
  for (int i = 0; i < 4; ++i) {
    slots.release(fw::limiter_key("user" + std::to_string(i)), ip);
  }
  EXPECT_EQ(slots.active_b(ip), 0u);
}

TEST(SecondFactorWait, GlobalCapStillAppliesAndPerKeyIsOptional) {
  fw::worker_slots_t slots {3, 2, 4};
  EXPECT_TRUE(slots.try_acquire("a", "1"));
  EXPECT_TRUE(slots.try_acquire("b", "2"));
  EXPECT_TRUE(slots.try_acquire("c", "3"));
  EXPECT_FALSE(slots.try_acquire("d", "4"));

  // Auth-round style: only the address dimension is limited.
  fw::worker_slots_t rounds {16, fw::unlimited_slots, 4};
  for (int i = 0; i < 4; ++i) {
    EXPECT_TRUE(rounds.try_acquire({}, "10.0.0.1"));
  }
  EXPECT_FALSE(rounds.try_acquire({}, "10.0.0.1"));
  EXPECT_TRUE(rounds.try_acquire({}, "10.0.0.2"));
  for (int i = 0; i < 4; ++i) {
    rounds.release({}, "10.0.0.1");
  }
  rounds.release({}, "10.0.0.2");
  EXPECT_EQ(rounds.active(), 0u);
  EXPECT_TRUE(rounds.wait_idle(10ms));

  // Plain use without keys keeps working.
  fw::worker_slots_t plain {1};
  EXPECT_TRUE(plain.try_acquire());
  EXPECT_FALSE(plain.try_acquire());
}
