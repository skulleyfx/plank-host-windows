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

// ---- push governor: supersede, cooldown, slot accounting ----

namespace {
  const auto t0 = fw::clock_t::time_point {} + 1000s;
}

TEST(SecondFactorWait, RefusalsNameTheLimitWithoutSecrets) {
  EXPECT_STREQ(fw::refusal_name(fw::refusal_e::global), "global");
  EXPECT_STREQ(fw::refusal_name(fw::refusal_e::account), "account");
  EXPECT_STREQ(fw::refusal_name(fw::refusal_e::address), "address");
  EXPECT_NE(std::string {fw::refusal_name(fw::refusal_e::cooldown_spacing)}.find("cooldown"), std::string::npos);
  EXPECT_NE(std::string {fw::refusal_name(fw::refusal_e::cooldown_window)}.find("cooldown"), std::string::npos);
  EXPECT_STREQ(fw::refusal_user_message(fw::refusal_e::cooldown_spacing),
               "Please wait a few seconds before requesting another DUO push.");
  EXPECT_STREQ(fw::refusal_user_message(fw::refusal_e::account),
               "Too many sign-ins are waiting for DUO. Try again in a minute.");
}

TEST(SecondFactorWait, SlotsReportWhichLimitRefused) {
  fw::worker_slots_t slots {3, 1, 2};
  EXPECT_EQ(slots.acquire("a", "1"), fw::refusal_e::none);
  EXPECT_EQ(slots.acquire("a", "2"), fw::refusal_e::account);
  EXPECT_EQ(slots.acquire("b", "1"), fw::refusal_e::none);
  EXPECT_EQ(slots.acquire("c", "1"), fw::refusal_e::address);
  EXPECT_EQ(slots.acquire("c", "3"), fw::refusal_e::none);
  EXPECT_EQ(slots.acquire("d", "4"), fw::refusal_e::global);
  EXPECT_EQ(slots.active(), 3u);
}

TEST(SecondFactorWait, SplitReleaseKeepsTheGlobalSlot) {
  fw::worker_slots_t slots {2, 1, 4};
  EXPECT_TRUE(slots.try_acquire("a", "1"));
  slots.release_keys("a", "1");
  EXPECT_EQ(slots.active(), 1u);
  EXPECT_EQ(slots.active_a("a"), 0u);
  EXPECT_EQ(slots.active_b("1"), 0u);
  EXPECT_FALSE(slots.wait_idle(5ms));
  slots.release_global();
  slots.release_global();  // never underflows
  EXPECT_EQ(slots.active(), 0u);
  EXPECT_TRUE(slots.wait_idle(5ms));
}

TEST(SecondFactorWait, RetryFromTheSameAddressSupersedesTheOldPush) {
  fw::push_governor_t gov;  // 16 / 2 / 4, 10 s spacing, 3 per 2 min
  const auto first = gov.admit("Alice", "10.0.0.1", t0, "Contacting DUO...");
  ASSERT_EQ(first.refusal, fw::refusal_e::none);
  EXPECT_EQ(first.approval->snapshot().message, "Contacting DUO...");

  const auto second = gov.admit("alice", "10.0.0.1", t0 + 11s);
  ASSERT_EQ(second.refusal, fw::refusal_e::none);
  EXPECT_EQ(second.superseded, 1u);
  EXPECT_NE(first.id, second.id);

  // The older approval is denied for good and cannot be approved late.
  EXPECT_TRUE(first.approval->cancelled());
  EXPECT_EQ(first.approval->snapshot().state, approval_e::denied);
  EXPECT_FALSE(first.approval->settle(approval_e::approved, "late approval"));
  EXPECT_EQ(first.approval->snapshot().state, approval_e::denied);
  EXPECT_EQ(second.approval->snapshot().state, approval_e::waiting);
  EXPECT_FALSE(second.approval->cancelled());

  // Per-account and per-address slots moved at cancel time; the cancelled
  // worker still holds a global slot until it exits.
  EXPECT_EQ(gov.slots().active(), 2u);
  EXPECT_EQ(gov.slots().active_a(fw::limiter_key("alice")), 1u);
  EXPECT_EQ(gov.slots().active_b(fw::limiter_key("10.0.0.1")), 1u);

  gov.finish(first.id);
  EXPECT_EQ(gov.slots().active(), 1u);
  EXPECT_EQ(gov.slots().active_a(fw::limiter_key("alice")), 1u);  // not released twice
  gov.finish(first.id);  // idempotent
  EXPECT_EQ(gov.slots().active(), 1u);
  gov.finish(second.id);
  EXPECT_EQ(gov.slots().active(), 0u);
  EXPECT_EQ(gov.slots().active_a(fw::limiter_key("alice")), 0u);
  EXPECT_EQ(gov.slots().active_b(fw::limiter_key("10.0.0.1")), 0u);
}

TEST(SecondFactorWait, SupersedeOnlyTouchesTheSameAccountAndAddress) {
  fw::push_governor_t gov;
  const auto other_address = gov.admit("alice", "10.0.0.9", t0);
  const auto other_account = gov.admit("bob", "10.0.0.1", t0);
  const auto mine = gov.admit("alice", "10.0.0.1", t0 + 11s);
  ASSERT_EQ(other_address.refusal, fw::refusal_e::none);
  ASSERT_EQ(other_account.refusal, fw::refusal_e::none);
  ASSERT_EQ(mine.refusal, fw::refusal_e::none);
  EXPECT_EQ(mine.superseded, 0u);
  EXPECT_FALSE(other_address.approval->cancelled());
  EXPECT_FALSE(other_account.approval->cancelled());
}

TEST(SecondFactorWait, SupersedeCannotSidestepTheGlobalCap) {
  fw::push_limits_t limits;
  limits.global = 2;
  limits.min_spacing = 0ms;
  limits.max_in_window = 100;
  fw::push_governor_t gov {limits};
  const auto a = gov.admit("alice", "10.0.0.1", t0);
  const auto b = gov.admit("alice", "10.0.0.1", t0 + 1s);  // supersedes a, which still holds a global slot
  ASSERT_EQ(a.refusal, fw::refusal_e::none);
  ASSERT_EQ(b.refusal, fw::refusal_e::none);
  const auto c = gov.admit("alice", "10.0.0.1", t0 + 2s);  // supersedes b; both a and b still hold global slots
  EXPECT_EQ(c.refusal, fw::refusal_e::global);
  EXPECT_FALSE(c.approval);
  EXPECT_EQ(c.id, 0u);
  gov.finish(a.id);  // the cancelled worker exits
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 3s).refusal, fw::refusal_e::none);
}

TEST(SecondFactorWait, PerAccountCapRemainsABackstopAcrossAddresses) {
  fw::push_limits_t limits;
  limits.min_spacing = 0ms;
  limits.max_in_window = 100;
  fw::push_governor_t gov {limits};
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0).refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("alice", "10.0.0.2", t0 + 1s).refusal, fw::refusal_e::none);
  const auto third = gov.admit("alice", "10.0.0.3", t0 + 2s);  // other address: nothing superseded
  EXPECT_EQ(third.refusal, fw::refusal_e::account);
  EXPECT_EQ(third.superseded, 0u);
}

TEST(SecondFactorWait, PerAddressCapStillApplies) {
  fw::push_limits_t limits;
  limits.per_address = 2;
  limits.min_spacing = 0ms;
  limits.max_in_window = 100;
  fw::push_governor_t gov {limits};
  EXPECT_EQ(gov.admit("a", "10.0.0.1", t0).refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("b", "10.0.0.1", t0).refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("c", "10.0.0.1", t0).refusal, fw::refusal_e::address);
}

TEST(SecondFactorWait, CooldownSpacesPushesPerAccount) {
  fw::push_governor_t gov;
  const auto first = gov.admit("alice", "10.0.0.1", t0);
  ASSERT_EQ(first.refusal, fw::refusal_e::none);

  // Too soon: refused, no new approval, and the older push is left alone.
  const auto soon = gov.admit("alice", "10.0.0.1", t0 + 9s);
  EXPECT_EQ(soon.refusal, fw::refusal_e::cooldown_spacing);
  EXPECT_FALSE(soon.approval);
  EXPECT_EQ(soon.superseded, 0u);
  EXPECT_FALSE(first.approval->cancelled());
  EXPECT_EQ(gov.slots().active(), 1u);

  // The spacing applies to the account from any address.
  EXPECT_EQ(gov.admit("ALICE", "10.0.0.7", t0 + 9s).refusal, fw::refusal_e::cooldown_spacing);
  // Another account is unaffected.
  EXPECT_EQ(gov.admit("bob", "10.0.0.1", t0 + 9s).refusal, fw::refusal_e::none);
  // A refused attempt does not extend the cooldown.
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 10s).refusal, fw::refusal_e::none);
}

TEST(SecondFactorWait, CooldownLimitsPushesInARollingWindow) {
  fw::push_governor_t gov;
  for (int i = 0; i < 3; ++i) {
    const auto pushed = gov.admit("alice", "10.0.0.1", t0 + std::chrono::seconds {i * 11});
    ASSERT_EQ(pushed.refusal, fw::refusal_e::none);
    gov.finish(pushed.id);
  }
  // Pushes at 0, 11 and 22 s: a fourth is refused until the first leaves the 2 min window.
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 40s).refusal, fw::refusal_e::cooldown_window);
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 119s).refusal, fw::refusal_e::cooldown_window);
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 120s).refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("alice", "10.0.0.1", t0 + 121s).refusal, fw::refusal_e::cooldown_spacing);
}

TEST(SecondFactorWait, RefusedAdmissionsLeaveNoSlotsBehind) {
  fw::push_limits_t limits;
  limits.global = 1;
  fw::push_governor_t gov {limits};
  const auto held = gov.admit("alice", "10.0.0.1", t0);
  ASSERT_EQ(held.refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("bob", "10.0.0.2", t0).refusal, fw::refusal_e::global);
  EXPECT_EQ(gov.slots().active(), 1u);
  EXPECT_EQ(gov.slots().active_a(fw::limiter_key("bob")), 0u);
  // The refused attempt must not count toward bob's cooldown.
  gov.finish(held.id);
  EXPECT_EQ(gov.admit("bob", "10.0.0.2", t0 + 1s).refusal, fw::refusal_e::none);
}

TEST(SecondFactorWait, EmptyAddressIsStillLimited) {
  fw::push_limits_t limits;
  limits.per_address = 1;
  limits.min_spacing = 0ms;
  fw::push_governor_t gov {limits};
  EXPECT_EQ(gov.admit("a", "", t0).refusal, fw::refusal_e::none);
  EXPECT_EQ(gov.admit("b", "", t0).refusal, fw::refusal_e::address);
}
