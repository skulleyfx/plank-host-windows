/**
 * @file src/auth/second_factor_wait.h
 * @brief Platform-neutral pieces of an out-of-band second-factor wait.
 *
 * A push approval is decided on a worker thread while the client keeps asking
 * "is it done yet?" one sign-in round at a time. Each round may wait on the
 * worker for a bounded budget. Every client abandons a request after 5 s, and
 * Alan's client allows only 16 rounds in total, so the budget sets how long a
 * user has to approve: 15 waiting rounds x 3.5 s covers DUO's own 60 s push
 * lifetime. The round clock starts when the HTTPS request arrives (not when
 * the worker picks it up), and the budget stays well under 5 s so a fresh TCP +
 * TLS handshake, the transfer and io-thread queueing still fit before the
 * client gives up. The rounds run off the HTTPS thread (see nvhttp.cpp), so a long
 * budget never stalls serverinfo polling from other clients.
 *
 * Kept free of Windows APIs so the timing and state rules are unit tested.
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace plank::auth::factor_wait {
  using clock_t = std::chrono::steady_clock;  ///< Monotonic clock for every deadline.

  inline constexpr int round_wait_default_ms = 3500;  ///< Default per-round wait.
  inline constexpr int round_wait_min_ms = 500;  ///< Shortest accepted per-round wait.
  /// Longest accepted per-round wait: clients abandon a request after 5 s,
  /// which also covers a fresh TCP + TLS handshake on every round.
  inline constexpr int round_wait_max_ms = 4500;

  /**
   * @brief Clamp a configured per-round wait to the range every client tolerates.
   *
   * @param configured_ms Value from security.second_factor_round_wait_ms.
   * @return Budget in milliseconds.
   */
  inline std::chrono::milliseconds round_budget(int configured_ms) {
    return std::chrono::milliseconds {std::clamp(configured_ms, round_wait_min_ms, round_wait_max_ms)};
  }

  /**
   * @brief Time left in a round, never negative.
   *
   * The round starts when the HTTPS request arrives on the io thread, so
   * queueing and work done before the wait (for example the password check)
   * are charged to the same budget.
   *
   * @param started When the request arrived.
   * @param now Current time.
   * @param budget Per-round budget.
   * @return Remaining wait.
   */
  inline std::chrono::milliseconds round_remaining(clock_t::time_point started, clock_t::time_point now,
                                                   std::chrono::milliseconds budget) {
    const auto end = started + budget;
    if (now >= end) {
      return std::chrono::milliseconds {0};
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - now);
  }

  /**
   * @brief Approval time a client gets when it allows a fixed number of rounds.
   *
   * @param waiting_rounds Rounds the client spends waiting on the push.
   * @param budget Per-round budget.
   * @return Total wait, ignoring network time.
   */
  inline std::chrono::milliseconds client_coverage(int waiting_rounds, std::chrono::milliseconds budget) {
    return budget * std::max(waiting_rounds, 0);
  }

  /**
   * @brief One pending out-of-band approval, shared by a sign-in and its worker.
   *
   * The first terminal result wins and never changes afterwards, so one
   * approval can complete only the sign-in that requested it, and a late
   * worker result cannot overturn a denial or a cancellation.
   */
  class pending_approval_t {
  public:
    /**
     * @brief Approval state.
     */
    enum class state_e {
      waiting,  ///< No decision yet.
      approved,  ///< The second factor was satisfied.
      denied,  ///< Refused, unavailable, timed out or cancelled.
    };

    /**
     * @brief Copy of the state taken under the lock.
     */
    struct snapshot_t {
      state_e state {state_e::waiting};  ///< Current state.
      std::string message;  ///< Progress text shown while waiting.
      std::string detail;  ///< Auditable reason once settled; safe to log.
      std::string user_message;  ///< Short reason for the user on denial; may be empty.
    };

    /**
     * @param initial_message Progress text before the worker reports anything.
     */
    explicit pending_approval_t(std::string initial_message = {}) {
      current_.message = std::move(initial_message);
    }

    /**
     * @brief Replace the progress text; ignored once settled.
     *
     * @param message New progress text.
     */
    void progress(std::string message) {
      std::lock_guard lock {mutex_};
      if (current_.state == state_e::waiting) {
        current_.message = std::move(message);
      }
    }

    /**
     * @brief Record the decision. Only the first call has any effect.
     *
     * @param state approved or denied; waiting is rejected.
     * @param detail Auditable reason.
     * @param user_message Short reason for the user.
     * @return True when this call settled the approval.
     */
    bool settle(state_e state, std::string detail, std::string user_message = {}) {
      if (state == state_e::waiting) {
        return false;
      }
      {
        std::lock_guard lock {mutex_};
        if (current_.state != state_e::waiting) {
          return false;
        }
        current_.state = state;
        current_.detail = std::move(detail);
        current_.user_message = std::move(user_message);
      }
      changed_.notify_all();
      return true;
    }

    /**
     * @brief Abandon the approval: it settles as denied and the worker stops.
     */
    void cancel() {
      {
        std::lock_guard lock {mutex_};
        cancelled_flag_ = true;
      }
      settle(state_e::denied, "second-factor exchange abandoned");
    }

    /**
     * @brief Whether the sign-in that owns this approval has gone away.
     *
     * @return True after cancel().
     */
    bool cancelled() const {
      std::lock_guard lock {mutex_};
      return cancelled_flag_;
    }

    /**
     * @brief Wait for a decision until a deadline.
     *
     * @param deadline Latest return time.
     * @return State at the decision or the deadline, whichever comes first.
     */
    snapshot_t wait_until(clock_t::time_point deadline) {
      std::unique_lock lock {mutex_};
      changed_.wait_until(lock, deadline, [this] {
        return current_.state != state_e::waiting;
      });
      return current_;
    }

    /**
     * @brief Current state without waiting.
     *
     * @return Copy of the state.
     */
    snapshot_t snapshot() const {
      std::lock_guard lock {mutex_};
      return current_;
    }

  private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    snapshot_t current_;
    bool cancelled_flag_ {false};  ///< Set by cancel().
  };

  /// No limit for a key dimension.
  inline constexpr std::size_t unlimited_slots = std::numeric_limits<std::size_t>::max();

  /**
   * @brief Normalize an account or address into a limiter key.
   *
   * Account names compare case-insensitively on Windows, so "Alice" and
   * "alice" must share one allowance. An empty value maps to a fixed key so
   * it is still limited rather than skipped.
   *
   * @param value Account name or peer address.
   * @return Lower-cased key; never empty.
   */
  inline std::string limiter_key(std::string_view value) {
    std::string key {value};
    for (auto &c : key) {
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      }
    }
    if (key.empty()) {
      key = "(unknown)";
    }
    return key;
  }

  /**
   * @brief Counting limit for concurrent background workers.
   *
   * try_acquire() never blocks: a caller over the limit is refused, so a burst
   * of sign-ins cannot create unbounded threads. Besides the global limit it
   * can cap workers per key in two independent dimensions (for example per
   * account and per client address), so one client cannot take every slot.
   * A refused call changes nothing.
   */
  class worker_slots_t {
  public:
    /**
     * @param limit Most workers allowed at once.
     * @param per_key_a Most workers per first key; unlimited_slots for none.
     * @param per_key_b Most workers per second key; unlimited_slots for none.
     */
    explicit worker_slots_t(std::size_t limit, std::size_t per_key_a = unlimited_slots,
                            std::size_t per_key_b = unlimited_slots):
        limit_ {limit},
        per_key_a_ {per_key_a},
        per_key_b_ {per_key_b} {
    }

    /**
     * @brief Take a slot if one is free.
     *
     * An empty key skips that dimension (and its release); pass limiter_key()
     * output to enforce it.
     *
     * @param key_a First key (for example the account), or empty.
     * @param key_b Second key (for example the client address), or empty.
     * @return True when a slot was taken; the caller must release() it with the same keys.
     */
    bool try_acquire(const std::string &key_a = {}, const std::string &key_b = {}) {
      std::lock_guard lock {mutex_};
      if (active_ >= limit_) {
        return false;
      }
      if (!key_a.empty() && count_of(by_a_, key_a) >= per_key_a_) {
        return false;
      }
      if (!key_b.empty() && count_of(by_b_, key_b) >= per_key_b_) {
        return false;
      }
      ++active_;
      if (!key_a.empty()) {
        ++by_a_[key_a];
      }
      if (!key_b.empty()) {
        ++by_b_[key_b];
      }
      return true;
    }

    /**
     * @brief Return a slot taken by try_acquire().
     *
     * @param key_a Same first key given to try_acquire().
     * @param key_b Same second key given to try_acquire().
     */
    void release(const std::string &key_a = {}, const std::string &key_b = {}) {
      {
        std::lock_guard lock {mutex_};
        if (active_ > 0) {
          --active_;
        }
        drop(by_a_, key_a);
        drop(by_b_, key_b);
      }
      idle_.notify_all();
    }

    /**
     * @return Slots in use.
     */
    std::size_t active() const {
      std::lock_guard lock {mutex_};
      return active_;
    }

    /**
     * @param key_a First key.
     * @return Slots in use under that key.
     */
    std::size_t active_a(const std::string &key_a) const {
      std::lock_guard lock {mutex_};
      return count_of(by_a_, key_a);
    }

    /**
     * @param key_b Second key.
     * @return Slots in use under that key.
     */
    std::size_t active_b(const std::string &key_b) const {
      std::lock_guard lock {mutex_};
      return count_of(by_b_, key_b);
    }

    /**
     * @brief Wait until every slot has been released.
     *
     * @param timeout Longest wait.
     * @return True when idle.
     */
    bool wait_idle(std::chrono::milliseconds timeout) {
      std::unique_lock lock {mutex_};
      return idle_.wait_for(lock, timeout, [this] {
        return active_ == 0;
      });
    }

  private:
    using counts_t = std::map<std::string, std::size_t>;

    static std::size_t count_of(const counts_t &counts, const std::string &key) {
      const auto found = counts.find(key);
      return found == counts.end() ? 0 : found->second;
    }

    static void drop(counts_t &counts, const std::string &key) {
      if (key.empty()) {
        return;
      }
      if (const auto found = counts.find(key); found != counts.end()) {
        if (--found->second == 0) {
          counts.erase(found);
        }
      }
    }

    mutable std::mutex mutex_;
    std::condition_variable idle_;
    std::size_t limit_;
    std::size_t per_key_a_;
    std::size_t per_key_b_;
    std::size_t active_ {0};
    counts_t by_a_;
    counts_t by_b_;
  };
}  // namespace plank::auth::factor_wait
