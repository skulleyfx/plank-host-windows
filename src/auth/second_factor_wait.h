/**
 * @file src/auth/second_factor_wait.h
 * @brief Platform-neutral pieces of an out-of-band second-factor wait.
 *
 * A push approval is decided on a worker thread while the client keeps asking
 * "is it done yet?" one sign-in round at a time. Each round may wait on the
 * worker for a bounded budget. Every client abandons a request after 5 s, and
 * Alan's client allows only 16 rounds in total, so the budget sets how long a
 * user has to approve: 15 waiting rounds x 3.8 s is about 57 s, just short of
 * DUO's own 60 s push lifetime (the push goes out during the first round, so
 * in practice nearly all of it is covered). The round clock starts when the HTTPS request arrives (not when
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
#include <cstdint>
#include <deque>
#include <memory>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace plank::auth::factor_wait {
  using clock_t = std::chrono::steady_clock;  ///< Monotonic clock for every deadline.

  inline constexpr int round_wait_default_ms = 3800;  ///< Default per-round wait: 15 x 3.8 s = 57 s of DUO's 60 s push.
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
   * @brief Why a worker or push was refused.
   */
  enum class refusal_e {
    none,  ///< Not refused.
    global,  ///< Too many workers overall.
    account,  ///< Too many workers for this account.
    address,  ///< Too many workers for this client address.
    cooldown_spacing,  ///< This account asked for a push too soon after the last one.
    cooldown_window,  ///< This account asked for too many pushes in the rolling window.
  };

  /**
   * @brief Name of the limit that was hit, for logs. Contains no secrets.
   *
   * @param refusal Reason.
   * @return Short fixed text.
   */
  inline const char *refusal_name(refusal_e refusal) {
    switch (refusal) {
      case refusal_e::global:
        return "global";
      case refusal_e::account:
        return "account";
      case refusal_e::address:
        return "address";
      case refusal_e::cooldown_spacing:
        return "cooldown (too soon after the previous push)";
      case refusal_e::cooldown_window:
        return "cooldown (too many pushes in the window)";
      case refusal_e::none:
      default:
        return "none";
    }
  }

  /**
   * @brief Short text for the user that explains a refusal.
   *
   * @param refusal Reason.
   * @return Text safe to show on the client.
   */
  inline const char *refusal_user_message(refusal_e refusal) {
    switch (refusal) {
      case refusal_e::cooldown_spacing:
        return "Please wait a few seconds before requesting another DUO push.";
      case refusal_e::cooldown_window:
        return "Too many DUO pushes were requested. Try again in a couple of minutes.";
      default:
        return "Too many sign-ins are waiting for DUO. Try again in a minute.";
    }
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
      return acquire(key_a, key_b) == refusal_e::none;
    }

    /**
     * @brief try_acquire() that says which limit refused. A refusal changes nothing.
     *
     * @param key_a First key (the account), or empty.
     * @param key_b Second key (the client address), or empty.
     * @return none when a slot was taken, else the limit that was hit.
     */
    refusal_e acquire(const std::string &key_a = {}, const std::string &key_b = {}) {
      std::lock_guard lock {mutex_};
      if (active_ >= limit_) {
        return refusal_e::global;
      }
      if (!key_a.empty() && count_of(by_a_, key_a) >= per_key_a_) {
        return refusal_e::account;
      }
      if (!key_b.empty() && count_of(by_b_, key_b) >= per_key_b_) {
        return refusal_e::address;
      }
      ++active_;
      if (!key_a.empty()) {
        ++by_a_[key_a];
      }
      if (!key_b.empty()) {
        ++by_b_[key_b];
      }
      return refusal_e::none;
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
     * @brief Return only the per-key part of a slot; the global count stays taken.
     *
     * Used when a worker is cancelled but still running: it keeps counting
     * against the global limit until release_global() when it exits.
     *
     * @param key_a Same first key given to acquire().
     * @param key_b Same second key given to acquire().
     */
    void release_keys(const std::string &key_a, const std::string &key_b) {
      std::lock_guard lock {mutex_};
      drop(by_a_, key_a);
      drop(by_b_, key_b);
    }

    /**
     * @brief Return only the global part of a slot whose keys were already released.
     */
    void release_global() {
      {
        std::lock_guard lock {mutex_};
        if (active_ > 0) {
          --active_;
        }
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

  /**
   * @brief Limits for starting DUO pushes.
   */
  struct push_limits_t {
    std::size_t global {16};  ///< Workers at once, cancelled ones included until they exit.
    std::size_t per_account {2};  ///< Live (not superseded) workers per account; a backstop.
    std::size_t per_address {4};  ///< Live workers per client address.
    std::chrono::milliseconds min_spacing {std::chrono::seconds {10}};  ///< Least time between two pushes for an account.
    std::chrono::milliseconds window {std::chrono::minutes {2}};  ///< Rolling window for max_in_window.
    std::size_t max_in_window {3};  ///< Most pushes for an account within the window.
  };

  /**
   * @brief Decides whether a new DUO push may start, and supersedes older ones.
   *
   * Three rules, all of which deny (never approve) when they refuse:
   *  - Cooldown against push-bombing by someone holding the password: per
   *    account, a minimum spacing and a rolling-window maximum. A refused
   *    request neither sends a push nor disturbs an older one.
   *  - Supersede: a new push for the same account from the same client address
   *    cancels that pair's older approvals (cancel() settles them as denied,
   *    final) and frees their per-account and per-address slots at once. A
   *    cancelled worker may sit in a long poll for a while, so it keeps its
   *    global slot until finish().
   *  - Caps: global, per account and per address, checked after superseding.
   *
   * A pushed approval belongs to exactly one sign-in, so superseding cannot
   * turn a cancelled sign-in into an approved one: the old exchange is denied
   * for good and a late worker result is ignored (see pending_approval_t).
   */
  class push_governor_t {
  public:
    /**
     * @brief Outcome of admit().
     */
    struct admission_t {
      refusal_e refusal {refusal_e::none};  ///< none when the push may start.
      std::uint64_t id {0};  ///< Pass to finish() when the worker exits; 0 when refused.
      std::shared_ptr<pending_approval_t> approval;  ///< Shared with the worker; null when refused.
      std::size_t superseded {0};  ///< Older approvals cancelled by this call.
    };

    explicit push_governor_t(push_limits_t limits = {}):
        limits_ {limits},
        slots_ {limits.global, limits.per_account, limits.per_address} {
    }

    /**
     * @brief Ask to start a push.
     *
     * @param account Account name; case-insensitive.
     * @param address Client address; may be empty (limited as one unknown address).
     * @param now Current time.
     * @param initial_message Progress text for the new approval.
     * @return The admission; check refusal first.
     */
    admission_t admit(std::string_view account, std::string_view address, clock_t::time_point now,
                      std::string initial_message = {}) {
      const auto account_key = limiter_key(account);
      const auto address_key = limiter_key(address);
      std::lock_guard lock {mutex_};
      sweep_history(now);

      admission_t result;
      auto &history = history_[account_key];
      if (!history.empty() && now - history.back() < limits_.min_spacing) {
        result.refusal = refusal_e::cooldown_spacing;
        return result;
      }
      if (history.size() >= limits_.max_in_window) {
        result.refusal = refusal_e::cooldown_window;
        return result;
      }

      for (auto &[id, entry] : entries_) {
        if (entry.keys_held && entry.account_key == account_key && entry.address_key == address_key) {
          entry.approval->cancel();
          slots_.release_keys(entry.account_key, entry.address_key);
          entry.keys_held = false;
          ++result.superseded;
        }
      }

      result.refusal = slots_.acquire(account_key, address_key);
      if (result.refusal != refusal_e::none) {
        erase_if_empty(account_key);
        return result;
      }
      history.push_back(now);
      result.id = ++last_id_;
      result.approval = std::make_shared<pending_approval_t>(std::move(initial_message));
      entries_.emplace(result.id, entry_t {account_key, address_key, result.approval, true});
      return result;
    }

    /**
     * @brief The worker has exited (or never started): return whatever it still holds.
     *
     * @param id Value from admit().
     */
    void finish(std::uint64_t id) {
      std::lock_guard lock {mutex_};
      const auto found = entries_.find(id);
      if (found == entries_.end()) {
        return;
      }
      if (found->second.keys_held) {
        slots_.release(found->second.account_key, found->second.address_key);
      } else {
        slots_.release_global();
      }
      entries_.erase(found);
    }

    /**
     * @return Slot accounting, for tests and diagnostics.
     */
    const worker_slots_t &slots() const {
      return slots_;
    }

    /**
     * @return The limits in force.
     */
    const push_limits_t &limits() const {
      return limits_;
    }

  private:
    struct entry_t {
      std::string account_key;
      std::string address_key;
      std::shared_ptr<pending_approval_t> approval;
      bool keys_held;  ///< False once superseded: only the global slot is still held.
    };

    void sweep_history(clock_t::time_point now) {
      for (auto it = history_.begin(); it != history_.end();) {
        auto &times = it->second;
        while (!times.empty() && now - times.front() >= limits_.window) {
          times.pop_front();
        }
        it = times.empty() ? history_.erase(it) : std::next(it);
      }
    }

    void erase_if_empty(const std::string &account_key) {
      if (const auto found = history_.find(account_key); found != history_.end() && found->second.empty()) {
        history_.erase(found);
      }
    }

    std::mutex mutex_;
    push_limits_t limits_;
    worker_slots_t slots_;
    std::map<std::uint64_t, entry_t> entries_;
    std::map<std::string, std::deque<clock_t::time_point>> history_;  ///< Push start times per account.
    std::uint64_t last_id_ {0};
  };
}  // namespace plank::auth::factor_wait
