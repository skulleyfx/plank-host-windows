/**
 * @file src/auth/resume_window.h
 * @brief Expiry rule for second-factor resume tickets.
 *
 * Kept free of platform headers so the rule can be unit tested anywhere.
 */
#pragma once

#include <cstdint>

namespace plank::auth {
  /// Stored ticket format. Entries without this exact value are rejected.
  constexpr int resume_ticket_format = 2;

  /**
   * @brief Whether a resume ticket may still skip the second factor.
   *
   * The window slides: the ticket is good for @p window_minutes after the
   * last streaming activity, but never later than @p max_hours after the
   * original complete sign-in, after which the second factor is always asked.
   *
   * @param now Current time, seconds since the Unix epoch.
   * @param signin_at When the second factor was last actually completed.
   * @param last_activity End of the latest streaming activity (or issue time).
   * @param window_minutes Sliding window; 0 or less disables tickets.
   * @param max_hours Absolute cap from the original sign-in; 0 or less disables tickets.
   * @return True when the ticket is still valid.
   */
  constexpr bool resume_ticket_valid(std::int64_t now, std::int64_t signin_at, std::int64_t last_activity,
                                     int window_minutes, int max_hours) {
    if (window_minutes <= 0 || max_hours <= 0) {
      return false;
    }
    if (now > last_activity + static_cast<std::int64_t>(window_minutes) * 60) {
      return false;
    }
    return now <= signin_at + static_cast<std::int64_t>(max_hours) * 3600;
  }
}  // namespace plank::auth
