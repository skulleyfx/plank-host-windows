/**
 * @file src/auth/second_factor.h
 * @brief Pluggable second-factor provider interface.
 *
 * On Linux, second factor is supplied by the PAM stack: `plank-host` delegates
 * to `system-auth`, so pam_duo or any other module participates without PLANK
 * knowing it exists. Windows has no PAM, so PLANK must provide the equivalent
 * seam itself rather than bind to one vendor.
 *
 * The provider runs ONLY after the primary credential has been validated,
 * matching how a Windows credential provider behaves: password first, then
 * challenge.
 */
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pam_broker_protocol.h"

namespace plank::auth {
  /**
   * @brief Result of advancing a second-factor exchange.
   */
  struct factor_step_t {
    /**
     * @brief Provider state.
     */
    enum class state_e {
      challenge,  ///< Caller must collect and submit responses.
      approved,  ///< Second factor satisfied.
      denied,  ///< Second factor refused, unavailable, or timed out.
    };

    state_e state {state_e::denied};  ///< Terminal or intermediate state.
    std::vector<prompt_t> prompts;  ///< Empty for out-of-band approval (push).
    std::string detail;  ///< Auditable reason; safe to log.
    std::string user_message;  ///< Short reason safe to show the user on denial; may be empty.
  };

  /**
   * @brief One second-factor exchange for a single authentication attempt.
   */
  class second_factor_t {
  public:
    virtual ~second_factor_t() = default;

    /**
     * @brief Begin the exchange after the primary credential has been accepted.
     *
     * @param username Validated operating-system account.
     * @param remote_host Auditable source host label.
     * @return Challenge, approval, or denial.
     */
    virtual factor_step_t begin(std::string_view username, std::string_view remote_host) = 0;

    /**
     * @brief Submit one response per preceding prompt.
     *
     * @param responses Prompt responses in order.
     * @return Next challenge or a terminal result.
     */
    virtual factor_step_t respond(std::vector<std::string> responses) = 0;
  };

  /**
   * @brief Behaviour when a provider cannot be reached.
   *
   * Mirrors pam_duo's `failmode`. The default is `deny`; an administrator must
   * opt into `allow` deliberately.
   */
  enum class factor_failmode_e {
    deny,  ///< Refuse authentication when the provider is unreachable.
    allow,  ///< Accept the primary credential alone when unreachable.
  };

  /**
   * @brief Construct the configured second-factor provider.
   *
   * An unrecognised provider name MUST fail closed: returning nullptr denies
   * authentication rather than silently degrading to password-only, which would
   * be the same class of defect as bypassing the credential provider entirely.
   *
   * @param provider Configured provider name, e.g. "none" or "duo".
   * @param failmode Behaviour when the provider is unreachable.
   * @param error Populated when no provider could be constructed.
   * @return Provider, or nullptr when the name is unknown.
   */
  std::unique_ptr<second_factor_t> make_second_factor(
    std::string_view provider,
    factor_failmode_e failmode,
    std::string &error_message
  );

  /**
   * @brief Parse a configured failmode value.
   *
   * Unrecognised values fail closed to `deny`, matching the broker policy
   * convention that an administrator typo cannot weaken authentication.
   *
   * @param value Configured text.
   * @return Parsed failmode.
   */
  factor_failmode_e parse_failmode(std::string_view value);

#ifdef _WIN32
  /**
   * @brief Qualify an account name the way every Windows auth path must.
   *
   * "DOMAIN\\user" and "user@upn" are returned unchanged. A bare name gets
   * security.default_domain when one is configured, and is otherwise returned
   * bare. Password validation, identity lookup and console attestation all use
   * this so they cannot disagree about which account a name means.
   *
   * @param account Account name as typed by the user.
   * @return Qualified account name.
   */
  std::string qualified_windows_account(std::string_view account);

  /**
   * @brief Whether an account was in security.admin_group when it last signed in.
   *
   * Membership is read from the logon token at each password sign-in and kept
   * for the life of the host process. An account that has not signed in with
   * a password since the host started is not treated as an admin.
   *
   * @param account Account name as presented.
   * @return True for a remembered member of the admin group.
   */
  bool account_is_plank_admin(std::string_view account);

  /**
   * @brief Hold a resume ticket presented at sign-in start until the password is checked.
   *
   * @param username Account name as presented.
   * @param remote_host Client address.
   * @param ticket Ticket from the client's previous complete sign-in.
   */
  void stage_resume_ticket(std::string_view username, std::string_view remote_host, std::string ticket);

  /**
   * @brief Spend a staged resume ticket after the password has been accepted.
   *
   * @param username Account name as presented.
   * @param remote_host Client address.
   * @return True when a valid, unexpired ticket was presented; the ticket is consumed either way.
   */
  bool consume_staged_resume_ticket(std::string_view username, std::string_view remote_host);

  /**
   * @brief Issue a new resume ticket after a complete sign-in.
   *
   * @param username Account name as authenticated.
   * @param remote_host Client address.
   * @return Ticket for the client to keep in memory, or empty when disabled.
   */
  std::string issue_resume_ticket(std::string_view username, std::string_view remote_host);

  /**
   * @brief Construct the DUO Auth API provider from security.duo_* settings.
   *
   * @param failmode Behaviour when DUO is unreachable.
   * @param error_message Populated when the provider is not fully configured.
   * @return Provider, or nullptr when configuration is incomplete.
   */
  std::unique_ptr<second_factor_t> make_duo_provider(factor_failmode_e failmode, std::string &error_message);
#endif
}  // namespace plank::auth
