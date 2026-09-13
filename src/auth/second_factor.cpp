/**
 * @file src/auth/second_factor.cpp
 * @brief Second-factor provider factory and the explicit "none" provider.
 */

#include "second_factor.h"

#include <algorithm>
#include <cctype>

#include "src/logging.h"

namespace plank::auth {
  namespace {
    std::string lowercase(std::string_view value) {
      std::string result {value};
      std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
      });
      return result;
    }

    /**
     * @brief Provider for deployments with no second factor.
     *
     * This is a supported configuration - not every site runs 2FA - but it must
     * be chosen deliberately and it announces itself on every authentication so
     * a missing second factor can never be mistaken for a working one.
     */
    class none_provider_t final: public second_factor_t {
    public:
      factor_step_t begin(std::string_view username, std::string_view remote_host) override {
        BOOST_LOG(warning)
          << "PLANK second factor is disabled (security.second_factor=none). "
             "Authenticating "
          << username << " from " << remote_host << " on password alone.";
        return {factor_step_t::state_e::approved, {}, "second factor disabled by configuration"};
      }

      factor_step_t respond(std::vector<std::string>) override {
        // begin() is always terminal for this provider.
        return {factor_step_t::state_e::approved, {}, "second factor disabled by configuration"};
      }
    };
  }  // namespace

  factor_failmode_e parse_failmode(std::string_view value) {
    const auto text = lowercase(value);
    if (text == "allow") {
      return factor_failmode_e::allow;
    }
    if (!text.empty() && text != "deny") {
      BOOST_LOG(warning)
        << "Unrecognised security.second_factor_failmode '" << value
        << "'; failing closed (deny).";
    }
    return factor_failmode_e::deny;
  }

  std::unique_ptr<second_factor_t> make_second_factor(
    std::string_view provider,
    factor_failmode_e failmode,
    std::string &error_message
  ) {
    const auto name = lowercase(provider);

    if (name == "none") {
      (void) failmode;  // nothing to be unreachable
      return std::make_unique<none_provider_t>();
    }

    // Deliberately no default case. An unknown name must deny rather than
    // silently degrade to password-only; that would reproduce the credential
    // provider bypass this design exists to prevent.
    error_message = "unknown second-factor provider '" + std::string {provider} +
            "'; refusing to authenticate without one";
    BOOST_LOG(error) << error_message;
    return nullptr;
  }
}  // namespace plank::auth
