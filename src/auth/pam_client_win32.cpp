/**
 * @file src/auth/pam_client_win32.cpp
 * @brief Windows host authentication: primary credential plus second factor.
 *
 * Mirrors the shape of the Linux PAM exchange behind the same `pam_client_t`
 * interface, so `web_auth.cpp` and `nvhttp.cpp` need no platform knowledge:
 *
 *   1. begin()   -> challenge for the account password
 *   2. respond() -> LogonUser() validates it, then the configured second-factor
 *                   provider runs (see second_factor.h)
 *   3. respond() -> provider result; approved yields `authenticated`
 *
 * The second factor is a pluggable provider rather than a specific vendor,
 * matching how PAM lets any module participate on Linux. See AUTH-AND-DUO.md.
 */

#include "pam_client.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <set>
#include <vector>

#include <windows.h>

#include "second_factor.h"
#include "src/config.h"
#include "src/logging.h"

namespace plank::auth {
  namespace {
    constexpr std::int32_t prompt_style_password = 1;  ///< PAM_PROMPT_ECHO_OFF.
    constexpr std::int32_t prompt_style_text_info = 4;  ///< PAM_TEXT_INFO.

    step_t denied(phase_e phase, int status, std::string_view reason) {
      BOOST_LOG(warning) << "PLANK authentication denied: " << reason;
      return {step_t::state_e::denied, {}, phase, status};
    }

    /**
     * @brief Split "DOMAIN\\user" or "user@domain" into LogonUser arguments.
     */
    void split_account(const std::string &account, std::wstring &user, std::wstring &domain) {
      auto widen = [](const std::string &value) {
        if (value.empty()) {
          return std::wstring {};
        }
        const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                             static_cast<int>(value.size()), nullptr, 0);
        std::wstring result(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                            result.data(), size);
        return result;
      };

      if (const auto slash = account.find('\\'); slash != std::string::npos) {
        domain = widen(account.substr(0, slash));
        user = widen(account.substr(slash + 1));
        return;
      }
      if (const auto at = account.find('@'); at != std::string::npos) {
        // LogonUser accepts a UPN with a null domain.
        user = widen(account);
        domain.clear();
        return;
      }
      user = widen(account);
      domain = L".";  // local account; qualified_windows_account() adds default_domain first
    }

    std::string admin_key(std::string_view account) {
      std::string key = qualified_windows_account(account);
      std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return key;
    }

    std::mutex &admin_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    std::set<std::string> &admin_accounts() {
      static std::set<std::string> accounts;
      return accounts;
    }

    /**
     * @brief Check a logon token for membership of security.admin_group.
     */
    bool token_in_admin_group(HANDLE token) {
      std::vector<BYTE> sid_buffer;
      PSID sid = nullptr;
      if (config::plank_auth.admin_group.empty()) {
        sid_buffer.resize(SECURITY_MAX_SID_SIZE);
        DWORD size = static_cast<DWORD>(sid_buffer.size());
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid_buffer.data(), &size)) {
          return false;
        }
        sid = sid_buffer.data();
      } else {
        const auto &name = config::plank_auth.admin_group;
        const int wide_size = MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), nullptr, 0);
        std::wstring wide(static_cast<std::size_t>(wide_size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), wide.data(), wide_size);
        DWORD sid_size = 0;
        DWORD domain_size = 0;
        SID_NAME_USE use {};
        LookupAccountNameW(nullptr, wide.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
        sid_buffer.resize(sid_size);
        std::wstring domain(domain_size, L'\0');
        if (sid_size == 0 ||
            !LookupAccountNameW(nullptr, wide.c_str(), sid_buffer.data(), &sid_size, domain.data(), &domain_size, &use)) {
          BOOST_LOG(warning) << "PLANK admin_group could not be resolved: " << name;
          return false;
        }
        sid = sid_buffer.data();
      }
      BOOL member = FALSE;
      return CheckTokenMembership(token, sid, &member) && member;
    }

    /**
     * @brief Validate an account password without creating a logon session.
     *
     * LOGON32_LOGON_NETWORK is a credential check only. It deliberately does
     * NOT invoke Windows credential providers, which is exactly why a second
     * factor must be applied separately here rather than assumed.
     */
    bool primary_credential_valid(const std::string &account, const std::string &password,
                                  std::string &reason) {
      std::wstring user;
      std::wstring domain;
      split_account(qualified_windows_account(account), user, domain);

      std::wstring secret;
      if (!password.empty()) {
        const int size = MultiByteToWideChar(CP_UTF8, 0, password.data(),
                                             static_cast<int>(password.size()), nullptr, 0);
        secret.resize(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, password.data(), static_cast<int>(password.size()),
                            secret.data(), size);
      }

      HANDLE token = nullptr;
      const BOOL ok = LogonUserW(user.c_str(), domain.empty() ? nullptr : domain.c_str(),
                                 secret.c_str(), LOGON32_LOGON_NETWORK,
                                 LOGON32_PROVIDER_DEFAULT, &token);
      const DWORD last_error = ok ? ERROR_SUCCESS : GetLastError();

      if (!secret.empty()) {
        SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
      }
      if (token != nullptr) {
        const bool admin = token_in_admin_group(token);
        CloseHandle(token);
        std::lock_guard lock {admin_mutex()};
        if (admin) {
          admin_accounts().insert(admin_key(account));
        } else {
          admin_accounts().erase(admin_key(account));
        }
      }
      if (!ok) {
        reason = "LogonUser failed (" + std::to_string(last_error) + ")";
      }
      return ok == TRUE;
    }
  }  // namespace

  /**
   * @brief Per-connection Windows authentication state.
   */
  struct win32_auth_state_t {
    std::string account;
    std::string remote_host;
    std::unique_ptr<second_factor_t> factor;
    bool awaiting_password {false};
    std::string pending_denial;  ///< Logged reason for a denial whose message has been shown.
  };

  namespace {
    // One in-flight exchange per pam_client_t, keyed by object address, so the
    // shared header needs no Windows-specific members. Guarded because
    // nvhttp serves requests from multiple threads.
    std::mutex &state_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    std::map<const void *, win32_auth_state_t> &state_table() {
      static std::map<const void *, win32_auth_state_t> table;
      return table;
    }

    win32_auth_state_t &state_for(const void *key) {
      std::lock_guard lock {state_mutex()};
      return state_table()[key];
    }

    void clear_state(const void *key) {
      std::lock_guard lock {state_mutex()};
      state_table().erase(key);
    }

    /**
     * @brief Map a provider result onto the PAM-shaped step the callers expect.
     */
    step_t translate(win32_auth_state_t &state, const factor_step_t &factor) {
      if (factor.state == factor_step_t::state_e::denied && !factor.user_message.empty()) {
        // Denied responses carry no text, so send the reason as a final
        // informational message and deny on the next round. The password was
        // already accepted, so this discloses nothing a push would not.
        state.pending_denial = factor.detail.empty() ? "second factor denied" : factor.detail;
        return {step_t::state_e::challenge, {prompt_t {prompt_style_text_info, factor.user_message}},
                phase_e::authenticate, 0};
      }
      switch (factor.state) {
        case factor_step_t::state_e::approved:
          BOOST_LOG(info) << "PLANK second factor approved: " << factor.detail;
          return {step_t::state_e::authenticated, {}, phase_e::authenticated, 0};
        case factor_step_t::state_e::challenge:
          return {step_t::state_e::challenge, factor.prompts, phase_e::authenticate, 0};
        case factor_step_t::state_e::denied:
        default:
          return denied(phase_e::authenticate, -1,
                        factor.detail.empty() ? "second factor denied" : factor.detail);
      }
    }
  }  // namespace

  std::string qualified_windows_account(std::string_view account) {
    if (account.find('\\') != std::string_view::npos || account.find('@') != std::string_view::npos ||
        config::plank_auth.default_domain.empty()) {
      return std::string {account};
    }
    return config::plank_auth.default_domain + "\\" + std::string {account};
  }

  bool account_is_plank_admin(std::string_view account) {
    if (account.empty()) {
      return false;
    }
    std::lock_guard lock {admin_mutex()};
    return admin_accounts().contains(admin_key(account));
  }

  pam_client_t::~pam_client_t() {
    clear_state(this);
  }

  pam_client_t::pam_client_t(pam_client_t &&other) noexcept:
      descriptor_ {other.descriptor_},
      transaction_id_ {other.transaction_id_},
      expected_responses_ {other.expected_responses_},
      authenticated_ {other.authenticated_} {
    other.descriptor_ = -1;
  }

  pam_client_t &pam_client_t::operator=(pam_client_t &&other) noexcept {
    if (this != &other) {
      descriptor_ = other.descriptor_;
      transaction_id_ = other.transaction_id_;
      expected_responses_ = other.expected_responses_;
      authenticated_ = other.authenticated_;
      other.descriptor_ = -1;
    }
    return *this;
  }

  step_t pam_client_t::begin(std::uint64_t transaction_id,
                             std::string_view username, std::string_view remote_host,
                             std::string_view) {
    transaction_id_ = transaction_id;
    authenticated_ = false;

    auto &state = state_for(this);
    state.account.assign(username);
    state.remote_host.assign(remote_host);
    state.factor.reset();
    state.pending_denial.clear();
    state.awaiting_password = true;

    expected_responses_ = 1;
    return {step_t::state_e::challenge,
            {prompt_t {prompt_style_password, "Password: "}},
            phase_e::authenticate, 0};
  }

  step_t pam_client_t::respond(std::vector<std::string> responses) {
    auto &state = state_for(this);

    if (state.awaiting_password) {
      if (responses.size() != 1) {
        return denied(phase_e::protocol, -1, "expected exactly one password response");
      }
      std::string password = std::move(responses.front());
      std::string reason;
      const bool valid = primary_credential_valid(state.account, password, reason);
      SecureZeroMemory(password.data(), password.size());
      state.awaiting_password = false;

      if (!valid) {
        return denied(phase_e::authenticate, -1, reason);
      }

      if (consume_staged_resume_ticket(state.account, state.remote_host)) {
        BOOST_LOG(info) << "PLANK second factor satisfied by a resume ticket for " << state.account
                        << " from " << state.remote_host;
        authenticated_ = true;
        expected_responses_ = 0;
        return {step_t::state_e::authenticated, {}, phase_e::authenticated, 0};
      }

      std::string error_message;
      state.factor = make_second_factor(config::plank_auth.second_factor,
                                        parse_failmode(config::plank_auth.second_factor_failmode),
                                        error_message);
      if (!state.factor) {
        // Unknown provider: deny rather than degrade to password-only.
        return denied(phase_e::authenticate, -1, error_message);
      }

      const auto step = translate(state, state.factor->begin(state.account, state.remote_host));
      authenticated_ = step.state == step_t::state_e::authenticated;
      expected_responses_ = step.prompts.size();
      return step;
    }

    if (!state.pending_denial.empty()) {
      const auto reason = std::move(state.pending_denial);
      state.pending_denial.clear();
      expected_responses_ = 0;
      return denied(phase_e::authenticate, -1, reason);
    }
    if (!state.factor) {
      return denied(phase_e::protocol, -1, "no second-factor exchange in progress");
    }
    const auto step = translate(state, state.factor->respond(std::move(responses)));
    authenticated_ = step.state == step_t::state_e::authenticated;
    expected_responses_ = step.prompts.size();
    return step;
  }

  void pam_client_t::close() {
    clear_state(this);
    descriptor_ = -1;
    transaction_id_ = 0;
    expected_responses_ = 0;
    authenticated_ = false;
  }

  bool pam_client_t::connected() const {
    return transaction_id_ != 0;
  }

  step_t pam_client_t::read_step() {
    return denied(phase_e::protocol, -1, "read_step is not used by the Windows broker");
  }
}  // namespace plank::auth
