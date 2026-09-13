/**
 * @file src/auth/web_auth.cpp
 * @brief Network-to-broker PAM conversation and session-token state.
 */

#include "web_auth.h"


#include "src/plank_win32_compat.h"
#include "../session/session_context.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <utility>

#include <openssl/rand.h>

#ifndef _WIN32
  #include <pwd.h>
  #include <unistd.h>
#else
  #include <windows.h>
  #include <vector>
#endif

namespace plank::auth {
  namespace {
    /**
     * @brief Production adapter around @ref pam_client_t.
     */
    class pam_conversation_t: public conversation_i {
    public:
      step_t begin(std::uint64_t transaction_id, std::string_view username,
                   std::string_view remote_host) override {
        return client_.begin(transaction_id, username, remote_host,
                             "plank");
      }

      step_t respond(std::vector<std::string> responses) override {
        return client_.respond(std::move(responses));
      }

    private:
      pam_client_t client_;  ///< Local broker connection.
    };

    /**
     * @brief Securely erase response strings.
     *
     * @param responses Strings to erase.
     */
    void erase(std::vector<std::string> &responses) {
      for (auto &response : responses) {
        if (!response.empty()) {
          explicit_bzero(response.data(), response.size());
        }
      }
    }
  }  // namespace

  web_auth_manager_t::web_auth_manager_t(
    conversation_factory_t factory,
    random_t random,
    now_t now,
    std::chrono::seconds conversation_lifetime,
    std::chrono::seconds token_lifetime
  ):
      factory_ {std::move(factory)},
      random_ {std::move(random)},
      now_ {std::move(now)},
      conversation_lifetime_ {conversation_lifetime},
      token_lifetime_ {token_lifetime} {
  }

  web_auth_step_t web_auth_manager_t::begin(std::string_view username,
                                            std::string_view remote_host) {
    std::lock_guard lock {mutex_};
    expire_locked();
    if (username.empty() || username.size() > 256 || remote_host.empty() ||
        remote_host.size() > 256 || conversations_.size() + tokens_.size() >= 32) {
      return {};
    }
    std::shared_ptr<conversation_i> conversation = factory_();
    std::string id = random_(24);
    if (!conversation || id.empty() || conversations_.contains(id) || tokens_.contains(id)) {
      return {};
    }
    const auto transaction_id = next_transaction_++;
    if (next_transaction_ == 0) {
      next_transaction_ = 1;
    }
    auto step = conversation->begin(transaction_id, username, remote_host);
    entry_t entry {
      std::string {remote_host},
      std::string {username},
      now_() + conversation_lifetime_,
      std::move(conversation),
      {},
    };
    return retain(std::move(step), std::move(id), std::move(entry));
  }

  web_auth_step_t web_auth_manager_t::respond(std::string_view conversation_id,
                                              std::string_view remote_host,
                                              std::vector<std::string> responses) {
    std::lock_guard lock {mutex_};
    expire_locked();
    const auto found = conversations_.find(std::string {conversation_id});
    if (found == conversations_.end() || found->second.remote_host != remote_host) {
      erase(responses);
      return {};
    }
    auto id = found->first;
    auto entry = std::move(found->second);
    conversations_.erase(found);
    auto step = entry.conversation->respond(std::move(responses));
    entry.expires = now_() + conversation_lifetime_;
    return retain(std::move(step), std::move(id), std::move(entry));
  }

  bool web_auth_manager_t::authorize(std::string_view token,
                                     std::string_view remote_host) {
    return identity(token, remote_host).has_value();
  }

  std::optional<std::string> web_auth_manager_t::identity(
    std::string_view token,
    std::string_view remote_host
  ) {
    std::lock_guard lock {mutex_};
    expire_locked();
    const auto found = tokens_.find(std::string {token});
    if (found == tokens_.end() || found->second.remote_host != remote_host) {
      return std::nullopt;
    }
    if (!found->second.conversation && found->second.claimed_session.expired()) {
      tokens_.erase(found);
      return std::nullopt;
    }
    return found->second.username;
  }

  std::shared_ptr<conversation_i> web_auth_manager_t::claim(
    std::string_view token,
    std::string_view remote_host
  ) {
    std::lock_guard lock {mutex_};
    expire_locked();
    const auto found = tokens_.find(std::string {token});
    if (found == tokens_.end() || found->second.remote_host != remote_host) {
      return {};
    }
    if (found->second.conversation) {
      auto session = std::move(found->second.conversation);
      found->second.claimed_session = session;
      return session;
    }
    auto session = found->second.claimed_session.lock();
    if (!session) {
      tokens_.erase(found);
    }
    return session;
  }

  void web_auth_manager_t::cancel(std::string_view token) {
    std::lock_guard lock {mutex_};
    tokens_.erase(std::string {token});
  }

  void web_auth_manager_t::expire() {
    std::lock_guard lock {mutex_};
    expire_locked();
  }

  web_auth_step_t web_auth_manager_t::retain(step_t step, std::string id,
                                             entry_t entry) {
    web_auth_step_t output {
      step.state,
      {},
      {},
      std::move(step.prompts),
      step.phase,
      step.pam_status,
    };
    if (step.state == step_t::state_e::challenge) {
      output.conversation_id = id;
      conversations_.emplace(std::move(id), std::move(entry));
    } else if (step.state == step_t::state_e::authenticated) {
      std::string token = random_(32);
      if (token.empty() || conversations_.contains(token) || tokens_.contains(token)) {
        return {};
      }
      entry.expires = now_() + token_lifetime_;
      output.session_token = token;
      tokens_.emplace(std::move(token), std::move(entry));
    }
    return output;
  }

  void web_auth_manager_t::expire_locked() {
    const auto time = now_();
    std::erase_if(conversations_, [time](const auto &item) {
      return item.second.expires <= time;
    });
    std::erase_if(tokens_, [time](const auto &item) {
      return item.second.expires <= time;
    });
  }

  web_auth_manager_t::conversation_factory_t pam_conversation_factory() {
    return []() {
      return std::make_unique<pam_conversation_t>();
    };
  }

  std::string secure_random_hex(std::size_t bytes) {
    if (bytes == 0 || bytes > 64) {
      return {};
    }
    std::array<unsigned char, 64> random {};
    if (RAND_bytes(random.data(), static_cast<int>(bytes)) != 1) {
      return {};
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string output(bytes * 2, '0');
    for (std::size_t index = 0; index < bytes; ++index) {
      output[index * 2] = digits[random[index] >> 4U];
      output[index * 2 + 1] = digits[random[index] & 0x0fU];
    }
    return output;
  }

  std::optional<uid_t> account_uid(std::string_view username) {
    if (username.empty() || username.find('\0') != std::string_view::npos ||
        username.size() > 256) {
      return std::nullopt;
    }

    const std::string account {username};
    constexpr std::size_t minimum_buffer_size = 1024;
    constexpr std::size_t maximum_buffer_size = 1024 * 1024;
#ifdef _WIN32
    // Windows has no POSIX uid. Use the relative identifier (RID) - the final
    // sub-authority of the account SID - as a stable numeric identity. This
    // MUST match session_context_win32.cpp's account_rid(), because the two are
    // compared to decide whether an account owns the console session.
    {
      std::wstring wide(account.size(), L'\0');
      if (!account.empty()) {
        const int size = MultiByteToWideChar(CP_UTF8, 0, account.data(),
                                             static_cast<int>(account.size()),
                                             wide.data(), static_cast<int>(wide.size()));
        wide.resize(static_cast<std::size_t>(size));
      }
      DWORD sid_size = 0;
      DWORD domain_size = 0;
      SID_NAME_USE use {};
      LookupAccountNameW(nullptr, wide.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
      if (sid_size == 0) {
        return std::nullopt;
      }
      std::vector<unsigned char> sid(sid_size);
      std::wstring domain(domain_size, L'\0');
      if (!LookupAccountNameW(nullptr, wide.c_str(), sid.data(), &sid_size,
                              domain.data(), &domain_size, &use)) {
        return std::nullopt;
      }
      auto *sid_pointer = reinterpret_cast<PSID>(sid.data());
      const auto *count = GetSidSubAuthorityCount(sid_pointer);
      if (count == nullptr || *count == 0) {
        return std::nullopt;
      }
      return static_cast<uid_t>(*GetSidSubAuthority(sid_pointer, static_cast<DWORD>(*count - 1)));
    }
#else
    const long recommended_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = recommended_size > 0 ?
                                static_cast<std::size_t>(recommended_size) :
                                minimum_buffer_size;
    buffer_size = std::clamp(buffer_size, minimum_buffer_size, maximum_buffer_size);

    passwd record {};
    passwd *result = nullptr;
    std::vector<char> buffer(buffer_size);
    int status;
    do {
      status = getpwnam_r(account.c_str(), &record, buffer.data(), buffer.size(), &result);
      if (status != ERANGE || buffer.size() == maximum_buffer_size) {
        break;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer_size));
    } while (true);

    if (status != 0 || result == nullptr) {
      return std::nullopt;
    }
    return result->pw_uid;
#endif
  }

  bool account_authorized_for_desktop(std::string_view username) {
    const auto uid = account_uid(username);
    return uid && plank::session::supervisor_attests_account_for_active_seat0(*uid);
  }
}  // namespace plank::auth
