/**
 * @file src/auth/resume_ticket_win32.cpp
 * @brief Single-use tickets that let a client's automatic reconnect skip a repeat second factor.
 *
 * The Windows host restarts whenever the console session changes, and the
 * client then signs in again on its own. Without a ticket each of those
 * reconnects costs another second-factor approval. After a complete sign-in
 * (password and second factor) the host issues a random ticket that the client
 * keeps in memory only. Presenting it with the correct password skips the
 * second factor once; a new ticket is issued on every success.
 *
 * Tickets are bound to the account and client address, expire after
 * security.second_factor_resume_minutes (0 disables them), and are stored only
 * as SHA-256 hashes in %ProgramData%\PLANK so they survive host restarts.
 */

#include "second_factor.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <mutex>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "src/config.h"
#include "src/logging.h"
#include "src/platform/common.h"
#include "web_auth.h"

using namespace std::literals;

namespace plank::auth {
  namespace {
    /// A staged ticket must be used by the sign-in that presented it.
    constexpr auto staged_lifetime = 2min;

    std::mutex &store_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    std::string key_for(std::string_view username, std::string_view remote_host) {
      auto account = qualified_windows_account(username);
      std::transform(account.begin(), account.end(), account.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return account + "|" + std::string {remote_host};
    }

    std::string sha256_hex(std::string_view data) {
      unsigned char digest[EVP_MAX_MD_SIZE];
      unsigned int length = 0;
      EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr);
      std::string out;
      for (unsigned int i = 0; i < length; ++i) {
        out += std::format("{:02x}", digest[i]);
      }
      return out;
    }

    std::int64_t unix_now() {
      return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()
      )
        .count();
    }

    std::filesystem::path store_path() {
      return platf::appdata() / "resume-tickets.json";
    }

    nlohmann::json load_store() {
      std::ifstream in {store_path()};
      auto json = in ? nlohmann::json::parse(in, nullptr, false) : nlohmann::json::object();
      if (!json.is_object()) {
        return nlohmann::json::object();
      }
      // Drop expired entries so the file cannot grow without bound.
      const auto now = unix_now();
      for (auto it = json.begin(); it != json.end();) {
        if (!it->is_object() || it->value("expires", std::int64_t {0}) <= now) {
          it = json.erase(it);
        } else {
          ++it;
        }
      }
      return json;
    }

    void save_store(const nlohmann::json &store) {
      const auto target = store_path();
      auto temporary = target;
      temporary += ".tmp";
      {
        std::ofstream out {temporary, std::ios::trunc};
        out << store.dump();
        if (!out) {
          BOOST_LOG(warning) << "Unable to write PLANK resume tickets";
          return;
        }
      }
      std::error_code ec;
      std::filesystem::rename(temporary, target, ec);
      if (ec) {
        BOOST_LOG(warning) << "Unable to replace PLANK resume tickets: " << ec.message();
      }
    }

    struct staged_t {
      std::string ticket;
      std::chrono::steady_clock::time_point staged_at;
    };

    std::map<std::string, staged_t> &staged_tickets() {
      static std::map<std::string, staged_t> staged;
      return staged;
    }
  }  // namespace

  void stage_resume_ticket(std::string_view username, std::string_view remote_host, std::string ticket) {
    if (ticket.empty() || ticket.size() > 256 || config::plank_auth.second_factor_resume_minutes <= 0) {
      return;
    }
    std::lock_guard lock {store_mutex()};
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(staged_tickets(), [now](const auto &item) {
      return now - item.second.staged_at > staged_lifetime;
    });
    staged_tickets()[key_for(username, remote_host)] = {std::move(ticket), now};
  }

  bool consume_staged_resume_ticket(std::string_view username, std::string_view remote_host) {
    if (config::plank_auth.second_factor_resume_minutes <= 0) {
      return false;
    }
    const auto key = key_for(username, remote_host);
    std::lock_guard lock {store_mutex()};
    const auto staged = staged_tickets().find(key);
    if (staged == staged_tickets().end()) {
      return false;
    }
    const auto presented_hash = sha256_hex(staged->second.ticket);
    const bool fresh = std::chrono::steady_clock::now() - staged->second.staged_at <= staged_lifetime;
    staged_tickets().erase(staged);
    if (!fresh) {
      return false;
    }

    auto store = load_store();
    const auto entry = store.find(key);
    const bool valid = entry != store.end() && entry->value("hash", "").size() == presented_hash.size() &&
                       CRYPTO_memcmp(entry->value("hash", "").data(), presented_hash.data(), presented_hash.size()) == 0;
    // Single use: whatever the outcome, the stored ticket is spent.
    if (entry != store.end()) {
      store.erase(entry);
      save_store(store);
    }
    if (!valid) {
      BOOST_LOG(warning) << "Rejected an invalid or expired PLANK resume ticket for " << username << " from " << remote_host;
    }
    return valid;
  }

  std::string issue_resume_ticket(std::string_view username, std::string_view remote_host) {
    const int minutes = config::plank_auth.second_factor_resume_minutes;
    if (minutes <= 0) {
      return {};
    }
    auto ticket = secure_random_hex(32);
    if (ticket.empty()) {
      return {};
    }
    std::lock_guard lock {store_mutex()};
    auto store = load_store();
    store[key_for(username, remote_host)] = {
      {"hash", sha256_hex(ticket)},
      {"expires", unix_now() + static_cast<std::int64_t>(minutes) * 60},
    };
    save_store(store);
    return ticket;
  }
}  // namespace plank::auth
