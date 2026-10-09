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
 * Tickets are bound to the account and client address and are stored only as
 * SHA-256 hashes in %ProgramData%\PLANK so they survive host restarts. The
 * window slides: a ticket is good for security.second_factor_resume_minutes
 * (0 disables them) after the end of the last streaming activity, refreshed
 * while a session is streaming and when it ends, but never later than
 * security.second_factor_resume_max_hours after the sign-in that last used the
 * second factor. Stored entries from the older format (a fixed expiry) are
 * discarded, which costs one second-factor prompt after an upgrade.
 */

#include "second_factor.h"

#include "resume_window.h"

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

    /// Whether a stored entry is in the current format and still inside both limits.
    bool entry_is_current(const nlohmann::json &entry, std::int64_t now) {
      if (!entry.is_object() || !entry.contains("format") || !entry["format"].is_number_integer() ||
          entry["format"].get<int>() != resume_ticket_format || !entry.contains("hash") ||
          !entry["hash"].is_string() || !entry.contains("signin") || !entry["signin"].is_number_integer() ||
          !entry.contains("last_activity") || !entry["last_activity"].is_number_integer()) {
        return false;
      }
      return resume_ticket_valid(now, entry["signin"].get<std::int64_t>(),
                                 entry["last_activity"].get<std::int64_t>(),
                                 config::plank_auth.second_factor_resume_minutes,
                                 config::plank_auth.second_factor_resume_max_hours);
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
        if (!entry_is_current(*it, now)) {
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

    /// Original sign-in time of a ticket just spent, handed to the ticket issued next.
    struct carried_t {
      std::int64_t signin_at;
      std::chrono::steady_clock::time_point carried_at;
    };

    std::map<std::string, carried_t> &carried_signins() {
      static std::map<std::string, carried_t> carried;
      return carried;
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
    carried_signins().erase(key);
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
    // load_store() has already dropped entries that are expired or in another format.
    const bool valid = entry != store.end() && entry->value("hash", "").size() == presented_hash.size() &&
                       CRYPTO_memcmp(entry->value("hash", "").data(), presented_hash.data(), presented_hash.size()) == 0;
    if (valid) {
      carried_signins()[key] = {entry->value("signin", std::int64_t {0}), std::chrono::steady_clock::now()};
    }
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
    const auto key = key_for(username, remote_host);
    const auto now = unix_now();
    auto signin_at = now;
    // A ticket issued after a resume keeps the time of the real second factor.
    if (const auto carried = carried_signins().find(key); carried != carried_signins().end()) {
      if (std::chrono::steady_clock::now() - carried->second.carried_at <= staged_lifetime) {
        signin_at = carried->second.signin_at;
      }
      carried_signins().erase(carried);
    }
    store[key] = {
      {"format", resume_ticket_format},
      {"hash", sha256_hex(ticket)},
      {"signin", signin_at},
      {"last_activity", now},
    };
    save_store(store);
    return ticket;
  }

  void touch_resume_ticket(std::string_view username, std::string_view remote_host) {
    if (config::plank_auth.second_factor_resume_minutes <= 0 || username.empty()) {
      return;
    }
    const auto key = key_for(username, remote_host);
    std::lock_guard lock {store_mutex()};
    auto store = load_store();
    const auto entry = store.find(key);
    if (entry == store.end()) {
      return;
    }
    (*entry)["last_activity"] = unix_now();
    save_store(store);
  }
}  // namespace plank::auth
