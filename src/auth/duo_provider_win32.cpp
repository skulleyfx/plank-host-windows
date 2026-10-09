/**
 * @file src/auth/duo_provider_win32.cpp
 * @brief DUO Auth API second-factor provider for the Windows host.
 *
 * DUO for Windows Logon is a credential provider, which LogonUser() never
 * invokes, so PLANK calls the DUO Auth API itself after the primary credential
 * has been validated (see AUTH-AND-DUO.md).
 *
 * Only push approval is offered. The PLANK client answers every hidden-input
 * prompt with the account password, so a passcode prompt would send that
 * password to DUO; this provider therefore never issues one. A push is
 * awaited in rounds of informational challenges because each client request
 * times out after five seconds. The push and its polling run on a worker per
 * sign-in; each round waits on it for security.second_factor_round_wait_ms
 * (see second_factor_wait.h). Rounds run off the HTTPS thread, so the wait
 * does not delay other clients.
 */

#include "second_factor.h"
#include "second_factor_wait.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <format>
#include <map>
#include <optional>
#include <system_error>
#include <thread>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "src/config.h"
#include "src/logging.h"
#include "src/platform/common.h"

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
  #define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

using namespace std::literals;

namespace plank::auth {
  namespace {
    constexpr std::int32_t prompt_style_text_info = 4;  ///< PAM_TEXT_INFO.

    /// DUO expires a push after about a minute.
    constexpr auto push_deadline = 70s;
    /// Admission for DUO pushes (limits in push_limits_t: 16 workers overall, 2
    /// per account, 4 per client address, and a per-account push cooldown). A
    /// worker lives for at most push_deadline plus one poll after its sign-in
    /// ends, and needs a valid password to start. A retry from the same account
    /// and address supersedes the older push instead of waiting for it to expire.
    factor_wait::push_governor_t &duo_pushes() {
      static factor_wait::push_governor_t governor;
      return governor;
    }

    std::wstring widen(std::string_view text) {
      if (text.empty()) {
        return {};
      }
      const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring wide(static_cast<std::size_t>(size), L'\0');
      MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
      return wide;
    }

    std::string lowercase(std::string_view value) {
      std::string result {value};
      std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return result;
    }

    /// DUO parameter encoding: RFC 3986 unreserved characters pass, upper-case hex otherwise.
    std::string duo_encode(std::string_view value) {
      std::string out;
      for (unsigned char c : value) {
        if (std::isalnum(c) || c == '_' || c == '.' || c == '~' || c == '-') {
          out.push_back(static_cast<char>(c));
        } else {
          out += std::format("%{:02X}", c);
        }
      }
      return out;
    }

    std::string hex(const unsigned char *data, std::size_t size) {
      std::string out;
      out.reserve(size * 2);
      for (std::size_t i = 0; i < size; ++i) {
        out += std::format("{:02x}", data[i]);
      }
      return out;
    }

    std::string sha512_hex(std::string_view data) {
      unsigned char digest[EVP_MAX_MD_SIZE];
      unsigned int length = 0;
      EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha512(), nullptr);
      return hex(digest, length);
    }

    std::string hmac_sha512_hex(std::string_view key, std::string_view data) {
      unsigned char digest[EVP_MAX_MD_SIZE];
      unsigned int length = 0;
      HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char *>(data.data()), data.size(), digest, &length);
      return hex(digest, length);
    }

    std::string base64(std::string_view data) {
      std::string out(4 * ((data.size() + 2) / 3), '\0');
      const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                                          reinterpret_cast<const unsigned char *>(data.data()),
                                          static_cast<int>(data.size()));
      out.resize(static_cast<std::size_t>(std::max(written, 0)));
      return out;
    }

    /// RFC 2822 date in UTC, as DUO signs it: "Tue, 21 Aug 2012 17:29:18 -0000".
    std::string rfc2822_now() {
      const std::time_t now = std::time(nullptr);
      std::tm utc {};
      gmtime_s(&utc, &now);
      char buffer[64];
      std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S -0000", &utc);
      return buffer;
    }

    struct http_result_t {
      bool transport_ok {false};  ///< A response was received.
      bool timed_out {false};  ///< The request exceeded its receive timeout.
      DWORD status {0};  ///< HTTP status code.
      std::string body;  ///< Response body.
      std::string error;  ///< Transport failure description.
    };

    /**
     * @brief One signed DUO Auth API call (canonical request version 5, HMAC-SHA512).
     */
    class duo_client_t {
    public:
      duo_client_t(std::string ikey, std::string skey, std::string host):
          ikey_ {std::move(ikey)},
          skey_ {std::move(skey)},
          host_ {lowercase(host)} {
        // Default (static) proxy settings: automatic discovery can stall for
        // seconds. One session lets WinHTTP keep the TLS connection alive.
        session_ = WinHttpOpen(L"PLANK-Host-Duo/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session_) {
          DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
          if (!WinHttpSetOption(session_, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;  // TLS 1.3 unavailable on older Windows
            WinHttpSetOption(session_, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
          }
        }
      }

      ~duo_client_t() {
        if (session_) {
          WinHttpCloseHandle(session_);
        }
        SecureZeroMemory(skey_.data(), skey_.size());
      }

      duo_client_t(const duo_client_t &) = delete;
      duo_client_t &operator=(const duo_client_t &) = delete;

      http_result_t call(std::string_view method, std::string_view path,
                         const std::map<std::string, std::string> &params,
                         std::chrono::milliseconds timeout) const {
        const std::string date = rfc2822_now();
        std::string query;
        std::string body;
        if (method == "GET"sv) {
          for (const auto &[key, value] : params) {  // std::map iterates sorted
            if (!query.empty()) {
              query.push_back('&');
            }
            query += duo_encode(key) + "=" + duo_encode(value);
          }
        } else {
          // v5 POST bodies are compact JSON with sorted keys.
          body = nlohmann::json(params).dump();
        }

        const std::string canonical = date + "\n" + std::string {method} + "\n" + host_ + "\n" +
                                      std::string {path} + "\n" + query + "\n" + sha512_hex(body) + "\n" +
                                      sha512_hex("");
        const std::string authorization = "Basic " + base64(ikey_ + ":" + hmac_sha512_hex(skey_, canonical));

        http_result_t result;
        if (!session_) {
          result.error = "WinHttpOpen failed";
          return result;
        }
        const int ms = static_cast<int>(timeout.count());

        const HINTERNET connection = WinHttpConnect(session_, widen(host_).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        const std::wstring target = widen(std::string {path} + (query.empty() ? "" : "?" + query));
        const HINTERNET request = connection ?
                                    WinHttpOpenRequest(connection, widen(method).c_str(), target.c_str(), nullptr,
                                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) :
                                    nullptr;
        if (request) {
          WinHttpSetTimeouts(request, ms, ms, ms, ms);
          std::wstring headers = L"Date: " + widen(date) + L"\r\nAuthorization: " + widen(authorization) + L"\r\n";
          if (!body.empty()) {
            headers += L"Content-Type: application/json\r\n";
          }
          const bool sent =
            WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1L),
                               body.empty() ? WINHTTP_NO_REQUEST_DATA : body.data(), static_cast<DWORD>(body.size()),
                               static_cast<DWORD>(body.size()), 0) &&
            WinHttpReceiveResponse(request, nullptr);
          if (sent) {
            DWORD size = sizeof(result.status);
            WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &result.status, &size, WINHTTP_NO_HEADER_INDEX);
            DWORD available = 0;
            while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
              std::string chunk(available, '\0');
              DWORD read = 0;
              if (!WinHttpReadData(request, chunk.data(), available, &read)) {
                break;
              }
              result.body.append(chunk.data(), read);
            }
            result.transport_ok = true;
          } else {
            const DWORD error = GetLastError();
            result.timed_out = error == ERROR_WINHTTP_TIMEOUT;
            result.error = std::format("DUO request failed ({})", error);
          }
          WinHttpCloseHandle(request);
        } else {
          result.error = std::format("DUO connection failed ({})", GetLastError());
        }
        if (connection) {
          WinHttpCloseHandle(connection);
        }
        return result;
      }

    private:
      std::string ikey_;
      std::string skey_;
      std::string host_;
      HINTERNET session_ {nullptr};
    };

    /// Parsed `response` object of a successful call, or nullopt with a reason.
    std::optional<nlohmann::json> duo_response(const http_result_t &http, std::string &reason) {
      if (!http.transport_ok) {
        reason = http.error;
        return std::nullopt;
      }
      const auto json = nlohmann::json::parse(http.body, nullptr, false);
      if (json.is_discarded() || !json.is_object()) {
        reason = std::format("DUO returned HTTP {} with an unreadable body", http.status);
        return std::nullopt;
      }
      if (json.value("stat", "") != "OK" || !json.contains("response")) {
        // Code 40103 is an invalid signature: wrong keys or clock skew.
        reason = std::format("DUO error {} {}: {}", http.status, json.value("code", 0),
                             json.value("message_detail", json.value("message", std::string {"unknown"})));
        return std::nullopt;
      }
      return json["response"];
    }

    std::string duo_username(std::string_view account) {
      // DUO users are normally named without the NetBIOS domain prefix.
      const auto slash = account.find('\\');
      return std::string {slash == std::string_view::npos ? account : account.substr(slash + 1)};
    }

    /**
     * @brief DUO remembered-device tokens, persisted across host restarts.
     *
     * The host restarts whenever the console session changes (sign-in,
     * sign-out), and the client then re-authenticates automatically, so tokens
     * must outlive the process. DUO does not bind a token to a machine, so
     * PLANK stores it per account and source address: a remembered sign-in from
     * one client cannot be replayed from another. The password is still
     * verified on every sign-in, and DUO policy sets the token lifetime. The
     * file lives in %ProgramData%\PLANK, readable only by SYSTEM and
     * Administrators.
     */
    class trusted_device_store_t {
    public:
      static std::string key(std::string_view username, std::string_view remote_host) {
        return lowercase(username) + "|" + std::string {remote_host};
      }

      static std::string get(const std::string &key) {
        std::lock_guard lock {mutex()};
        const auto tokens = load();
        const auto found = tokens.find(key);
        return found != tokens.end() && found->is_string() ? found->get<std::string>() : std::string {};
      }

      static void put(const std::string &key, const std::string &token) {
        std::lock_guard lock {mutex()};
        auto tokens = load();
        if (token.empty()) {
          tokens.erase(key);
        } else {
          tokens[key] = token;
        }
        save(tokens);
      }

    private:
      static std::mutex &mutex() {
        static std::mutex m;
        return m;
      }

      static std::filesystem::path path() {
        return platf::appdata() / "duo-trusted-devices.json";
      }

      static nlohmann::json load() {
        std::ifstream in {path()};
        auto json = in ? nlohmann::json::parse(in, nullptr, false) : nlohmann::json::object();
        return json.is_object() ? json : nlohmann::json::object();
      }

      static void save(const nlohmann::json &tokens) {
        const auto target = path();
        auto temporary = target;
        temporary += ".tmp";
        {
          std::ofstream out {temporary, std::ios::trunc};
          out << tokens.dump();
          if (!out) {
            BOOST_LOG(warning) << "Unable to write DUO remembered-device tokens";
            return;
          }
        }
        std::error_code ec;
        std::filesystem::rename(temporary, target, ec);
        if (ec) {
          BOOST_LOG(warning) << "Unable to replace DUO remembered-device tokens: " << ec.message();
        }
      }
    };

    /**
     * @brief State shared between a DUO exchange and its worker thread.
     *
     * The worker outlives the provider if a DUO call is still in flight when
     * the login is abandoned, so the state is reference counted. The first
     * decision is final (see pending_approval_t).
     */
    using duo_exchange_t = factor_wait::pending_approval_t;
    using approval_e = factor_wait::pending_approval_t::state_e;

    /**
     * @brief Return the worker's slots when the DUO worker exits by any path.
     */
    struct worker_slot_guard_t {
      std::uint64_t id;  ///< Admission id from push_governor_t::admit().

      ~worker_slot_guard_t() {
        duo_pushes().finish(id);
      }
    };

    class duo_provider_t final: public second_factor_t {
    public:
      explicit duo_provider_t(factor_failmode_e failmode):
          failmode_ {failmode} {
      }

      ~duo_provider_t() override {
        if (exchange_) {
          exchange_->cancel();
        }
      }

      factor_step_t begin(std::string_view username, std::string_view remote_host) override {
        // A new push for the same account and address supersedes that pair's
        // older pushes (their approvals settle as denied).
        const auto admission = duo_pushes().admit(duo_username(username), remote_host, factor_wait::clock_t::now(),
                                                  "Contacting DUO...");
        if (admission.refusal != factor_wait::refusal_e::none) {
          // Fail closed: never degrade to password-only because DUO is busy or
          // the account is asking for pushes too fast. The log names the limit,
          // never a secret.
          const auto &limits = duo_pushes().limits();
          BOOST_LOG(warning) << "DUO sign-in refused: " << factor_wait::refusal_name(admission.refusal)
                             << " limit (" << limits.global << " waiting overall, " << limits.per_account
                             << " per account, " << limits.per_address << " per client address, at most "
                             << limits.max_in_window << " pushes per " << limits.window.count() / 1000
                             << " s and one per " << limits.min_spacing.count() / 1000 << " s per account)";
          return {factor_step_t::state_e::denied, {},
                  std::string {"DUO sign-in refused: "} + factor_wait::refusal_name(admission.refusal) + " limit",
                  factor_wait::refusal_user_message(admission.refusal)};
        }
        if (admission.superseded > 0) {
          BOOST_LOG(info) << "DUO push restarted from the same account and address; " << admission.superseded
                          << " older push(es) cancelled";
        }
        exchange_ = admission.approval;
        try {
          std::thread(run, exchange_, duo_username(username), std::string {remote_host}, failmode_,
                      config::plank_auth.duo_integration_key, config::plank_auth.duo_secret_key,
                      config::plank_auth.duo_api_host, admission.id)
            .detach();
        } catch (const std::system_error &e) {
          exchange_->cancel();
          duo_pushes().finish(admission.id);
          exchange_.reset();
          return {factor_step_t::state_e::denied, {}, std::string {"DUO worker could not start: "} + e.what(),
                  "DUO could not be reached, so sign-in was refused."};
        }
        return wait_round();
      }

      factor_step_t respond(std::vector<std::string>) override {
        if (!exchange_) {
          return {factor_step_t::state_e::denied, {}, "no DUO transaction in progress"};
        }
        return wait_round();
      }

    private:
      /// Wait for the worker, but end the round before the client's 5 s request timeout.
      factor_step_t wait_round() {
        const auto budget = factor_wait::round_budget(config::plank_auth.second_factor_round_wait_ms);
        const auto result = exchange_->wait_until(round_started_ + budget);
        switch (result.state) {
          case approval_e::approved:
            return {factor_step_t::state_e::approved, {}, result.detail, result.user_message};
          case approval_e::denied:
            return {factor_step_t::state_e::denied, {}, result.detail, result.user_message};
          case approval_e::waiting:
          default:
            return {factor_step_t::state_e::challenge,
                    {prompt_t {prompt_style_text_info, result.message}}, "waiting for DUO"};
        }
      }

      static void finish(duo_exchange_t &exchange, factor_step_t::state_e state, std::string detail,
                         std::string user_message = {}) {
        exchange.settle(state == factor_step_t::state_e::approved ? approval_e::approved : approval_e::denied,
                        std::move(detail), std::move(user_message));
      }

      static void progress(duo_exchange_t &exchange, std::string message) {
        exchange.progress(std::move(message));
      }

      static void unreachable(duo_exchange_t &exchange, factor_failmode_e failmode,
                              const std::string &username, const std::string &reason) {
        BOOST_LOG(error) << "DUO unavailable for " << username << ": " << reason;
        if (failmode == factor_failmode_e::allow) {
          BOOST_LOG(warning) << "security.second_factor_failmode=allow: accepting " << username
                             << " on password alone because DUO is unreachable";
          finish(exchange, factor_step_t::state_e::approved, "DUO unreachable; failmode allow");
          return;
        }
        finish(exchange, factor_step_t::state_e::denied, "DUO unreachable: " + reason,
               "DUO could not be reached, so sign-in was refused.");
      }

      static void run(std::shared_ptr<duo_exchange_t> exchange, std::string username, std::string remote_host,
                      factor_failmode_e failmode, std::string ikey, std::string skey, std::string host,
                      std::uint64_t admission_id) {
        const worker_slot_guard_t slot {admission_id};  // admitted by begin()
        platf::set_thread_name("duo-auth");
        const duo_client_t client {std::move(ikey), std::move(skey), std::move(host)};
        std::map<std::string, std::string> params {{"username", username}};
        if (!remote_host.empty()) {
          params.emplace("ipaddr", remote_host);
        }

        const auto device_key = trusted_device_store_t::key(username, remote_host);
        const auto trusted_token = trusted_device_store_t::get(device_key);
        auto preauth_params = params;
        if (!trusted_token.empty()) {
          preauth_params.emplace("trusted_device_token", trusted_token);
        }

        std::string reason;
        const auto preauth = duo_response(client.call("POST", "/auth/v2/preauth", preauth_params, 8s), reason);
        if (!preauth) {
          unreachable(*exchange, failmode, username, reason);
          return;
        }
        const auto result = preauth->value("result", "");
        const auto message = preauth->value("status_msg", "");
        if (result == "allow") {
          if (!trusted_token.empty()) {
            BOOST_LOG(info) << "DUO remembered device for " << username << " from " << remote_host << ": " << message;
            finish(*exchange, factor_step_t::state_e::approved, "DUO remembered device: " + message);
          } else {
            BOOST_LOG(warning) << "DUO allowed " << username << " without a second factor: " << message;
            finish(*exchange, factor_step_t::state_e::approved, "DUO preauth allow: " + message);
          }
          return;
        }
        if (!trusted_token.empty()) {
          trusted_device_store_t::put(device_key, {});  // expired or revoked
        }
        if (result != "auth") {
          // deny or enroll: never fall through to password-only.
          finish(*exchange, factor_step_t::state_e::denied, "DUO preauth " + result + ": " + message,
                 result == "enroll" ? "This account is not enrolled in DUO. Enroll, then sign in again." :
                                      "DUO denied this sign-in.");
          return;
        }

        std::string device;
        std::string device_name;
        for (const auto &entry : preauth->value("devices", nlohmann::json::array())) {
          const auto capabilities = entry.value("capabilities", nlohmann::json::array());
          if (std::find(capabilities.begin(), capabilities.end(), "push") != capabilities.end()) {
            device = entry.value("device", "");
            device_name = entry.value("display_name", "your device");
            break;
          }
        }
        if (device.empty()) {
          finish(*exchange, factor_step_t::state_e::denied,
                 "DUO user " + username + " has no push-capable device; passcode entry is not supported by the PLANK client",
                 "This account has no DUO Mobile device for push approval.");
          return;
        }

        if (exchange->cancelled()) {
          // Superseded or abandoned before the push went out: send nothing.
          finish(*exchange, factor_step_t::state_e::denied, "DUO exchange abandoned",
                 "The DUO push was not approved in time.");
          return;
        }
        params.emplace("factor", "push");
        params.emplace("device", device);
        params.emplace("async", "1");
        // type replaces the push title; pushinfo adds form-encoded detail rows.
        const auto computer = config::nvhttp.host_name;
        params.emplace("type", "PLANK login to " + computer);
        params.emplace("pushinfo", "Computer=" + duo_encode(computer) +
                                     (remote_host.empty() ? "" : "&From=" + duo_encode(remote_host)));
        const auto auth = duo_response(client.call("POST", "/auth/v2/auth", params, 8s), reason);
        if (!auth || auth->value("txid", "").empty()) {
          unreachable(*exchange, failmode, username, auth ? "DUO did not return a transaction id" : reason);
          return;
        }
        const auto txid = auth->value("txid", "");
        BOOST_LOG(info) << "DUO push sent for " << username << " to " << device_name << "; sign-in rounds wait up to "
                        << factor_wait::round_budget(config::plank_auth.second_factor_round_wait_ms).count() << " ms";
        progress(*exchange, "DUO push sent to " + device_name + ". Approve it to continue.");

        const auto deadline = std::chrono::steady_clock::now() + push_deadline;
        while (!exchange->cancelled() && std::chrono::steady_clock::now() < deadline) {
          const auto http = client.call("GET", "/auth/v2/auth_status", {{"txid", txid}}, 15s);
          if (http.timed_out) {
            continue;  // long poll expired without a decision
          }
          const auto status = duo_response(http, reason);
          if (!status) {
            unreachable(*exchange, failmode, username, reason);
            return;
          }
          const auto state = status->value("result", "");
          const auto status_msg = status->value("status_msg", "");
          if (state == "allow") {
            // Present only when DUO policy enables Remembered Devices.
            if (const auto token = status->value("trusted_device_token", ""); !token.empty()) {
              trusted_device_store_t::put(device_key, token);
            }
            finish(*exchange, factor_step_t::state_e::approved, "DUO push approved: " + status_msg);
            return;
          }
          if (state == "deny") {
            finish(*exchange, factor_step_t::state_e::denied,
                   "DUO denied: " + status->value("status", "") + " " + status_msg,
                   status_msg.empty() ? "The DUO push was denied." : "DUO: " + status_msg);
            return;
          }
          if (!status_msg.empty()) {
            progress(*exchange, status_msg);
          }
          std::this_thread::sleep_for(1s);
        }
        finish(*exchange, factor_step_t::state_e::denied,
               exchange->cancelled() ? "DUO exchange abandoned" : "DUO push timed out",
               "The DUO push was not approved in time.");
      }

      factor_failmode_e failmode_;
      std::shared_ptr<duo_exchange_t> exchange_;
    };
  }  // namespace

  std::unique_ptr<second_factor_t> make_duo_provider(factor_failmode_e failmode, std::string &error_message) {
    const auto &cfg = config::plank_auth;
    if (cfg.duo_integration_key.empty() || cfg.duo_secret_key.empty() || cfg.duo_api_host.empty()) {
      error_message = "security.second_factor=duo requires duo_integration_key, duo_secret_key and duo_api_host";
      BOOST_LOG(error) << error_message;
      return nullptr;
    }
    return std::make_unique<duo_provider_t>(failmode);
  }
}  // namespace plank::auth
