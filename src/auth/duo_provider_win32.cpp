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
 * awaited in short rounds of informational challenges because each client
 * request times out after five seconds.
 */

#include "second_factor.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <format>
#include <map>
#include <optional>
#include <thread>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "src/config.h"
#include "src/logging.h"

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
  #define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

using namespace std::literals;

namespace plank::auth {
  namespace {
    constexpr std::int32_t prompt_style_text_info = 4;  ///< PAM_TEXT_INFO.

    /// Longest a single client round may spend waiting; the client gives up at 5 s.
    constexpr auto poll_round_budget = 3s;
    /// DUO expires a push after about a minute.
    constexpr auto push_deadline = 70s;

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
      }

      ~duo_client_t() {
        SecureZeroMemory(skey_.data(), skey_.size());
      }

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
        const HINTERNET session = WinHttpOpen(L"PLANK-Host-Duo/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) {
          result.error = std::format("WinHttpOpen failed ({})", GetLastError());
          return result;
        }
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
          protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;  // TLS 1.3 unavailable on older Windows
          WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
        }
        const int ms = static_cast<int>(timeout.count());
        WinHttpSetTimeouts(session, ms, ms, ms, ms);

        const HINTERNET connection = WinHttpConnect(session, widen(host_).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        const std::wstring target = widen(std::string {path} + (query.empty() ? "" : "?" + query));
        const HINTERNET request = connection ?
                                    WinHttpOpenRequest(connection, widen(method).c_str(), target.c_str(), nullptr,
                                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) :
                                    nullptr;
        if (request) {
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
        WinHttpCloseHandle(session);
        return result;
      }

    private:
      std::string ikey_;
      std::string skey_;
      std::string host_;
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

    class duo_provider_t final: public second_factor_t {
    public:
      duo_provider_t(factor_failmode_e failmode):
          failmode_ {failmode},
          client_ {config::plank_auth.duo_integration_key, config::plank_auth.duo_secret_key,
                   config::plank_auth.duo_api_host} {
      }

      factor_step_t begin(std::string_view username, std::string_view remote_host) override {
        username_ = duo_username(username);
        std::map<std::string, std::string> params {{"username", username_}};
        if (!remote_host.empty()) {
          params.emplace("ipaddr", std::string {remote_host});
        }

        std::string reason;
        const auto preauth = duo_response(client_.call("POST", "/auth/v2/preauth", params, 4s), reason);
        if (!preauth) {
          return unreachable(reason);
        }

        const auto result = preauth->value("result", "");
        const auto message = preauth->value("status_msg", "");
        if (result == "allow") {
          BOOST_LOG(warning) << "DUO allowed " << username_ << " without a second factor: " << message;
          return {factor_step_t::state_e::approved, {}, "DUO preauth allow: " + message};
        }
        if (result != "auth") {
          // deny or enroll: never fall through to password-only.
          return {factor_step_t::state_e::denied, {}, "DUO preauth " + result + ": " + message};
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
          return {factor_step_t::state_e::denied, {},
                  "DUO user " + username_ + " has no push-capable device; passcode entry is not supported by the PLANK client"};
        }

        params.emplace("factor", "push");
        params.emplace("device", device);
        params.emplace("async", "1");
        params.emplace("type", "PLANK login");
        const auto auth = duo_response(client_.call("POST", "/auth/v2/auth", params, 4s), reason);
        if (!auth || auth->value("txid", "").empty()) {
          return unreachable(auth ? "DUO did not return a transaction id" : reason);
        }
        txid_ = auth->value("txid", "");
        deadline_ = std::chrono::steady_clock::now() + push_deadline;
        BOOST_LOG(info) << "DUO push sent for " << username_ << " to " << device_name;
        return waiting("DUO push sent to " + device_name + ". Approve it to continue.");
      }

      factor_step_t respond(std::vector<std::string>) override {
        if (txid_.empty()) {
          return {factor_step_t::state_e::denied, {}, "no DUO transaction in progress"};
        }
        const auto round_end = std::chrono::steady_clock::now() + poll_round_budget;
        std::string last_message = "Waiting for DUO approval.";
        while (std::chrono::steady_clock::now() < round_end) {
          if (std::chrono::steady_clock::now() >= deadline_) {
            return {factor_step_t::state_e::denied, {}, "DUO push timed out"};
          }
          const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(round_end - std::chrono::steady_clock::now());
          const auto http = client_.call("GET", "/auth/v2/auth_status", {{"txid", txid_}},
                                         std::max(remaining, std::chrono::milliseconds {500}));
          if (http.timed_out) {
            break;  // long poll still open; ask again next round
          }
          std::string reason;
          const auto status = duo_response(http, reason);
          if (!status) {
            return unreachable(reason);
          }
          const auto result = status->value("result", "");
          last_message = status->value("status_msg", last_message);
          if (result == "allow") {
            return {factor_step_t::state_e::approved, {}, "DUO push approved: " + last_message};
          }
          if (result == "deny") {
            return {factor_step_t::state_e::denied, {}, "DUO denied: " + status->value("status", "") + " " + last_message};
          }
          std::this_thread::sleep_for(500ms);
        }
        return waiting(last_message);
      }

    private:
      static factor_step_t waiting(std::string message) {
        return {factor_step_t::state_e::challenge, {prompt_t {prompt_style_text_info, message}}, "waiting for DUO"};
      }

      factor_step_t unreachable(const std::string &reason) const {
        BOOST_LOG(error) << "DUO unavailable for " << username_ << ": " << reason;
        if (failmode_ == factor_failmode_e::allow) {
          BOOST_LOG(warning) << "security.second_factor_failmode=allow: accepting " << username_
                             << " on password alone because DUO is unreachable";
          return {factor_step_t::state_e::approved, {}, "DUO unreachable; failmode allow"};
        }
        return {factor_step_t::state_e::denied, {}, "DUO unreachable: " + reason};
      }

      factor_failmode_e failmode_;
      duo_client_t client_;
      std::string username_;
      std::string txid_;
      std::chrono::steady_clock::time_point deadline_ {};
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
