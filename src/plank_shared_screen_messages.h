/**
 * @file src/plank_shared_screen_messages.h
 * @brief Wire format of the PLANK shared screen event (consent, watchers, control).
 *
 * One native event type carries a small UTF-8 JSON object whose "t" field
 * names the message. Like clipboard text (event 5) it is not in the shared
 * transport header: it is sent only to clients that set the shared screen
 * feature bit on their launch, so older clients never see it.
 */
#pragma once

// standard includes
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// lib includes
#include <nlohmann/json.hpp>

namespace plank::shared_screen::messages {
  /// Native event type for shared screen messages, both directions.
  constexpr std::uint16_t event_type = 6;

  /// Largest message either side accepts.
  constexpr std::size_t max_message_bytes = 4096;

  /// Seconds the owner has to answer a watch or control request; silence is a refusal.
  constexpr int answer_timeout_seconds = 30;

  /**
   * @brief One entry of the watchers list shown to the controller.
   */
  struct watcher_t {
    std::uint32_t id {};  ///< Host-assigned viewer id.
    std::string account;  ///< Account the viewer signed in as.
    bool control {};  ///< The viewer currently holds the mouse and keyboard.
  };

  /**
   * @brief Messages a client may send to the host.
   */
  enum class client_type_e {
    join_answer,  ///< Controller: allow or deny a watch request {id, allow}.
    kick,  ///< Controller: disconnect a viewer {id}.
    control_answer,  ///< Controller: allow or deny a control request {id, allow}.
    take_back,  ///< Controller: take the mouse and keyboard back.
    control_request,  ///< Viewer: ask the owner for the mouse and keyboard.
    control_release,  ///< Viewer: give the mouse and keyboard back.
  };

  /**
   * @brief A decoded client message.
   */
  struct client_message_t {
    client_type_e type {};  ///< Message type.
    std::uint32_t id {};  ///< Request or viewer id, when the type has one.
    bool allow {};  ///< Answer, for join_answer and control_answer.
  };

  /**
   * @brief Serialize a JSON message.
   *
   * @param message JSON object.
   * @return Compact UTF-8 bytes.
   */
  inline std::string dump(const nlohmann::json &message) {
    return message.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  }

  /**
   * @brief Host to controller: someone asks to watch.
   *
   * @param id Request id.
   * @param account Requesting account.
   * @return Encoded message.
   */
  inline std::string join_request(const std::uint32_t id, const std::string_view account) {
    return dump({{"t", "join_request"}, {"id", id}, {"account", std::string {account}}});
  }

  /**
   * @brief Host to controller: a pending request ended without an answer.
   *
   * @param id Request id.
   * @return Encoded message.
   */
  inline std::string request_cancel(const std::uint32_t id) {
    return dump({{"t", "request_cancel"}, {"id", id}});
  }

  /**
   * @brief Host to controller: a viewer asks for the mouse and keyboard.
   *
   * @param id Viewer id.
   * @param account Viewer account.
   * @return Encoded message.
   */
  inline std::string control_request(const std::uint32_t id, const std::string_view account) {
    return dump({{"t", "control_request"}, {"id", id}, {"account", std::string {account}}});
  }

  /**
   * @brief Host to controller: everyone watching right now (admins are never listed).
   *
   * @param watchers Visible viewers.
   * @return Encoded message.
   */
  inline std::string watchers(const std::vector<watcher_t> &watchers) {
    auto list = nlohmann::json::array();
    for (const auto &watcher : watchers) {
      list.push_back({{"id", watcher.id}, {"account", watcher.account}, {"control", watcher.control}});
    }
    return dump({{"t", "watchers"}, {"viewers", std::move(list)}});
  }

  /**
   * @brief Host to any client: whether its input now reaches the desktop.
   *
   * @param has_control True when this client holds the mouse and keyboard.
   * @param reason Why it changed: "granted", "denied", "taken_back", "released" or "returned".
   * @return Encoded message.
   */
  inline std::string control_state(const bool has_control, const std::string_view reason) {
    return dump({{"t", "control_state"}, {"has_control", has_control}, {"reason", std::string {reason}}});
  }

  /**
   * @brief Decode a client message.
   *
   * @param bytes Event payload.
   * @return The message, or no value when it is malformed or unknown.
   */
  inline std::optional<client_message_t> parse_client(const std::string_view bytes) {
    if (bytes.empty() || bytes.size() > max_message_bytes) {
      return std::nullopt;
    }
    const auto json = nlohmann::json::parse(bytes, nullptr, false);
    if (!json.is_object() || !json.contains("t") || !json["t"].is_string()) {
      return std::nullopt;
    }
    const auto type = json["t"].get<std::string>();
    const auto read_id = [&json](client_message_t &message) {
      if (!json.contains("id") || !json["id"].is_number_unsigned()) {
        return false;
      }
      const auto id = json["id"].get<std::uint64_t>();
      if (id == 0 || id > UINT32_MAX) {
        return false;
      }
      message.id = static_cast<std::uint32_t>(id);
      return true;
    };
    const auto read_allow = [&json](client_message_t &message) {
      if (!json.contains("allow") || !json["allow"].is_boolean()) {
        return false;
      }
      message.allow = json["allow"].get<bool>();
      return true;
    };

    client_message_t message;
    if (type == "join_answer" || type == "control_answer") {
      message.type = type == "join_answer" ? client_type_e::join_answer : client_type_e::control_answer;
      if (!read_id(message) || !read_allow(message)) {
        return std::nullopt;
      }
      return message;
    }
    if (type == "kick") {
      message.type = client_type_e::kick;
      if (!read_id(message)) {
        return std::nullopt;
      }
      return message;
    }
    if (type == "take_back") {
      message.type = client_type_e::take_back;
      return message;
    }
    if (type == "control_request") {
      message.type = client_type_e::control_request;
      return message;
    }
    if (type == "control_release") {
      message.type = client_type_e::control_release;
      return message;
    }
    return std::nullopt;
  }

  /**
   * @brief Whether a client message may come from this role.
   *
   * @param type Message type.
   * @param from_viewer True when the sender is a viewer, false for the controller.
   * @return True when that role may send it.
   */
  inline bool allowed_from(const client_type_e type, const bool from_viewer) {
    switch (type) {
      case client_type_e::control_request:
      case client_type_e::control_release:
        return from_viewer;
      case client_type_e::join_answer:
      case client_type_e::kick:
      case client_type_e::control_answer:
      case client_type_e::take_back:
        return !from_viewer;
    }
    return false;
  }

  /**
   * @brief Whether an owner input message should take control back.
   *
   * The owner reclaims the desktop with any key or button press; plain
   * pointer motion does not, so a nudged mouse does not end a demonstration.
   *
   * @param input_type KyProto input type.
   * @param payload Input payload.
   * @param payload_size Payload size.
   * @param keyboard_type KyProto keyboard type value.
   * @param button_type KyProto mouse-button type value.
   * @param press KyProto press action value.
   * @return True for a key or mouse-button press.
   */
  inline bool owner_input_reclaims(const std::uint8_t input_type, const std::uint8_t *payload, const std::size_t payload_size, const std::uint8_t keyboard_type, const std::uint8_t button_type, const std::uint8_t press) {
    if (input_type == button_type) {
      return payload_size >= 2 && payload[1] == press;
    }
    if (input_type == keyboard_type) {
      return payload_size >= 3 && payload[2] == press;
    }
    return false;
  }
}  // namespace plank::shared_screen::messages
