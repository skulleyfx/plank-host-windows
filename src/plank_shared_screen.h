/**
 * @file src/plank_shared_screen.h
 * @brief Pure decision logic for PLANK shared screen: roles, viewer admission,
 *        consent, and the single control token.
 *
 * Nothing here touches Windows, the transport or the encoder, so every rule is
 * unit-testable. The host wiring lives in nvhttp.cpp, session_stream.cpp and
 * stream.cpp.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace plank::shared_screen {
  /// Client and host PLANK feature bit for shared screen. High bit, clear of
  /// the Linux host's 0x2000000 and the Mac bits.
  constexpr std::uint32_t feature_shared_screen = 0x40000000;

  /// Launch query argument naming the requested role.
  constexpr std::string_view role_argument = "plankSessionRole";

  /**
   * @brief Role of one streaming session on the host.
   */
  enum class role_e {
    controller,  ///< Owns capture, encoder and input; at most one per host.
    viewer,  ///< Receives the controller's stream; input is never applied.
  };

  /**
   * @brief Parse the plankSessionRole launch argument.
   *
   * @param value Argument value; empty when the argument was not sent.
   * @return The role, or no value when the argument is malformed.
   */
  inline std::optional<role_e> parse_role(const std::string_view value) {
    if (value.empty() || value == "controller") {
      return role_e::controller;
    }
    if (value == "viewer") {
      return role_e::viewer;
    }
    return std::nullopt;
  }

  /**
   * @brief Name of a role for logs and launch responses.
   *
   * @param role Role to name.
   * @return Lower-case role name.
   */
  inline std::string_view role_name(const role_e role) {
    return role == role_e::viewer ? "viewer" : "controller";
  }

  /**
   * @brief Stream parameters a viewer must share with its controller.
   */
  struct stream_shape_t {
    int width {};  ///< Encoded width.
    int height {};  ///< Encoded height.
    int fps {};  ///< Encoded frame rate.
    int video_format {};  ///< 0 H.264, 1 HEVC.
    int dynamic_range {};  ///< 0 8-bit, 1 10-bit.
    int chroma {};  ///< Chroma sampling type.
    int encoder_csc_mode {};  ///< Colorspace and range.
    int audio_channels {};  ///< Opus channel count.
    int audio_packet_duration {};  ///< Opus packet duration in ms.
    bool high_quality_audio {};  ///< High-quality Opus layout.
  };

  /**
   * @brief Name the first parameter where a viewer differs from the controller.
   *
   * @param controller The running controller's stream.
   * @param viewer The viewer's native setup request.
   * @return Empty when they match, otherwise the differing field.
   */
  inline std::string_view shape_mismatch(const stream_shape_t &controller, const stream_shape_t &viewer) {
    if (controller.width != viewer.width || controller.height != viewer.height) {
      return "resolution";
    }
    if (controller.fps != viewer.fps) {
      return "frame rate";
    }
    if (controller.video_format != viewer.video_format ||
        controller.dynamic_range != viewer.dynamic_range ||
        controller.chroma != viewer.chroma ||
        controller.encoder_csc_mode != viewer.encoder_csc_mode) {
      return "video format";
    }
    if (controller.audio_channels != viewer.audio_channels ||
        controller.audio_packet_duration != viewer.audio_packet_duration ||
        controller.high_quality_audio != viewer.high_quality_audio) {
      return "audio format";
    }
    return {};
  }

  /**
   * @brief Everything the host knows when a client asks to join as a viewer.
   */
  struct admission_input_t {
    bool enabled {};  ///< host.conf shared_screen.
    bool protocol_matches {};  ///< plankProtocolVersion is the host's version.
    std::uint32_t client_features {};  ///< plankFeatureFlags from the launch.
    bool controller_running {};  ///< A controller stream is running.
    int viewer_count {};  ///< Viewers already attached.
    int max_viewers {};  ///< host.conf shared_screen_max_viewers.
    bool launch_matches {};  ///< Mode, encoding mode, capture source and backend match the controller.
  };

  /**
   * @brief HTTP status and message for a viewer admission decision.
   */
  struct admission_t {
    int status {};  ///< 200 when admitted, otherwise the HTTP-style error code.
    std::string_view message;  ///< Status message; empty when admitted.

    /**
     * @brief Whether the viewer was admitted.
     * @return True for status 200.
     */
    bool admitted() const {
      return status == 200;
    }
  };

  /**
   * @brief Decide whether a viewer join may proceed (after the desktop auth gate).
   *
   * @param input Facts gathered by the launch handler.
   * @return 200, or the refusal to return to the client.
   */
  inline admission_t admit_viewer(const admission_input_t &input) {
    if (!input.enabled) {
      return {403, "Shared screen is off on this workstation"};
    }
    if (!input.protocol_matches || (input.client_features & feature_shared_screen) == 0) {
      return {400, "Invalid PLANK shared screen request"};
    }
    if (!input.controller_running) {
      return {409, "There is no PLANK session to watch"};
    }
    if (input.viewer_count >= input.max_viewers) {
      return {409, "The shared screen viewer limit has been reached"};
    }
    if (!input.launch_matches) {
      return {409, "Shared screen settings differ from the active stream"};
    }
    return {200, {}};
  }

  /**
   * @brief How the desktop owner's consent applies to a join.
   */
  enum class consent_e {
    refuse,  ///< Not allowed at all.
    admit,  ///< Same account as the desktop owner: no prompt.
    admit_admin_silently,  ///< PLANK admin using the desktop override: no prompt, one log line.
    ask_owner,  ///< Show Allow/Deny to the person at the host.
  };

  /**
   * @brief Decide how a viewer join is consented.
   *
   * @param enabled host.conf shared_screen.
   * @param same_account The requester is the account signed in at the desktop.
   * @param admin_override The requester is a PLANK admin and admin_desktop_override is on.
   * @param approval_available The host can show an Allow/Deny prompt (slice 2).
   * @return The consent path.
   */
  inline consent_e decide_consent(const bool enabled, const bool same_account, const bool admin_override, const bool approval_available) {
    if (!enabled) {
      return consent_e::refuse;
    }
    if (same_account) {
      return consent_e::admit;
    }
    if (admin_override) {
      return consent_e::admit_admin_silently;
    }
    return approval_available ? consent_e::ask_owner : consent_e::refuse;
  }

  /**
   * @brief The one host log line for an admin observe or takeover.
   *
   * @param account Admin account.
   * @param action "observe" or "takeover".
   * @param started True when it starts, false when it ends.
   * @return Log text.
   */
  inline std::string admin_audit_line(const std::string_view account, const std::string_view action, const bool started) {
    std::string line = "PLANK admin ";
    line += action;
    line += ": ";
    line += account;
    line += started ? " started" : " ended";
    return line;
  }

  /**
   * @brief Rate limit for keyframes a viewer may force on the controller's encoder.
   *
   * @param last When this viewer last forced one; default-constructed for never.
   * @param now Current time.
   * @param minimum_interval Shortest gap between forced keyframes.
   * @return True when another keyframe may be forced now.
   */
  inline bool keyframe_request_allowed(const std::chrono::steady_clock::time_point last, const std::chrono::steady_clock::time_point now, const std::chrono::steady_clock::duration minimum_interval) {
    return last == std::chrono::steady_clock::time_point {} || now - last >= minimum_interval;
  }

  /**
   * @brief Keys and mouse buttons one input source is holding down on the host.
   *
   * When control moves away from a source, everything it still holds is
   * released on the host, so a key pressed at the moment of hand-off cannot
   * stay down. Works on raw KyProto payloads; the type and action values are
   * the transport's (checked against its header where it is available).
   */
  class held_input_t {
  public:
    static constexpr std::uint8_t mouse_button_type = 2;  ///< KyProto mouse button.
    static constexpr std::uint8_t keyboard_type = 5;  ///< KyProto keyboard.
    static constexpr std::uint8_t press = 1;  ///< KyProto press action.
    static constexpr std::uint8_t release = 0;  ///< KyProto release action.

    /**
     * @brief One synthetic release to inject.
     */
    struct release_t {
      std::uint8_t type {};  ///< KyProto input type.
      std::vector<std::uint8_t> payload;  ///< KyProto payload.
    };

    /**
     * @brief Note an input message that was applied to the desktop.
     *
     * @param type KyProto input type.
     * @param payload Payload.
     * @param size Payload size.
     */
    void record(const std::uint8_t type, const std::uint8_t *payload, const std::size_t size) {
      if (type == mouse_button_type && size >= 2) {
        if (payload[1] == press) {
          buttons_.insert(payload[0]);
        } else if (payload[1] == release) {
          buttons_.erase(payload[0]);
        }
      } else if (type == keyboard_type && size >= 5) {
        const auto code = static_cast<std::uint16_t>((payload[0] << 8) | payload[1]);
        if (payload[2] == press) {
          keys_[code] = payload[4];
        } else if (payload[2] == release) {
          keys_.erase(code);
        }
      }
    }

    /**
     * @brief Releases for everything held, and forget it.
     *
     * @return Messages to inject, keys first.
     */
    std::vector<release_t> take_releases() {
      std::vector<release_t> releases;
      for (const auto &[code, flags] : keys_) {
        releases.push_back({keyboard_type, {static_cast<std::uint8_t>(code >> 8), static_cast<std::uint8_t>(code & 0xFF), release, 0, flags}});
      }
      for (const auto button : buttons_) {
        releases.push_back({mouse_button_type, {button, release}});
      }
      keys_.clear();
      buttons_.clear();
      return releases;
    }

    /**
     * @brief Whether nothing is held.
     * @return True when no key or button is down.
     */
    bool empty() const {
      return keys_.empty() && buttons_.empty();
    }

  private:
    std::map<std::uint16_t, std::uint8_t> keys_;  ///< Held key code to its flags byte.
    std::set<std::uint8_t> buttons_;  ///< Held mouse buttons.
  };

  /**
   * @brief Counts one viewer's keyframe requests to drop a viewer that keeps asking.
   */
  class keyframe_budget_t {
  public:
    /**
     * @brief Count a request and say whether the viewer is still within budget.
     *
     * @param now Current time.
     * @param window Counting window.
     * @param limit Most requests allowed in one window.
     * @return False once the viewer has asked more than limit times in one window.
     */
    bool allow(const std::chrono::steady_clock::time_point now, const std::chrono::steady_clock::duration window, const int limit) {
      if (count_ == 0 || now - window_start_ >= window) {
        window_start_ = now;
        count_ = 0;
      }
      return ++count_ <= limit;
    }

  private:
    std::chrono::steady_clock::time_point window_start_ {};  ///< Start of the current window.
    int count_ {};  ///< Requests in the current window.
  };

  /**
   * @brief Single control token shared by the sessions of one host.
   *
   * Exactly one session holds control at any time. The owner (the desktop's
   * controller) can always take it back. Session ids are the host's own
   * opaque identifiers; 0 means none.
   */
  class control_token_t {
  public:
    using id_t = std::uint64_t;  ///< Session identifier; 0 is none.

    /**
     * @brief Result of a token operation.
     */
    enum class result_e {
      ok,  ///< Applied.
      not_allowed,  ///< The caller may not do this.
      busy,  ///< Another request is already pending.
      nothing_pending,  ///< No request to answer.
    };

    /**
     * @brief Start a share owned by a controller session.
     * @param owner Owner session id.
     */
    explicit control_token_t(const id_t owner):
        owner_ {owner},
        holder_ {owner} {
    }

    /**
     * @brief Owner session id.
     * @return Owner id, 0 after the owner left.
     */
    id_t owner() const {
      return owner_;
    }

    /**
     * @brief Session currently holding control.
     * @return Holder id, 0 when nobody holds it.
     */
    id_t holder() const {
      return holder_;
    }

    /**
     * @brief Session waiting for the owner's answer.
     * @return Pending requester id, or 0.
     */
    id_t pending() const {
      return pending_;
    }

    /**
     * @brief Whether input from this session may reach the desktop.
     * @param session Session id.
     * @return True only for the holder.
     */
    bool accepts_input(const id_t session) const {
      return session != 0 && session == holder_;
    }

    /**
     * @brief A viewer asks the owner for control.
     * @param viewer Requesting session.
     * @return ok, busy when another request is open, not_allowed for the holder or owner.
     */
    result_e request(const id_t viewer) {
      if (viewer == 0 || viewer == owner_ || viewer == holder_ || owner_ == 0) {
        return result_e::not_allowed;
      }
      if (pending_ != 0 && pending_ != viewer) {
        return result_e::busy;
      }
      pending_ = viewer;
      return result_e::ok;
    }

    /**
     * @brief The owner allows the pending request; control moves to the requester.
     * @param by Session answering.
     * @return ok, not_allowed unless the owner answers, nothing_pending without a request.
     */
    result_e grant(const id_t by) {
      if (by == 0 || by != owner_) {
        return result_e::not_allowed;
      }
      if (pending_ == 0) {
        return result_e::nothing_pending;
      }
      holder_ = pending_;
      pending_ = 0;
      return result_e::ok;
    }

    /**
     * @brief The owner declines the pending request.
     * @param by Session answering.
     * @return ok, not_allowed unless the owner answers, nothing_pending without a request.
     */
    result_e deny(const id_t by) {
      if (by == 0 || by != owner_) {
        return result_e::not_allowed;
      }
      if (pending_ == 0) {
        return result_e::nothing_pending;
      }
      pending_ = 0;
      return result_e::ok;
    }

    /**
     * @brief The owner takes control back; always wins and clears any request.
     * @param by Session asking.
     * @return ok, or not_allowed for anyone but the owner.
     */
    result_e take_back(const id_t by) {
      if (by == 0 || by != owner_) {
        return result_e::not_allowed;
      }
      holder_ = owner_;
      pending_ = 0;
      return result_e::ok;
    }

    /**
     * @brief An admin takes control silently, without a request.
     * @param admin Admin session.
     * @return ok, or not_allowed for id 0.
     */
    result_e admin_takeover(const id_t admin) {
      if (admin == 0) {
        return result_e::not_allowed;
      }
      holder_ = admin;
      if (pending_ == admin) {
        pending_ = 0;
      }
      return result_e::ok;
    }

    /**
     * @brief A session disconnected.
     *
     * The holder leaving returns control to the owner; the owner leaving ends
     * the share (no holder, no owner).
     *
     * @param session Session that left.
     */
    void leave(const id_t session) {
      if (session == 0) {
        return;
      }
      if (pending_ == session) {
        pending_ = 0;
      }
      if (session == owner_) {
        owner_ = 0;
        holder_ = 0;
        pending_ = 0;
        return;
      }
      if (session == holder_) {
        holder_ = owner_;
      }
    }

  private:
    id_t owner_ {};
    id_t holder_ {};
    id_t pending_ {};
  };
}  // namespace plank::shared_screen
