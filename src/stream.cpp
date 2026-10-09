/**
 * @file src/stream.cpp
 * @brief Definitions for the streaming protocols.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>

// lib includes
extern "C" {
  // clang-format off
#include <moonlight-common-c/src/plank.h>
  // clang-format on
}

// local includes
#include "config.h"
#include "clipboard_protocol.h"
#include "display_device.h"
#include "globals.h"
#include "input.h"
#include "logging.h"
#include "platform/common.h"
#include "process.h"
#include "raw_hid_tablet.h"
#include "session_stream.h"
#include "auth/second_factor.h"
#include "session/clipboard.h"
#include "session/session_context.h"
#include "stream.h"
#include "plank_bitrate.h"
#include "plank_shared_screen_messages.h"
#include "plank_topology.h"
#include "sync.h"
#include "thread_safe.h"
#include "utility.h"

#ifdef PLANK_TRANSPORT
  #include <plank_transport.h>
  #include <plank_transport_control.h>
  #include <plank_transport_event.h>
  #include <plank_transport_input.h>
#endif

#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  #include "platform/linux/graphics.h"
  #include "platform/linux/x11grab.h"
  #include "platform/linux/x11_clipboard.h"
#endif

#ifdef PLANK_TRANSPORT
constexpr int PLANK_TRANSPORT_CONTROL_DRAIN_LIMIT = 16;
#endif

using namespace std::literals;

namespace stream {

  static inline void while_starting_do_nothing(std::atomic<session::state_e> &state) {
    while (state.load(std::memory_order_acquire) == session::state_e::STARTING) {
      std::this_thread::sleep_for(1ms);
    }
  }

  /**
   * @brief Process-wide native media/control worker state.
   */
  struct broadcast_ctx_t {
    std::jthread video_thread;  ///< Thread that sends encoded video packets.
    std::jthread audio_thread;  ///< Thread that sends encoded audio packets.
    std::jthread control_thread;  ///< Thread that runs native control and event delivery.
    sync_util::sync_t<std::vector<session_t *>> sessions;  ///< Active native sessions.
    sync_util::sync_t<std::vector<session_t *>> viewers;  ///< View-only sessions fed by a controller's encoder.
  };

  /// Viewers attached to any controller; lets the media threads skip the
  /// fan-out lock entirely when nobody is watching.
  static std::atomic_uint attached_viewers {0};

  /// Shortest gap between keyframes one viewer may force on the shared encoder.
  constexpr auto viewer_keyframe_interval = 1s;

  /// Control-token id of a controller itself; viewer ids are 32-bit and never collide.
  constexpr std::uint64_t owner_token_id = 1ULL << 32;

  /// Next host-assigned viewer id.
  static std::atomic_uint32_t next_viewer_id {0};

  /**
   * @brief Runtime state for one audio/video streaming session.
   */
  struct session_t {
    config_t config;  ///< Stream or encoder configuration captured for the worker.

    safe::mail_t mail;  ///< Mailbox used to distribute packets and lifecycle events.

    std::shared_ptr<input::input_t> input;  ///< Platform input device state for this stream.
    std::uint64_t input_connection_id = 0;  ///< Lease preventing an older disconnect from resetting resumed input.

    std::jthread audioThread;  ///< Audio thread.
    std::jthread videoThread;  ///< Video thread.
    std::jthread cursorThread;  ///< XFixes cursor-shape monitor for local-cursor clients.
    std::jthread clipboardThread;  ///< X11 CLIPBOARD monitor for clipboard-sync clients.
    std::jthread inputThread;  ///< Native KyProto input receiver for PLANK sessions.
    std::uint32_t plank_feature_flags {};  ///< Client-supported PLANK feature bits for this session.
    clipboard::receiver_t client_clipboard_receiver;
    std::uint64_t outbound_clipboard_generation = 0;
    clipboard::inbox_t client_clipboard_inbox;
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
    std::shared_ptr<platf::x11::clipboard_t> clipboard;  ///< Shared X11 clipboard bridge for this session.
#endif

    safe::shared_t<broadcast_ctx_t>::ptr_t broadcast_ref;  ///< Shared broadcast context retained while the session is active.

    struct {
      safe::mail_raw_t::event_t<bool> idr_events;
      safe::mail_raw_t::event_t<std::pair<int64_t, int64_t>> invalidate_ref_frames_events;
    } video;  ///< Video worker thread state for the active stream.

    struct {
      std::uint32_t timestamp;
    } audio;  ///< Native audio timestamp state for the stream.

    struct {
      safe::mail_raw_t::event_t<video::hdr_info_t> hdr_queue;
      raw_hid::feedback_queue_t raw_hid_feedback_queue;
      safe::mail_raw_t::queue_t<std::vector<std::vector<std::uint8_t>>> cursor_shape_queue;
      safe::mail_raw_t::event_t<PLANK_CURSOR_POSITION_WIRE_MESSAGE> cursor_position_event;
      safe::mail_raw_t::event_t<std::vector<std::vector<std::uint8_t>>> clipboard_offer_queue; ///< Latest local offer only.
      std::vector<std::vector<std::uint8_t>> clipboard_pending; ///< Control-thread-owned in-flight offer.
      std::size_t clipboard_next = 0; ///< First chunk not yet accepted by transport.
    } control;  ///< Native Host-to-Client event queues.

    std::string input_session_id;  ///< Internal desktop key retaining input devices across resume.
    bool plank_display_lease {};  ///< Whether this stream owns the temporary physical-display layout.
    uid_t plank_display_lease_uid {};  ///< PAM account that owns the display lease.
    std::shared_ptr<void> authentication_session;  ///< PAM lifetime retained until this stream is destroyed.
    std::string authenticated_account;  ///< Account that authenticated this stream.
    std::string authenticated_peer;  ///< Client address that authenticated this stream.
    std::chrono::steady_clock::time_point resume_ticket_next_touch {};  ///< When to next refresh the resume ticket's activity time.
    std::uint32_t plank_client_features {};  ///< PLANK feature bits the client advertised.
    std::uint32_t clipboard_generation {};  ///< Host clipboard change counter last seen by this stream.
    std::chrono::steady_clock::time_point clipboard_next_poll {};  ///< When to look at the host clipboard again.
    std::shared_ptr<void> plank_transport_endpoint;  ///< Native QUIC data-plane lifetime.

    /// Congestion-driven bitrate control. The configured bitrate is the
    /// ceiling; the target is lowered under loss and recovers when the link
    /// clears, so a home connection thinner than the ceiling stops flooding.
    struct {
      std::chrono::steady_clock::time_point next_poll {};
      std::uint64_t last_packets_lost {};
      std::uint64_t last_bytes_sent {};
      std::uint64_t last_send_drops {};
      int current_kbps {};  ///< Currently applied target.
      int clean_intervals {};  ///< Consecutive clear polls, for recovery.
      bool initialized {};
    } adaptive_bitrate;

    safe::mail_raw_t::event_t<bool> shutdown_event;  ///< Event raised when the stream should shut down.
    safe::signal_t controlEnd;  ///< Signal raised when the control channel exits.

    std::atomic<session::state_e> state;  ///< Current lifecycle state observed by stream workers.
    std::atomic_bool setup_response_sent {false};  ///< Native setup reply delivered; control data may follow.

    plank::shared_screen::role_e role {plank::shared_screen::role_e::controller};  ///< Controller, or a view-only viewer.
    std::weak_ptr<session_t> controller;  ///< Viewer only: the session whose encoder feeds it.
    const session_t *controller_id {};  ///< Viewer only: identity of that controller for fan-out matching.
    std::atomic_bool awaiting_keyframe {false};  ///< Viewer only: hold video until the next keyframe.
    std::uint64_t frame_base {};  ///< Viewer only: controller frame number just before its first keyframe.
    std::chrono::steady_clock::time_point last_keyframe_request {};  ///< Viewer only: last keyframe it forced.
    bool admin_observer {};  ///< Viewer only: a PLANK admin watching through the desktop override.
    std::uint32_t viewer_id {};  ///< Viewer only: host-assigned id the controller sees.

    std::mutex shared_mutex;  ///< Controller only: guards control_token and control_request_deadline.
    plank::shared_screen::control_token_t control_token {owner_token_id};  ///< Controller only: who may drive the desktop.
    std::chrono::steady_clock::time_point control_request_deadline {};  ///< Controller only: when a pending control request expires.

    std::mutex shared_outbox_mutex;  ///< Guards shared_outbox.
    std::deque<std::string> shared_outbox;  ///< Shared screen messages awaiting the control thread.
  };

  /**
   * @brief Whether a session is a view-only viewer.
   *
   * @param session Streaming session.
   * @return True for viewers.
   */
  static bool is_viewer(const session_t *session) {
    return session->role == plank::shared_screen::role_e::viewer;
  }

  namespace shared_messages = plank::shared_screen::messages;

  /**
   * @brief Whether a session's client understands shared screen messages.
   *
   * @param session Streaming session.
   * @return True when the feature is on and the client set the bit on its launch.
   */
  static bool accepts_shared_messages(const session_t *session) {
    return config::plank_auth.shared_screen &&
           (session->plank_client_features & plank::shared_screen::feature_shared_screen) != 0;
  }

  /**
   * @brief Queue a shared screen message for the control thread to send.
   *
   * @param session Recipient.
   * @param message Encoded message.
   */
  static void queue_shared_message(session_t *session, std::string message) {
    if (!accepts_shared_messages(session)) {
      return;
    }
    std::lock_guard lock {session->shared_outbox_mutex};
    if (session->shared_outbox.size() >= 64) {
      session->shared_outbox.pop_front();
    }
    session->shared_outbox.push_back(std::move(message));
  }

  /**
   * @brief Queue a message to one viewer of a controller.
   *
   * @param controller Controller the viewer watches.
   * @param viewer_id Recipient viewer.
   * @param message Encoded message.
   */
  static void queue_to_viewer(session_t *controller, const std::uint64_t viewer_id, const std::string &message) {
    if (!controller->broadcast_ref || viewer_id == 0) {
      return;
    }
    auto viewers = controller->broadcast_ref->viewers.lock();
    for (auto *viewer : *controller->broadcast_ref->viewers) {
      if (viewer->controller_id == controller && viewer->viewer_id == viewer_id) {
        queue_shared_message(viewer, message);
      }
    }
  }

  /**
   * @brief Send the controller the current list of visible viewers.
   *
   * Admins observing through the desktop override are never listed.
   *
   * @param controller Controller to inform.
   */
  static void publish_watchers(session_t *controller) {
    if (!accepts_shared_messages(controller) || !controller->broadcast_ref) {
      return;
    }
    std::uint64_t holder {};
    {
      std::lock_guard lock {controller->shared_mutex};
      holder = controller->control_token.holder();
    }
    std::vector<shared_messages::watcher_t> watchers;
    {
      auto viewers = controller->broadcast_ref->viewers.lock();
      for (auto *viewer : *controller->broadcast_ref->viewers) {
        if (viewer->controller_id != controller || viewer->admin_observer ||
            viewer->state.load(std::memory_order_acquire) != session::state_e::RUNNING) {
          continue;
        }
        watchers.push_back({viewer->viewer_id, viewer->authenticated_account, holder == viewer->viewer_id});
      }
    }
    queue_shared_message(controller, shared_messages::watchers(watchers));
  }

  /**
   * @brief Return the mouse and keyboard to the controller.
   *
   * @param controller Controller taking control back.
   * @param reason Reason sent to the viewer that loses control.
   */
  static void take_back_control(session_t *controller, const std::string_view reason) {
    std::uint64_t previous {};
    std::uint64_t pending {};
    {
      std::lock_guard lock {controller->shared_mutex};
      previous = controller->control_token.holder();
      pending = controller->control_token.pending();
      controller->control_token.take_back(owner_token_id);
    }
    if (pending != 0) {
      queue_shared_message(controller, shared_messages::request_cancel(static_cast<std::uint32_t>(pending)));
      queue_to_viewer(controller, pending, shared_messages::control_state(false, "denied"));
    }
    if (previous != owner_token_id) {
      BOOST_LOG(info) << "Shared screen: the owner took control back"sv;
      queue_to_viewer(controller, previous, shared_messages::control_state(false, reason));
      queue_shared_message(controller, shared_messages::control_state(true, reason));
      publish_watchers(controller);
    }
  }

  /**
   * @brief Deny a control request the owner did not answer in time.
   *
   * @param controller Controller whose pending request is checked.
   */
  static void expire_control_request(session_t *controller) {
    std::uint64_t expired {};
    {
      std::lock_guard lock {controller->shared_mutex};
      const auto pending = controller->control_token.pending();
      if (pending != 0 && std::chrono::steady_clock::now() >= controller->control_request_deadline) {
        expired = pending;
        controller->control_token.deny(owner_token_id);
      }
    }
    if (expired != 0) {
      BOOST_LOG(info) << "Shared screen: a control request expired without an answer"sv;
      queue_shared_message(controller, shared_messages::request_cancel(static_cast<std::uint32_t>(expired)));
      queue_to_viewer(controller, expired, shared_messages::control_state(false, "denied"));
    }
  }

  /**
   * @brief Pending "may I watch" questions awaiting the owner's answer.
   */
  struct join_requests_t {
    /**
     * @brief One question.
     */
    struct request_t {
      const session_t *controller {};  ///< Controller that must answer.
      int answer {};  ///< 0 pending, 1 allowed, 2 declined.
    };

    std::mutex mutex;  ///< Guards everything below.
    std::condition_variable changed;  ///< Signalled when an answer arrives.
    std::map<std::uint32_t, request_t> pending;  ///< Open questions by id.
    std::uint32_t next_id {};  ///< Last id handed out.
  };

  static join_requests_t join_requests;

  /**
   * @brief Apply a client's shared screen message.
   *
   * @param session Sender.
   * @param message Decoded message.
   */
  static void handle_shared_message(session_t *session, const shared_messages::client_message_t &message) {
    using shared_messages::client_type_e;
    if (!shared_messages::allowed_from(message.type, is_viewer(session))) {
      BOOST_LOG(warning) << "Ignoring a shared screen message the sender's role may not send"sv;
      return;
    }
    switch (message.type) {
      case client_type_e::join_answer: {
        std::lock_guard lock {join_requests.mutex};
        const auto found = join_requests.pending.find(message.id);
        if (found != join_requests.pending.end() && found->second.controller == session &&
            found->second.answer == 0) {
          found->second.answer = message.allow ? 1 : 2;
          join_requests.changed.notify_all();
        }
        break;
      }
      case client_type_e::kick: {
        if (!session->broadcast_ref) {
          break;
        }
        auto viewers = session->broadcast_ref->viewers.lock();
        for (auto *viewer : *session->broadcast_ref->viewers) {
          if (viewer->controller_id == session && viewer->viewer_id == message.id && !viewer->admin_observer) {
            BOOST_LOG(info) << "Shared screen viewer "sv << viewer->authenticated_account << " removed by the owner"sv;
#ifdef PLANK_TRANSPORT
            session::stop(*viewer, PLANK_TRANSPORT_TERMINATION_GRACEFUL);
#else
            session::stop(*viewer);
#endif
          }
        }
        break;
      }
      case client_type_e::control_answer: {
        std::uint64_t previous {};
        bool answered = false;
        {
          std::lock_guard lock {session->shared_mutex};
          if (session->control_token.pending() == message.id) {
            previous = session->control_token.holder();
            answered = (message.allow ? session->control_token.grant(owner_token_id) :
                                        session->control_token.deny(owner_token_id)) ==
                       plank::shared_screen::control_token_t::result_e::ok;
          }
        }
        if (!answered) {
          break;
        }
        BOOST_LOG(info) << "Shared screen: the owner "sv << (message.allow ? "granted"sv : "declined"sv)
                        << " a control request"sv;
        queue_to_viewer(session, message.id, shared_messages::control_state(message.allow, message.allow ? "granted" : "denied"));
        if (message.allow) {
          if (previous == owner_token_id) {
            queue_shared_message(session, shared_messages::control_state(false, "granted"));
          } else {
            queue_to_viewer(session, previous, shared_messages::control_state(false, "taken_back"));
          }
          publish_watchers(session);
        }
        break;
      }
      case client_type_e::take_back:
        take_back_control(session, "taken_back");
        break;
      case client_type_e::control_request: {
        auto controller = session->controller.lock();
        auto result = plank::shared_screen::control_token_t::result_e::not_allowed;
        if (controller && accepts_shared_messages(controller.get())) {
          std::lock_guard lock {controller->shared_mutex};
          result = controller->control_token.request(session->viewer_id);
          if (result == plank::shared_screen::control_token_t::result_e::ok) {
            controller->control_request_deadline = std::chrono::steady_clock::now() +
                                                   std::chrono::seconds {shared_messages::answer_timeout_seconds};
          }
        }
        if (result != plank::shared_screen::control_token_t::result_e::ok) {
          queue_shared_message(session, shared_messages::control_state(false, "denied"));
          break;
        }
        BOOST_LOG(info) << "Shared screen viewer "sv << session->authenticated_account << " asked for control"sv;
        queue_shared_message(controller.get(), shared_messages::control_request(session->viewer_id, session->authenticated_account));
        break;
      }
      case client_type_e::control_release: {
        auto controller = session->controller.lock();
        if (!controller) {
          break;
        }
        bool held = false;
        {
          std::lock_guard lock {controller->shared_mutex};
          held = controller->control_token.holder() == session->viewer_id;
          if (held) {
            controller->control_token.take_back(owner_token_id);
          }
        }
        if (held) {
          BOOST_LOG(info) << "Shared screen viewer "sv << session->authenticated_account << " gave control back"sv;
          queue_shared_message(session, shared_messages::control_state(false, "released"));
          queue_shared_message(controller.get(), shared_messages::control_state(true, "returned"));
          publish_watchers(controller.get());
        }
        break;
      }
    }
  }

  /**
   * @brief Decode and apply a shared screen event from a client.
   *
   * Never ends the stream: a malformed or unexpected message is logged and dropped.
   *
   * @param session Sender.
   * @param payload Event payload.
   * @param payload_size Payload size.
   */
  static void handle_shared_event(session_t *session, const std::uint8_t *payload, const std::size_t payload_size) {
    if (!accepts_shared_messages(session)) {
      BOOST_LOG(warning) << "Ignoring a shared screen message from a client that did not negotiate it"sv;
      return;
    }
    const auto message = shared_messages::parse_client(
      std::string_view {reinterpret_cast<const char *>(payload), payload_size}
    );
    if (!message) {
      BOOST_LOG(warning) << "Ignoring a malformed or unknown shared screen message"sv;
      return;
    }
    handle_shared_message(session, *message);
  }

  /**
   * @brief Whether the controller's own input may reach the desktop now.
   *
   * While a viewer holds control the owner's input is dropped, except that any
   * key or mouse-button press takes control back first.
   *
   * @param session Controller.
   * @param type KyProto input type.
   * @param payload Input payload.
   * @param payload_size Payload size.
   * @return True when the input should be applied.
   */
  static bool owner_input_allowed(session_t *session, const std::uint8_t type, const std::uint8_t *payload, const std::size_t payload_size) {
    {
      std::lock_guard lock {session->shared_mutex};
      if (session->control_token.accepts_input(owner_token_id)) {
        return true;
      }
    }
#ifdef PLANK_TRANSPORT
    if (shared_messages::owner_input_reclaims(type, payload, payload_size, PLANK_TRANSPORT_INPUT_KEYBOARD, PLANK_TRANSPORT_INPUT_MOUSE_BUTTON, PLANK_TRANSPORT_INPUT_ACTION_PRESS)) {
      take_back_control(session, "taken_back");
      return true;
    }
#else
    (void) type;
    (void) payload;
    (void) payload_size;
#endif
    return false;
  }

  /**
   * @brief Start process-wide native media and control workers.
   *
   * @param ctx Native context object used by the operation or callback.
   * @return 0 on success; nonzero when broadcast setup fails.
   */
  int start_broadcast(broadcast_ctx_t &ctx);
  /**
   * @brief Stop broadcast processing.
   *
   * @param ctx Native context object used by the operation or callback.
   */
  void end_broadcast(broadcast_ctx_t &ctx);

  static auto broadcast = safe::make_shared<broadcast_ctx_t>(start_broadcast, end_broadcast);

  /**
   * @brief Replace a byte sequence in an encoded packet.
   *
   * @param original Original text value used when reporting a parsing failure.
   * @param old Byte sequence to replace in encoded packets.
   * @param _new Replacement byte sequence inserted into encoded packets.
   * @return Copy of the original buffer with each matching byte sequence replaced.
   */
  std::vector<uint8_t> replace(const std::string_view &original, const std::string_view &old, const std::string_view &_new) {
    std::vector<uint8_t> replaced;
    replaced.reserve(original.size() + _new.size() - old.size());

    auto begin = std::begin(original);
    auto end = std::end(original);
    auto next = std::search(begin, end, std::begin(old), std::end(old));

    std::copy(begin, next, std::back_inserter(replaced));
    if (next != end) {
      std::copy(std::begin(_new), std::end(_new), std::back_inserter(replaced));
      std::copy(next + old.size(), end, std::back_inserter(replaced));
    }

    return replaced;
  }

  /**
   * @brief Send the selected HDR mode to the connected client over the control channel.
   *
   * @param session Active streaming or pairing session for the request.
   * @param hdr_info HDR info.
   * @return 0 when the control message is queued; nonzero when no control peer is ready.
   */
#ifdef PLANK_TRANSPORT
  int send_plank_transport_event(session_t *session, std::uint16_t type,
                           const std::uint8_t *payload,
                           std::size_t payload_size) {
    if (!session->plank_transport_endpoint || !payload || payload_size == 0 ||
        payload_size > UINT16_MAX) {
      return -1;
    }
    std::vector<std::uint8_t> packet(
      PLANK_TRANSPORT_EVENT_HEADER_SIZE + payload_size
    );
    std::size_t packet_size = 0;
    if (plank_transport_event_encode(
          type, payload, payload_size, packet.data(), packet.size(),
          &packet_size) != 0) {
      return -1;
    }
    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(
      session->plank_transport_endpoint.get()
    );
    return plank_transport_native_data_send(
      endpoint, packet.data(), packet_size
    );
  }

  /// Plain-text clipboard, both directions. Not in the shared transport
  /// header: Windows hosts and clients negotiate it with a feature bit.
  constexpr std::uint16_t plank_event_clipboard_text = 5;

  /// Client packets are control-sized except clipboard text, which arrives
  /// on the event channel.
  constexpr std::size_t plank_client_packet_capacity =
    PLANK_TRANSPORT_EVENT_HEADER_SIZE + plank::clipboard::max_text_bytes;

  bool queue_clipboard_offer(session_t *session, const std::string &text);

  /**
   * @brief Offer host clipboard text to a client that supports clipboard sync.
   *
   * Uses the framed clipboard-sync format (protocol/clipboard-sync.md), the
   * same one Mac and Linux hosts send, so any PLANK client can receive it.
   */
  void send_clipboard_text(session_t *session, const std::string &text) {
    if ((session->plank_client_features & plank::topology::feature_clipboard_sync) == 0) {
      return;
    }
    if (!queue_clipboard_offer(session, text)) {
      BOOST_LOG(warning) << "Couldn't offer clipboard text to the client"sv;
    }
  }

  /**
   * @brief Refresh the second-factor resume ticket's activity time about once a minute.
   */
  void poll_resume_ticket(session_t *session) {
#ifdef _WIN32
    // Keep the reconnect window open while this stream is up, so a drop at any
    // point in a long session can still resume without a second-factor prompt.
    const auto now = std::chrono::steady_clock::now();
    if (now < session->resume_ticket_next_touch) {
      return;
    }
    session->resume_ticket_next_touch = now + 60s;
    plank::auth::touch_resume_ticket(session->authenticated_account, session->authenticated_peer);
#else
    (void) session;
#endif
  }

  /**
   * @brief Share clipboard changes both ways, at most a few times a second.
   *
   * Text the client offered (assembled by handle_client_clipboard_offer) is
   * placed on the host clipboard here; host changes go out as framed offers.
   */
  void poll_clipboard(session_t *session) {
    if (!config::input.clipboard_text ||
        (session->plank_client_features & plank::topology::feature_clipboard_sync) == 0) {
      return;
    }
#ifdef _WIN32
    if (auto incoming = session->client_clipboard_inbox.take()) {
      const std::string text(incoming->begin(), incoming->end());
      if (plank::clipboard::set_host_text(text)) {
        // Our own write bumps the clipboard counter; don't echo it back.
        session->clipboard_generation =
          static_cast<std::uint32_t>(plank::clipboard::host_generation());
      }
    }
#endif
    const auto now = std::chrono::steady_clock::now();
    if (now < session->clipboard_next_poll) {
      return;
    }
    session->clipboard_next_poll = now + 250ms;
    if (auto text = plank::clipboard::poll_host_text(session->clipboard_generation)) {
      send_clipboard_text(session, *text);
    }
  }

  int send_host_termination(session_t *session, const std::uint32_t reason) {
    if (!session || !session->plank_transport_endpoint) {
      return -1;
    }
    const std::uint32_t values[] {reason};
    std::array<std::uint8_t, PLANK_TRANSPORT_CONTROL_MAX_PACKET_SIZE> packet {};
    std::size_t packet_size = 0;
    if (plank_transport_control_encode(
          PLANK_TRANSPORT_CONTROL_HOST_TERMINATE, values, std::size(values),
          packet.data(), packet.size(), &packet_size
        ) != 0) {
      return -1;
    }
    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(
      session->plank_transport_endpoint.get()
    );
    return plank_transport_native_data_send(
      endpoint, packet.data(), packet_size
    ) == PLANK_TRANSPORT_OK ? 0 : -1;
  }
#endif

  int send_hdr_mode(session_t *session, video::hdr_info_t hdr_info) {
#ifdef PLANK_TRANSPORT
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    std::array<std::uint8_t, PLANK_TRANSPORT_EVENT_HDR_MODE_SIZE> payload {};
    payload[0] = hdr_info->enabled ? 1 : 0;
    std::size_t offset = 2;
    for (const auto &primary : hdr_info->metadata.displayPrimaries) {
      plank_transport_event_write_u16(payload.data() + offset, primary.x);
      plank_transport_event_write_u16(payload.data() + offset + 2, primary.y);
      offset += 4;
    }
    plank_transport_event_write_u16(payload.data() + offset, hdr_info->metadata.whitePoint.x);
    plank_transport_event_write_u16(payload.data() + offset + 2, hdr_info->metadata.whitePoint.y);
    offset += 4;
    plank_transport_event_write_u16(payload.data() + offset, hdr_info->metadata.maxDisplayLuminance);
    plank_transport_event_write_u16(payload.data() + offset + 2, hdr_info->metadata.minDisplayLuminance);
    plank_transport_event_write_u16(payload.data() + offset + 4, hdr_info->metadata.maxContentLightLevel);
    plank_transport_event_write_u16(payload.data() + offset + 6, hdr_info->metadata.maxFrameAverageLightLevel);
    plank_transport_event_write_u16(payload.data() + offset + 8, hdr_info->metadata.maxFullFrameLuminance);
    const auto result = send_plank_transport_event(
      session, PLANK_TRANSPORT_EVENT_HDR_MODE, payload.data(), payload.size()
    );
    if (!result) {
      BOOST_LOG(debug) << "Sent HDR mode over native KyProto: "sv << hdr_info->enabled;
    }
    return result;
#else
    (void) session;
    (void) hdr_info;
    return -1;
#endif
  }

  /**
   * @brief Send one raw HID control frame over the encrypted reliable control stream.
   *
   * @param session Active stream session.
   * @param frame Complete PLANK raw HID wire frame.
   * @return Zero when sent, otherwise a transport error.
   */
  int send_raw_hid_control(session_t *session, const std::vector<std::uint8_t> &frame) {
    if (frame.size() < sizeof(PLANK_RAW_HID_WIRE_HEADER) ||
        frame.size() > sizeof(PLANK_RAW_HID_WIRE_HEADER) + PLANK_RAW_HID_MAX_PAYLOAD_SIZE) {
      return -1;
    }
#ifdef PLANK_TRANSPORT
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    return send_plank_transport_event(
      session, PLANK_TRANSPORT_EVENT_RAW_HID_WACOM, frame.data(), frame.size()
    );
#else
    (void) session;
    return -1;
#endif
  }

  int send_cursor_shape_control(session_t *session, const std::vector<std::uint8_t> &frame) {
    if (frame.size() < sizeof(PLANK_CURSOR_WIRE_HEADER) ||
        frame.size() > sizeof(PLANK_CURSOR_WIRE_HEADER) + PLANK_CURSOR_MAX_CHUNK_SIZE) {
      return -1;
    }
#ifdef PLANK_TRANSPORT
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    return send_plank_transport_event(
      session, PLANK_TRANSPORT_EVENT_CURSOR_SHAPE, frame.data(), frame.size()
    );
#else
    (void) session;
    return -1;
#endif
  }

  int send_cursor_position_control(
    session_t *session,
    const PLANK_CURSOR_POSITION_WIRE_MESSAGE &position
  ) {
#ifdef PLANK_TRANSPORT
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    return send_plank_transport_event(
      session, PLANK_TRANSPORT_EVENT_CURSOR_POSITION,
      reinterpret_cast<const std::uint8_t *>(&position), sizeof(position)
    );
#else
    (void) session;
    (void) position;
    return -1;
#endif
  }

  bool clipboard_sync_enabled(const session_t *session) {
    return session != nullptr &&
      (session->plank_feature_flags & plank::topology::feature_clipboard_sync) != 0;
  }

  bool clipboard_backend_available(const session_t *session) {
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
    return session != nullptr && session->clipboard != nullptr;
#elif defined(_WIN32)
    // The Windows clipboard is read and written by poll_clipboard().
    return session != nullptr && config::input.clipboard_text;
#else
    (void) session;
    return false;
#endif
  }

  template<typename T>
  void write_cursor_little(T &destination, T value) {
    value = util::endian::little(value);
    std::memcpy(&destination, &value, sizeof(value));
  }

  int send_clipboard_offer_control(session_t *session, const std::vector<std::uint8_t> &frame) {
    if (frame.size() < sizeof(PLANK_CLIPBOARD_WIRE_HEADER) ||
        frame.size() > sizeof(PLANK_CLIPBOARD_WIRE_HEADER) + PLANK_CLIPBOARD_MAX_EVENT_CHUNK_SIZE) {
      return -1;
    }
#ifdef PLANK_TRANSPORT
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    return send_plank_transport_event(
      session, PLANK_TRANSPORT_EVENT_CLIPBOARD_OFFER, frame.data(), frame.size()
    );
#else
    (void) session;
    return -1;
#endif
  }

  bool queue_clipboard_offer(session_t *session, const std::string &text) {
    if (text.empty() || text.size() > PLANK_CLIPBOARD_MAX_TEXT_SIZE ||
        !clipboard::valid_utf8(
          reinterpret_cast<const std::uint8_t *>(text.data()), text.size())) {
      return false;
    }
    const auto total_size = static_cast<std::uint32_t>(text.size());
    const auto generation = ++session->outbound_clipboard_generation;
    std::vector<std::vector<std::uint8_t>> frames;
    for (std::uint32_t offset = 0; offset < total_size;) {
      const auto chunk_size = std::min<std::uint32_t>(
        PLANK_CLIPBOARD_MAX_EVENT_CHUNK_SIZE, total_size - offset
      );
      std::vector<std::uint8_t> frame(sizeof(PLANK_CLIPBOARD_WIRE_HEADER) + chunk_size);
      PLANK_CLIPBOARD_WIRE_HEADER header {};
      write_cursor_little(header.magic, static_cast<std::uint32_t>(PLANK_CLIPBOARD_WIRE_MAGIC));
      write_cursor_little(header.version, static_cast<std::uint16_t>(PLANK_CLIPBOARD_WIRE_VERSION));
      header.reserved = 0;
      std::uint32_t flags = 0;
      if (offset == 0) {
        flags |= PLANK_CLIPBOARD_FLAG_FIRST_CHUNK;
      }
      if (offset + chunk_size == total_size) {
        flags |= PLANK_CLIPBOARD_FLAG_LAST_CHUNK;
      }
      write_cursor_little(header.flags, flags);
      write_cursor_little(header.generation, generation);
      write_cursor_little(header.totalSize, total_size);
      write_cursor_little(header.chunkOffset, offset);
      write_cursor_little(header.chunkSize, chunk_size);
      std::memcpy(frame.data(), &header, sizeof(header));
      std::memcpy(frame.data() + sizeof(header), text.data() + offset, chunk_size);
      frames.push_back(std::move(frame));
      offset += chunk_size;
    }
    session->control.clipboard_offer_queue->raise(std::move(frames));
    BOOST_LOG(info) << "Queued PLANK clipboard offer generation "sv << generation
                    << " ("sv << text.size() << " bytes)"sv;
    return true;
  }

  bool queue_client_clipboard_offer(session_t *session,
                                    std::vector<std::uint8_t> text) {
    if (!clipboard::valid_utf8(text.data(), text.size())) {
      return false;
    }
    const auto text_size = text.size();
    session->client_clipboard_inbox.store(std::move(text));
    BOOST_LOG(info) << "Queued PLANK clipboard offer from client ("sv
                    << text_size << " bytes)"sv;
    return true;
  }

  bool handle_client_clipboard_offer(session_t *session,
                                     const std::uint8_t *payload,
                                     std::size_t payload_size) {
    if (!clipboard_sync_enabled(session) || !clipboard_backend_available(session) ||
        payload == nullptr ||
        payload_size < sizeof(PLANK_CLIPBOARD_WIRE_HEADER) ||
        payload_size > sizeof(PLANK_CLIPBOARD_WIRE_HEADER) + PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE) {
      return false;
    }

    auto result = session->client_clipboard_receiver.append(
      payload, payload_size, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
    );
    switch (result.status) {
      case clipboard::receive_status_e::ignored:
      case clipboard::receive_status_e::incomplete:
        return true;
      case clipboard::receive_status_e::complete:
        return queue_client_clipboard_offer(session, std::move(result.text));
      case clipboard::receive_status_e::rejected:
        return false;
    }
    return false;
  }

  // X11/EGL cursor capture; only localCursorThread (guarded below) calls these.
  // The wire-format senders above stay portable.
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  bool queue_cursor_shape(session_t *session, egl::cursor_t &image,
                          unsigned long &queued_serial) {
    if (image.serial == queued_serial) {
      return true;
    }

    const auto width = static_cast<std::uint32_t>(image.width);
    const auto height = static_cast<std::uint32_t>(image.height);
    const auto image_size_64 = static_cast<std::uint64_t>(width) * height * 4U;
    // Xorg represents the hidden pointer as a transparent 1x1 image whose
    // nominal hotspot may sit just outside that placeholder. The hotspot is
    // irrelevant while invisible, so normalize it instead of rejecting it.
    if (!image.visible && width != 0 && height != 0) {
      image.hotspot_x = std::clamp(image.hotspot_x, 0, image.width - 1);
      image.hotspot_y = std::clamp(image.hotspot_y, 0, image.height - 1);
    }
    if (width == 0 || height == 0 ||
        width > PLANK_CURSOR_MAX_DIMENSION || height > PLANK_CURSOR_MAX_DIMENSION ||
        image_size_64 > PLANK_CURSOR_MAX_IMAGE_SIZE ||
        image.hotspot_x < 0 || image.hotspot_y < 0 ||
        image.hotspot_x >= image.width || image.hotspot_y >= image.height) {
      BOOST_LOG(error) << "Invalid X11 cursor geometry for PLANK local cursor transport: "sv
                       << image.width << 'x' << image.height << " hotspot="sv
                       << image.hotspot_x << ',' << image.hotspot_y;
      return false;
    }

    const auto image_size = static_cast<std::uint32_t>(image_size_64);
    std::vector<std::vector<std::uint8_t>> frames;
    for (std::uint32_t offset = 0; offset < image_size;) {
      const auto chunk_size = std::min<std::uint32_t>(
        PLANK_CURSOR_MAX_CHUNK_SIZE, image_size - offset
      );
      std::vector<std::uint8_t> frame(sizeof(PLANK_CURSOR_WIRE_HEADER) + chunk_size);
      PLANK_CURSOR_WIRE_HEADER header {};
      write_cursor_little(header.magic, static_cast<std::uint32_t>(PLANK_CURSOR_WIRE_MAGIC));
      write_cursor_little(header.version, static_cast<std::uint16_t>(PLANK_CURSOR_WIRE_VERSION));
      write_cursor_little(header.pixelFormat, static_cast<std::uint16_t>(PLANK_CURSOR_PIXEL_FORMAT_ARGB8888));
      std::uint32_t flags = image.visible ? PLANK_CURSOR_FLAG_VISIBLE : 0U;
      if (offset == 0) flags |= PLANK_CURSOR_FLAG_FIRST_CHUNK;
      if (offset + chunk_size == image_size) flags |= PLANK_CURSOR_FLAG_LAST_CHUNK;
      write_cursor_little(header.flags, flags);
      write_cursor_little(header.generation, static_cast<std::uint64_t>(image.serial));
      write_cursor_little(header.width, width);
      write_cursor_little(header.height, height);
      write_cursor_little(header.hotspotX, static_cast<std::uint32_t>(image.hotspot_x));
      write_cursor_little(header.hotspotY, static_cast<std::uint32_t>(image.hotspot_y));
      write_cursor_little(header.imageSize, image_size);
      write_cursor_little(header.chunkOffset, offset);
      write_cursor_little(header.chunkSize, chunk_size);
      std::memcpy(frame.data(), &header, sizeof(header));
      std::memcpy(frame.data() + sizeof(header), image.data + offset, chunk_size);
      frames.emplace_back(std::move(frame));
      offset += chunk_size;
    }
    session->control.cursor_shape_queue->raise(std::move(frames));

    queued_serial = image.serial;
    BOOST_LOG(debug) << "Queued PLANK local cursor generation "sv
                     << static_cast<std::uint64_t>(image.serial) << " ("sv
                     << image.width << 'x' << image.height << ", hotspot "sv
                     << image.hotspot_x << ',' << image.hotspot_y << ")"sv;
    return true;
  }

  bool queue_cursor_position(session_t *session,
                             const platf::x11::cursor_position_t &root_position,
                             std::uint64_t &position_sequence) {
    if (root_position.desktop_width <= 0 || root_position.desktop_height <= 0 ||
        session->config.monitor.width <= 0 || session->config.monitor.height <= 0) {
      BOOST_LOG(error) << "Invalid desktop/video geometry for PLANK cursor position transport"sv;
      return false;
    }

    const auto frame_width = session->config.monitor.width;
    const auto frame_height = session->config.monitor.height;
    const auto scale = std::min(
      frame_width / static_cast<double>(root_position.desktop_width),
      frame_height / static_cast<double>(root_position.desktop_height)
    );
    const auto content_width = std::max(
      1, static_cast<int>(root_position.desktop_width * scale));
    const auto content_height = std::max(
      1, static_cast<int>(root_position.desktop_height * scale));
    const auto content_x = (frame_width - content_width) / 2;
    const auto content_y = (frame_height - content_height) / 2;
    const auto root_x = std::clamp(
      root_position.x, 0, root_position.desktop_width - 1);
    const auto root_y = std::clamp(
      root_position.y, 0, root_position.desktop_height - 1);
    const auto frame_x = std::clamp(
      content_x + static_cast<int>(std::lround(root_x * scale)), 0, frame_width - 1
    );
    const auto frame_y = std::clamp(
      content_y + static_cast<int>(std::lround(root_y * scale)), 0, frame_height - 1
    );

    PLANK_CURSOR_POSITION_WIRE_MESSAGE position {};
    write_cursor_little(position.magic, static_cast<std::uint32_t>(PLANK_CURSOR_POSITION_WIRE_MAGIC));
    write_cursor_little(position.version, static_cast<std::uint16_t>(PLANK_CURSOR_POSITION_WIRE_VERSION));
    write_cursor_little(position.sequence, ++position_sequence);
    write_cursor_little(position.x, static_cast<std::uint32_t>(frame_x));
    write_cursor_little(position.y, static_cast<std::uint32_t>(frame_y));
    write_cursor_little(position.frameWidth, static_cast<std::uint32_t>(frame_width));
    write_cursor_little(position.frameHeight, static_cast<std::uint32_t>(frame_height));
    session->control.cursor_position_event->raise(position);
    return true;
  }
#elif defined(_WIN32)
  // Windows equivalents of the X11 helpers above: same wire format, with the
  // pointer sampled through GetCursorInfo (see platform/windows/input.cpp).
  bool queue_cursor_shape(session_t *session, const platf::win_cursor_image_t &image,
                          std::uint64_t generation) {
    const auto width = static_cast<std::uint32_t>(image.width);
    const auto height = static_cast<std::uint32_t>(image.height);
    const auto image_size_64 = static_cast<std::uint64_t>(width) * height * 4U;
    if (width == 0 || height == 0 ||
        width > PLANK_CURSOR_MAX_DIMENSION || height > PLANK_CURSOR_MAX_DIMENSION ||
        image_size_64 > PLANK_CURSOR_MAX_IMAGE_SIZE ||
        image_size_64 != image.pixels.size() ||
        image.hotspot_x < 0 || image.hotspot_y < 0 ||
        image.hotspot_x >= image.width || image.hotspot_y >= image.height) {
      BOOST_LOG(error) << "Invalid Windows cursor geometry for PLANK local cursor transport: "sv
                       << image.width << 'x' << image.height << " hotspot="sv
                       << image.hotspot_x << ',' << image.hotspot_y;
      return false;
    }

    const auto image_size = static_cast<std::uint32_t>(image_size_64);
    std::vector<std::vector<std::uint8_t>> frames;
    for (std::uint32_t offset = 0; offset < image_size;) {
      const auto chunk_size = std::min<std::uint32_t>(
        PLANK_CURSOR_MAX_CHUNK_SIZE, image_size - offset
      );
      std::vector<std::uint8_t> frame(sizeof(PLANK_CURSOR_WIRE_HEADER) + chunk_size);
      PLANK_CURSOR_WIRE_HEADER header {};
      write_cursor_little(header.magic, static_cast<std::uint32_t>(PLANK_CURSOR_WIRE_MAGIC));
      write_cursor_little(header.version, static_cast<std::uint16_t>(PLANK_CURSOR_WIRE_VERSION));
      write_cursor_little(header.pixelFormat, static_cast<std::uint16_t>(PLANK_CURSOR_PIXEL_FORMAT_ARGB8888));
      std::uint32_t flags = image.visible ? PLANK_CURSOR_FLAG_VISIBLE : 0U;
      if (offset == 0) flags |= PLANK_CURSOR_FLAG_FIRST_CHUNK;
      if (offset + chunk_size == image_size) flags |= PLANK_CURSOR_FLAG_LAST_CHUNK;
      write_cursor_little(header.flags, flags);
      write_cursor_little(header.generation, generation);
      write_cursor_little(header.width, width);
      write_cursor_little(header.height, height);
      write_cursor_little(header.hotspotX, static_cast<std::uint32_t>(image.hotspot_x));
      write_cursor_little(header.hotspotY, static_cast<std::uint32_t>(image.hotspot_y));
      write_cursor_little(header.imageSize, image_size);
      write_cursor_little(header.chunkOffset, offset);
      write_cursor_little(header.chunkSize, chunk_size);
      std::memcpy(frame.data(), &header, sizeof(header));
      std::memcpy(frame.data() + sizeof(header), image.pixels.data() + offset, chunk_size);
      frames.emplace_back(std::move(frame));
      offset += chunk_size;
    }
    session->control.cursor_shape_queue->raise(std::move(frames));
    BOOST_LOG(debug) << "Queued PLANK local cursor generation "sv << generation << " ("sv
                     << image.width << 'x' << image.height << ", hotspot "sv
                     << image.hotspot_x << ',' << image.hotspot_y << ")"sv;
    return true;
  }

  bool queue_cursor_position(session_t *session,
                             const platf::win_cursor_position_t &root_position,
                             std::uint64_t &position_sequence) {
    if (root_position.desktop_width <= 0 || root_position.desktop_height <= 0 ||
        session->config.monitor.width <= 0 || session->config.monitor.height <= 0) {
      BOOST_LOG(error) << "Invalid desktop/video geometry for PLANK cursor position transport"sv;
      return false;
    }

    const auto frame_width = session->config.monitor.width;
    const auto frame_height = session->config.monitor.height;
    const auto scale = std::min(
      frame_width / static_cast<double>(root_position.desktop_width),
      frame_height / static_cast<double>(root_position.desktop_height)
    );
    const auto content_width = std::max(
      1, static_cast<int>(root_position.desktop_width * scale));
    const auto content_height = std::max(
      1, static_cast<int>(root_position.desktop_height * scale));
    const auto content_x = (frame_width - content_width) / 2;
    const auto content_y = (frame_height - content_height) / 2;
    const auto root_x = std::clamp(
      root_position.x, 0, root_position.desktop_width - 1);
    const auto root_y = std::clamp(
      root_position.y, 0, root_position.desktop_height - 1);
    const auto frame_x = std::clamp(
      content_x + static_cast<int>(std::lround(root_x * scale)), 0, frame_width - 1
    );
    const auto frame_y = std::clamp(
      content_y + static_cast<int>(std::lround(root_y * scale)), 0, frame_height - 1
    );

    PLANK_CURSOR_POSITION_WIRE_MESSAGE position {};
    write_cursor_little(position.magic, static_cast<std::uint32_t>(PLANK_CURSOR_POSITION_WIRE_MAGIC));
    write_cursor_little(position.version, static_cast<std::uint16_t>(PLANK_CURSOR_POSITION_WIRE_VERSION));
    write_cursor_little(position.sequence, ++position_sequence);
    write_cursor_little(position.x, static_cast<std::uint32_t>(frame_x));
    write_cursor_little(position.y, static_cast<std::uint32_t>(frame_y));
    write_cursor_little(position.frameWidth, static_cast<std::uint32_t>(frame_width));
    write_cursor_little(position.frameHeight, static_cast<std::uint32_t>(frame_height));
    session->control.cursor_position_event->raise(position);
    return true;
  }
#endif  // __linux__ && SUNSHINE_BUILD_X11 / _WIN32

  void localCursorThread(std::stop_token stop_token, session_t *session) {
    platf::set_thread_name("sc::cursor");

#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
    auto cursor = platf::x11::cursor_t::make();
    if (!cursor || !cursor->subscribe_shape_events()) {
      BOOST_LOG(error) << "Unable to initialize X11 cursor monitoring for PLANK"sv;
      session::stop(*session);
      return;
    }

    egl::cursor_t image {};
    unsigned long queued_serial = std::numeric_limits<unsigned long>::max();
    if (!cursor->capture(image) ||
        !queue_cursor_shape(session, image, queued_serial)) {
      BOOST_LOG(error) << "Unable to capture the initial X11 cursor through XFixes"sv;
      session::stop(*session);
      return;
    }

    BOOST_LOG(info) << "PLANK cursor position uses fixed-deadline XQueryPointer sampling; cursor shape uses XFixes notifications"sv;
    std::uint64_t position_sequence = 0;
    constexpr auto cursor_sample_period = 16'666'667ns;
    static_assert(cursor_sample_period.count() > 0);
    auto next_cursor_sample = std::chrono::steady_clock::now();

    while (!stop_token.stop_requested() && !session->shutdown_event->peek()) {
      platf::x11::cursor_position_t root_position {};
      if (!cursor->query_position(root_position) ||
          !queue_cursor_position(session, root_position, position_sequence)) {
        BOOST_LOG(error) << "Unable to query the active X11 pointer position"sv;
        session::stop(*session);
        return;
      }

      const int shape_status = cursor->consume_shape_change();
      if (shape_status < 0) {
        BOOST_LOG(error) << "Unable to monitor XFixes cursor-shape changes"sv;
        session::stop(*session);
        return;
      }
      if (shape_status > 0 &&
          (!cursor->capture(image) ||
           !queue_cursor_shape(session, image, queued_serial))) {
        BOOST_LOG(error) << "Unable to refresh the active X11 cursor through XFixes"sv;
        session::stop(*session);
        return;
      }

      next_cursor_sample += cursor_sample_period;
      const auto now = std::chrono::steady_clock::now();
      if (next_cursor_sample <= now) {
        const auto missed_samples =
          (now - next_cursor_sample) / cursor_sample_period + 1;
        next_cursor_sample += cursor_sample_period * missed_samples;
      }
      std::this_thread::sleep_until(next_cursor_sample);
    }
#elif defined(_WIN32)
    platf::win_cursor_image_t image {};
    std::uint64_t generation = 1;
    if (!platf::win_cursor_capture(image)) {
      // The secure desktop can refuse access transiently; start hidden and let
      // the sampling loop publish the real shape once it can be read.
      BOOST_LOG(warning) << "Initial Windows cursor unavailable; starting with a hidden cursor"sv;
      image.pixels.assign(4, 0);
      image.width = image.height = 1;
      image.hotspot_x = image.hotspot_y = 0;
      image.visible = false;
      image.serial = 0;
    }
    if (!queue_cursor_shape(session, image, generation)) {
      session::stop(*session);
      return;
    }

    BOOST_LOG(info) << "PLANK cursor position and shape use fixed-deadline GetCursorInfo sampling"sv;
    std::uint64_t position_sequence = 0;
    // Signing in at the Windows login screen usually reuses the same session,
    // so desktop ownership is rechecked while streaming. A stream opened at the
    // login screen must not continue into another account's desktop.
    constexpr auto ownership_check_period = 1s;
    auto next_ownership_check = std::chrono::steady_clock::now() + ownership_check_period;
    std::uintptr_t queued_shape = image.visible ? static_cast<std::uintptr_t>(image.serial) : 0;
    constexpr auto cursor_sample_period = 16'666'667ns;
    auto next_cursor_sample = std::chrono::steady_clock::now();

    while (!stop_token.stop_requested()) {
      if (std::chrono::steady_clock::now() >= next_ownership_check) {
        next_ownership_check = std::chrono::steady_clock::now() + ownership_check_period;
        if (plank::session::desktop_owner_relation(session->authenticated_account) ==
            plank::session::desktop_owner_e::different) {
          // A PLANK admin using the desktop override deliberately streams a
          // seat another account owns, so the ownership mismatch that ends an
          // ordinary login-screen stream must not end theirs. Everyone else is
          // still cut off the moment a different account takes the desktop.
          const bool admin_override =
            config::plank_auth.admin_desktop_override &&
            plank::auth::account_is_plank_admin(session->authenticated_account);
          if (!admin_override) {
            BOOST_LOG(warning) << "The captured desktop is now owned by a different account than "
                               << session->authenticated_account << "; ending the stream"sv;
            session::stop(*session);
            return;
          }
        }
      }
      platf::win_cursor_position_t root_position {};
      if (!platf::win_cursor_query(root_position)) {
        // GetCursorInfo fails transiently while the secure desktop is active
        // (UAC, lock screen); keep the session and retry next sample.
        BOOST_LOG(debug) << "GetCursorInfo failed; retrying"sv;
      } else {
        if (!queue_cursor_position(session, root_position, position_sequence)) {
          session::stop(*session);
          return;
        }
        if (root_position.shape != queued_shape) {
          if (platf::win_cursor_capture(image) &&
              queue_cursor_shape(session, image, ++generation)) {
            queued_shape = root_position.shape;
          }
        }
      }

      next_cursor_sample += cursor_sample_period;
      const auto now = std::chrono::steady_clock::now();
      if (next_cursor_sample <= now) {
        const auto missed_samples =
          (now - next_cursor_sample) / cursor_sample_period + 1;
        next_cursor_sample += cursor_sample_period * missed_samples;
      }
      std::this_thread::sleep_until(next_cursor_sample);
    }
#else
    BOOST_LOG(error) << "PLANK local cursor transport requires the Linux X11 or Windows host backend"sv;
    session::stop(*session);
#endif
  }

  void localClipboardThread(std::stop_token stop_token, session_t *session) {
    platf::set_thread_name("sc::clipboard");

#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
    if (!clipboard_sync_enabled(session) || !session->clipboard) {
      return;
    }

    BOOST_LOG(info) << "PLANK clipboard sync watching X11 CLIPBOARD"sv;
    while (!stop_token.stop_requested() && !session->shutdown_event->peek()) {
      if (auto pending = session->client_clipboard_inbox.take()) {
        if (!session->clipboard->set_text(*pending)) {
          BOOST_LOG(error) << "Unable to apply a PLANK clipboard offer to X11"sv;
          session::stop(*session);
          return;
        }
        BOOST_LOG(info) << "Applied PLANK clipboard offer from client ("sv
                        << pending->size() << " bytes)"sv;
      }
      std::string text;
      if (session->clipboard->poll_change(text)) {
        if (!queue_clipboard_offer(session, text)) {
          BOOST_LOG(warning) << "Unable to queue a PLANK clipboard offer"sv;
        }
      }
      if (!session->clipboard->wait_for_activity()) {
        BOOST_LOG(error) << "Lost the X11 clipboard connection"sv;
        session::stop(*session);
        return;
      }
    }
#else
    (void) session;
#endif
  }

  /**
   * @brief Confirm an accepted PLANK encoder target to the client.
   */
  int send_video_bitrate_applied(session_t *session, const int requested_kbps) {
#ifdef PLANK_TRANSPORT
    const int applied_kbps = requested_kbps;
    const int peak_kbps = applied_kbps * config::video.sw.vbv_maxrate_percentage / 100;
    if (!session->plank_transport_endpoint) {
      return -1;
    }
    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session->plank_transport_endpoint.get());
    const auto rate_result = plank_transport_native_set_video_bitrate(
      endpoint, static_cast<std::uint32_t>(requested_kbps),
      static_cast<std::uint32_t>(peak_kbps)
    );
    if (rate_result != PLANK_TRANSPORT_OK) {
      BOOST_LOG(error) << "PLANK transport bitrate update failed with result "sv
                       << rate_result;
      session::stop(*session);
      return -1;
    }
    const std::uint32_t values[] {
      static_cast<std::uint32_t>(requested_kbps),
      static_cast<std::uint32_t>(applied_kbps),
      static_cast<std::uint32_t>(peak_kbps),
    };
    std::array<std::uint8_t, PLANK_TRANSPORT_CONTROL_MAX_PACKET_SIZE> packet {};
    std::size_t packet_size = 0;
    const auto encode_result = plank_transport_control_encode(
      PLANK_TRANSPORT_CONTROL_VIDEO_BITRATE_APPLIED, values, std::size(values),
      packet.data(), packet.size(), &packet_size
    );
    const auto result = encode_result != 0 ? PLANK_TRANSPORT_ERROR_INVALID_ARGUMENT :
      plank_transport_native_data_send(endpoint, packet.data(), packet_size);
    if (result != PLANK_TRANSPORT_OK) {
      BOOST_LOG(error) << "PlankTransport bitrate acknowledgement failed with result "sv
                       << result;
      session::stop(*session);
      return -1;
    }
    BOOST_LOG(info) << "Confirmed PLANK encoder target over PlankTransport: requested="sv
                    << requested_kbps << " Kbps, applied="sv << applied_kbps
                    << " Kbps, peak="sv << peak_kbps << " Kbps"sv;
    return 0;
#else
    (void) session;
    return -1;
#endif
  }

#ifdef PLANK_TRANSPORT
  /**
   * @brief Lower the encoder target under packet loss and recover when clear.
   *
   * DCV's advantage on a home connection is that it fits itself to the link.
   * The configured bitrate is the ceiling; when the link cannot carry it the
   * transport drops packets and the send queue backs up, so the target is
   * reduced multiplicatively, and it climbs back gradually once several polls
   * are clean. Off unless plank_adaptive_bitrate is set, so the fixed-rate
   * behaviour is unchanged for everyone who has not turned it on.
   */
  void poll_adaptive_bitrate(session_t *session) {
    // Either the host is configured to always adapt, or this client asked for
    // it on this connection. The client request is the common case: the host
    // is shared, but the link belongs to whoever is connecting.
    const bool client_requested =
      (session->plank_client_features & plank::topology::feature_adaptive_bitrate) != 0;
    if ((!config::video.plank_adaptive_bitrate && !client_requested) ||
        session->state.load(std::memory_order_acquire) != session::state_e::RUNNING ||
        !session->plank_transport_endpoint) {
      return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now < session->adaptive_bitrate.next_poll) {
      return;
    }
    session->adaptive_bitrate.next_poll = now + 2s;

    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session->plank_transport_endpoint.get());
    PlankTransportNativeStats stats {};
    stats.struct_size = sizeof(stats);
    if (plank_transport_native_endpoint_stats(endpoint, &stats) != PLANK_TRANSPORT_OK) {
      return;
    }

    auto &state = session->adaptive_bitrate;
    if (!state.initialized) {
      state.current_kbps = session->config.monitor.bitrate;
      state.last_packets_lost = stats.quic_packets_lost;
      state.last_bytes_sent = stats.video_bytes_sent;
      state.last_send_drops = stats.video_send_drops;
      state.clean_intervals = 0;
      state.initialized = true;
      return;
    }

    const std::uint64_t delta_lost = stats.quic_packets_lost - state.last_packets_lost;
    const std::uint64_t delta_bytes = stats.video_bytes_sent - state.last_bytes_sent;
    const std::uint64_t delta_drops = stats.video_send_drops - state.last_send_drops;
    state.last_packets_lost = stats.quic_packets_lost;
    state.last_bytes_sent = stats.video_bytes_sent;
    state.last_send_drops = stats.video_send_drops;

    // Estimate packets from bytes at a typical datagram size, then a loss
    // fraction over the interval.
    const std::uint64_t est_packets = delta_bytes / 1200 + delta_lost;
    const double loss_fraction = est_packets > 0 ?
      static_cast<double>(delta_lost) / static_cast<double>(est_packets) : 0.0;

    const int ceiling = session->config.monitor.bitrate;
    // A practical floor: below a few Mbps the picture is not worth streaming,
    // and the ceiling caps it in case a bookmark is set lower still.
    const int floor_target = std::min(ceiling, 3000);
    int next_target = state.current_kbps;

    // The send queue backing up means the encoder is outrunning the link; loss
    // above a couple of percent means the network is dropping. Either is
    // congestion.
    if (delta_drops > 0 || loss_fraction > 0.02) {
      next_target = std::max<int>(floor_target, state.current_kbps * 3 / 4);
      state.clean_intervals = 0;
    } else if (loss_fraction < 0.005 && delta_drops == 0) {
      // Climb back only after a sustained clear stretch, and gently, so the
      // rate does not oscillate around the link's capacity.
      if (++state.clean_intervals >= 3) {
        next_target = std::min<int>(ceiling, state.current_kbps + 5000);
        state.clean_intervals = 0;
      }
    } else {
      state.clean_intervals = 0;
    }

    if (next_target != state.current_kbps) {
      BOOST_LOG(info) << "Adaptive bitrate: "sv << state.current_kbps << " -> "sv
                      << next_target << " Kbps (loss="sv
                      << static_cast<int>(loss_fraction * 1000) / 10.0 << "%, send_drops="sv
                      << delta_drops << ", ceiling="sv << ceiling << ')';
      state.current_kbps = next_target;
      session->mail->event<int>(mail::video_bitrate)->raise(next_target);
      send_video_bitrate_applied(session, next_target);
    }
  }
#endif

  /**
   * @brief Force a keyframe on a viewer's controller, at most once a second per viewer.
   *
   * The reference chain belongs to the controller, so a viewer's loss can
   * only be repaired with a keyframe that every client receives.
   *
   * @param viewer Viewer that lost video.
   */
  void request_controller_keyframe(session_t *viewer) {
    const auto now = std::chrono::steady_clock::now();
    if (!plank::shared_screen::keyframe_request_allowed(viewer->last_keyframe_request, now, viewer_keyframe_interval)) {
      return;
    }
    viewer->last_keyframe_request = now;
    if (auto controller = viewer->controller.lock()) {
      controller->video.idr_events->raise(true);
    }
  }

#ifdef PLANK_TRANSPORT
  /**
   * @brief Handle a client event packet, currently clipboard text only.
   *
   * @return True when the packet was understood.
   */
  bool handle_client_event(session_t *session, const std::uint8_t *packet, std::size_t packet_size) {
    PlankTransportEventPacket event {};
    if (plank_transport_event_decode(packet, packet_size, &event) != 0) {
      return false;
    }
    if (event.type == shared_messages::event_type) {
      handle_shared_event(session, event.payload, event.payload_size);
      return true;
    }
    if (event.type != plank_event_clipboard_text) {
      return false;
    }
    if (is_viewer(session)) {
      return true;  // a viewer never writes the host clipboard
    }
    if ((session->plank_client_features & plank::topology::feature_clipboard_text) == 0 ||
        !config::input.clipboard_text) {
      return true;  // ignore quietly; the client should not have sent it
    }
    if (event.payload_size == 0 || event.payload_size > plank::clipboard::max_text_bytes) {
      BOOST_LOG(info) << "Ignoring client clipboard text of "sv << event.payload_size << " bytes"sv;
      return true;
    }
    const std::string text(reinterpret_cast<const char *>(event.payload), event.payload_size);
    if (plank::clipboard::set_host_text(text)) {
      // Our own write bumps the clipboard counter; don't echo it back.
      session->clipboard_generation =
        static_cast<std::uint32_t>(plank::clipboard::host_generation());
    }
    return true;
  }

  void drain_plank_transport_control(session_t *session,
                               std::array<std::uint8_t, plank_client_packet_capacity> &packet) {
    if (!session->plank_transport_endpoint) {
      return;
    }

    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session->plank_transport_endpoint.get());
    for (int drained = 0; drained < PLANK_TRANSPORT_CONTROL_DRAIN_LIMIT; ++drained) {
      std::size_t packet_size = 0;
      const auto result = plank_transport_native_data_receive(
        endpoint, packet.data(), packet.size(), &packet_size, 0);
      if (result == PLANK_TRANSPORT_TIMEOUT) {
        return;
      }
      if (result != PLANK_TRANSPORT_OK || packet_size > packet.size()) {
        const auto state = plank_transport_native_endpoint_state(endpoint);
        if (result == PLANK_TRANSPORT_ERROR_INVALID_STATE || state != PLANK_TRANSPORT_STATE_READY) {
          BOOST_LOG(info) << "PlankTransport peer closed its native control channel"sv;
        } else {
          BOOST_LOG(error) << "PlankTransport control receive failed: result="sv << result
                           << ", packet_size="sv << packet_size;
        }
        session::stop(*session);
        return;
      }

      if (packet_size >= 4 &&
          plank_transport_event_read_u32(packet.data()) == PLANK_TRANSPORT_EVENT_MAGIC) {
        if (!handle_client_event(session, packet.data(), packet_size)) {
          BOOST_LOG(error) << "Rejected unexpected client PlankTransport event"sv;
          session::stop(*session);
          return;
        }
        continue;
      }

      PlankTransportControlPacket control {};
      if (plank_transport_control_decode(packet.data(), packet_size, &control)) {
        BOOST_LOG(error) << "Rejected malformed PlankTransport control packet"sv;
        session::stop(*session);
        return;
      }
      switch (control.type) {
        case PLANK_TRANSPORT_CONTROL_CLIENT_DISCONNECT:
          if (control.payload_size != 0) {
            BOOST_LOG(error) << "Rejected malformed PlankTransport disconnect"sv;
          } else {
            BOOST_LOG(info) << "PlankTransport client requested a clean disconnect"sv;
          }
          session::stop(*session);
          return;
        case PLANK_TRANSPORT_CONTROL_REQUEST_IDR:
          if (control.payload_size != 0) {
            BOOST_LOG(error) << "Rejected malformed PlankTransport IDR request"sv;
            session::stop(*session);
            return;
          }
          if (is_viewer(session)) {
            request_controller_keyframe(session);
          } else {
            session->video.idr_events->raise(true);
          }
          break;
        case PLANK_TRANSPORT_CONTROL_INVALIDATE_REFERENCE_FRAMES:
          if (control.payload_size != 2 * sizeof(std::uint32_t) ||
              plank_transport_control_read_u32(control.payload) >
                plank_transport_control_read_u32(control.payload + 4)) {
            BOOST_LOG(error) << "Rejected malformed PlankTransport reference-frame request"sv;
            session::stop(*session);
            return;
          }
          if (is_viewer(session)) {
            request_controller_keyframe(session);
            break;
          }
          session->video.invalidate_ref_frames_events->raise(
            std::make_pair(plank_transport_control_read_u32(control.payload),
                           plank_transport_control_read_u32(control.payload + 4))
          );
          break;
        case PLANK_TRANSPORT_CONTROL_SET_VIDEO_BITRATE: {
          const auto bitrate = control.payload_size == sizeof(std::uint32_t) ?
            plank::bitrate::validate_target(
              plank_transport_control_read_u32(control.payload)) : std::nullopt;
          if (!bitrate) {
            BOOST_LOG(error) << "Rejected malformed PlankTransport bitrate request"sv;
            session::stop(*session);
            return;
          }
          if (is_viewer(session)) {
            // A viewer shares the controller's encoder; it is paced at the
            // controller's ceiling and never changes the encoder target.
            send_video_bitrate_applied(session, session->config.monitor.bitrate);
            break;
          }
          session->mail->event<int>(mail::video_bitrate)->raise(*bitrate);
          send_video_bitrate_applied(session, *bitrate);
          break;
        }
        default:
          BOOST_LOG(error) << "Rejected unexpected client PlankTransport control type "sv
                           << control.type;
          session::stop(*session);
          return;
      }
      if (session->state.load(std::memory_order_acquire) == session::state_e::STOPPING) {
        return;
      }
    }
  }
#endif

  /**
   * @brief Run native control reception and Host-to-Client event delivery.
   *
   * @param ctx Process-wide native worker state.
   */
  void controlBroadcastThread(broadcast_ctx_t *ctx) {
    platf::set_thread_name("stream::nativeControl");
    platf::adjust_thread_priority(platf::thread_priority_e::critical);

    auto shutdown_event = mail::man->event<bool>(mail::shutdown);
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
#ifdef PLANK_TRANSPORT
    auto control_packet =
      std::make_unique<std::array<std::uint8_t, plank_client_packet_capacity>>();
#endif

    while (!shutdown_event->peek() && !broadcast_shutdown_event->peek()) {
      {
        auto sessions = ctx->sessions.lock();
        KITTY_WHILE_LOOP(auto pos = std::begin(*ctx->sessions), pos != std::end(*ctx->sessions), {
          if (shutdown_event->peek() || broadcast_shutdown_event->peek()) {
            break;
          }

          auto session = *pos;
#ifdef PLANK_TRANSPORT
          drain_plank_transport_control(session, *control_packet);
#endif
          if (session->state.load(std::memory_order_acquire) == session::state_e::STOPPING) {
            pos = ctx->sessions->erase(pos);
            session->controlEnd.raise(true);
            continue;
          }

          // The client expects the native setup reply as its first data
          // message. Hold every Host-to-Client control message (HDR mode,
          // tablet feedback, cursor) until it has been sent; queued events
          // stay queued. Video can start before audio setup completes, so
          // gating only the cursor still let an HDR notice arrive first.
          if (!session->setup_response_sent.load(std::memory_order_acquire)) {
            ++pos;
            continue;
          }

          if (!session->cursorThread.joinable()) {
            session->cursorThread = std::jthread(localCursorThread, session);
          }

          {
            std::deque<std::string> outbox;
            {
              std::lock_guard lock {session->shared_outbox_mutex};
              outbox.swap(session->shared_outbox);
            }
            for (const auto &message : outbox) {
#ifdef PLANK_TRANSPORT
              if (send_plank_transport_event(
                    session, shared_messages::event_type,
                    reinterpret_cast<const std::uint8_t *>(message.data()), message.size()
                  ) != 0) {
                BOOST_LOG(warning) << "Unable to send a shared screen message"sv;
              }
#endif
            }
          }
          if (!is_viewer(session) && attached_viewers.load() != 0) {
            expire_control_request(session);
          }

          if (!is_viewer(session)) {
            poll_clipboard(session);
            poll_resume_ticket(session);
#ifdef PLANK_TRANSPORT
            poll_adaptive_bitrate(session);
#endif
          }

          auto &hdr_queue = session->control.hdr_queue;
          while (hdr_queue->peek()) {
            auto hdr_info = hdr_queue->pop();
            if (hdr_info && attached_viewers.load() != 0) {
              auto viewers = ctx->viewers.lock();
              for (auto *viewer : *ctx->viewers) {
                if (viewer->controller_id == session &&
                    viewer->setup_response_sent.load(std::memory_order_acquire)) {
                  send_hdr_mode(viewer, std::make_unique<video::hdr_info_raw_t>(*hdr_info));
                }
              }
            }
            send_hdr_mode(session, std::move(hdr_info));
          }

          auto &raw_hid_feedback_queue = session->control.raw_hid_feedback_queue;
          while (raw_hid_feedback_queue->peek()) {
            const auto frame = raw_hid_feedback_queue->pop();
            send_raw_hid_control(session, *frame);
          }

          auto &cursor_shape_queue = session->control.cursor_shape_queue;
          while (cursor_shape_queue->peek()) {
            const auto frames = cursor_shape_queue->pop();
            for (const auto &frame : *frames) {
              if (send_cursor_shape_control(session, frame)) {
                BOOST_LOG(warning) << "Unable to send a PLANK local cursor chunk"sv;
                session::stop(*session);
                break;
              }
            }
          }

          if (const auto position = session->control.cursor_position_event->try_pop()) {
            if (send_cursor_position_control(session, *position)) {
              BOOST_LOG(debug) << "Unable to send a PLANK cursor position sample"sv;
            }
          }

          auto &control = session->control;
          if (auto frames = control.clipboard_offer_queue->try_pop()) {
            control.clipboard_pending = std::move(*frames);
            control.clipboard_next = 0;
          }
          // Bounded fair drain. Queue pressure is not a disconnected peer;
          // retain precisely the unsent chunk instead of restarting a copy.
          for (unsigned count = 0; count < 2 && control.clipboard_next < control.clipboard_pending.size(); ++count) {
            const auto result = send_clipboard_offer_control(session, control.clipboard_pending[control.clipboard_next]);
            if (result == PLANK_TRANSPORT_TIMEOUT) break;
            if (result != PLANK_TRANSPORT_OK) {
              BOOST_LOG(warning) << "Unable to send a PLANK clipboard offer chunk"sv;
              session::stop(*session);
              break;
            }
            ++control.clipboard_next;
          }
          if (control.clipboard_next == control.clipboard_pending.size()) {
            control.clipboard_pending.clear(); control.clipboard_next = 0;
          }

          ++pos;
        })
      }

      if (proc::proc.running() == 0) {
        BOOST_LOG(info) << "Process terminated"sv;
        break;
      }

      // Cursor position is a locally rendered 60 Hz interaction path. Keep
      // native control draining below one frame without polling in a busy loop.
      std::this_thread::sleep_for(8ms);
    }

    auto sessions = ctx->sessions.lock();
    for (auto *session : *ctx->sessions) {
#ifdef PLANK_TRANSPORT
      if (send_host_termination(
            session, PLANK_TRANSPORT_TERMINATION_GRACEFUL
          ) != 0) {
        BOOST_LOG(warning) << "Couldn't send PlankTransport termination code"sv;
      }
#endif
      session->shutdown_event->raise(true);
      session->controlEnd.raise(true);
    }
  }

#ifdef PLANK_TRANSPORT
  /**
   * @brief Send one encoded frame to every viewer of the controller that encoded it.
   *
   * Encode once, send N times: viewers receive the controller's exact
   * payload. A viewer that just joined waits for the next keyframe, and its
   * frame numbers are rebased so its first frame is 1.
   *
   * @param controller Session whose encoder produced the frame.
   * @param controller_info Frame description sent to the controller.
   * @param payload Encoded frame, after IDR replacements.
   */
  void fan_out_video(session_t *controller, const PlankTransportNativeVideoFrameInfo &controller_info, const std::string_view payload) {
    if (attached_viewers.load() == 0 || !controller->broadcast_ref) {
      return;
    }
    const bool keyframe = (controller_info.flags & PLANK_TRANSPORT_NATIVE_VIDEO_FLAG_KEY) != 0;
    auto viewers = controller->broadcast_ref->viewers.lock();
    for (auto *viewer : *controller->broadcast_ref->viewers) {
      if (viewer->controller_id != controller ||
          viewer->state.load(std::memory_order_acquire) != session::state_e::RUNNING ||
          !viewer->setup_response_sent.load(std::memory_order_acquire) ||
          !viewer->plank_transport_endpoint) {
        continue;
      }
      if (viewer->awaiting_keyframe.load(std::memory_order_acquire)) {
        if (!keyframe) {
          continue;
        }
        viewer->frame_base = controller_info.frame_number - 1;
        viewer->awaiting_keyframe.store(false, std::memory_order_release);
      }
      auto frame_info = controller_info;
      frame_info.frame_number = controller_info.frame_number - viewer->frame_base;
      auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(viewer->plank_transport_endpoint.get());
      const auto result = plank_transport_native_video_send(
        endpoint, &frame_info,
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()
      );
      if (result < PLANK_TRANSPORT_OK) {
        BOOST_LOG(info) << "Shared screen viewer video peer has closed (result "sv << result << ')';
        session::stop(*viewer);
      }
    }
  }

  /**
   * @brief Send one Opus packet to every viewer of the controller that captured it.
   *
   * @param controller Session whose audio capture produced the packet.
   * @param packet_info Packet description sent to the controller; pts is per viewer.
   * @param data Opus payload.
   * @param size Payload size in bytes.
   */
  void fan_out_audio(session_t *controller, const PlankTransportNativeAudioPacketInfo &packet_info, const std::uint8_t *data, const std::size_t size) {
    if (attached_viewers.load() == 0 || !controller->broadcast_ref) {
      return;
    }
    auto viewers = controller->broadcast_ref->viewers.lock();
    for (auto *viewer : *controller->broadcast_ref->viewers) {
      if (viewer->controller_id != controller ||
          viewer->state.load(std::memory_order_acquire) != session::state_e::RUNNING ||
          !viewer->setup_response_sent.load(std::memory_order_acquire) ||
          !viewer->plank_transport_endpoint) {
        continue;
      }
      auto viewer_info = packet_info;
      viewer_info.pts = viewer->audio.timestamp;
      viewer->audio.timestamp += viewer->config.audio.packetDuration;
      auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(viewer->plank_transport_endpoint.get());
      const auto result = plank_transport_native_audio_send(endpoint, &viewer_info, data, size);
      if (result < PLANK_TRANSPORT_OK) {
        BOOST_LOG(info) << "Shared screen viewer audio peer has closed (result "sv << result << ')';
        session::stop(*viewer);
      }
    }
  }
#endif

  /**
   * @brief Submit complete encoded video frames to the native transport.
   */
  void videoBroadcastThread() {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    auto packets = mail::man->queue<video::packet_t>(mail::video_packets);
#ifdef PLANK_TRANSPORT
    const auto video_epoch = std::chrono::steady_clock::now();
#endif

    platf::set_thread_name("stream::videoBroadcast");
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    logging::min_max_avg_periodic_logger<double> frame_processing_latency_logger(
      debug, "Frame processing latency", "ms"
    );
    logging::time_delta_periodic_logger frame_transport_latency_logger(
      debug, "Native transport: video submission latency"
    );

    while (auto packet = packets->pop()) {
      if (shutdown_event->peek()) {
        break;
      }

      auto *session = static_cast<session_t *>(packet->channel_data);
      std::string_view payload {
        reinterpret_cast<char *>(packet->data()), packet->data_size()
      };
      std::vector<std::uint8_t> replaced_payload;
      if (packet->is_idr() && packet->replacements) {
        for (const auto &replacement : *packet->replacements) {
          replaced_payload = replace(payload, replacement.old, replacement._new);
          payload = {
            reinterpret_cast<char *>(replaced_payload.data()),
            replaced_payload.size()
          };
        }
      }

#ifdef PLANK_TRANSPORT
      if (!session->plank_transport_endpoint) {
        BOOST_LOG(error) << "Native video frame has no PlankTransport endpoint"sv;
        session::stop(*session);
        continue;
      }

      PlankTransportNativeVideoFrameInfo frame_info {};
      frame_info.struct_size = sizeof(frame_info);
      if (session->config.monitor.videoFormat == 0) {
        frame_info.codec = PLANK_TRANSPORT_NATIVE_VIDEO_CODEC_H264;
      } else if (session->config.monitor.videoFormat == 1) {
        frame_info.codec = PLANK_TRANSPORT_NATIVE_VIDEO_CODEC_HEVC;
      } else {
        BOOST_LOG(error) << "PlankTransport native transport cannot carry video format "sv
                         << session->config.monitor.videoFormat;
        session::stop(*session);
        continue;
      }

      frame_info.flags = packet->is_idr() ? PLANK_TRANSPORT_NATIVE_VIDEO_FLAG_KEY : 0;
      frame_info.frame_number = static_cast<std::uint64_t>(packet->frame_index());
      const auto frame_time = packet->frame_timestamp.value_or(
        std::chrono::steady_clock::now()
      );
      using native_video_tick =
        std::chrono::duration<std::uint64_t, std::ratio<1, 90000>>;
      frame_info.pts = std::chrono::duration_cast<native_video_tick>(
        frame_time - video_epoch
      ).count();

      if (packet->frame_timestamp) {
        const auto latency_us = std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - *packet->frame_timestamp
        ).count();
        const auto latency_tenths_ms = static_cast<std::uint16_t>(
          std::clamp<decltype(latency_us)>(
            (latency_us + 50) / 100, 0,
            std::numeric_limits<std::uint16_t>::max()
          )
        );
        frame_info.host_processing_latency = latency_tenths_ms;
        frame_processing_latency_logger.collect_and_log(latency_tenths_ms / 10.0);
      }

      auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(
        session->plank_transport_endpoint.get()
      );
      frame_transport_latency_logger.first_point_now();
      const auto result = plank_transport_native_video_send(
        endpoint, &frame_info,
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()
      );
      frame_transport_latency_logger.second_point_now_and_log();
      if (result < PLANK_TRANSPORT_OK) {
        const auto state = plank_transport_native_endpoint_state(endpoint);
        if (result == PLANK_TRANSPORT_ERROR_INVALID_STATE ||
            state != PLANK_TRANSPORT_STATE_READY) {
          BOOST_LOG(info) << "PlankTransport native video peer has closed"sv;
        } else {
          BOOST_LOG(error) << "PlankTransport native video submission failed with result "sv
                           << result;
        }
        session::stop(*session);
      } else if (result == PLANK_TRANSPORT_DROPPED) {
        BOOST_LOG(warning) << "PlankTransport native video queue replaced an old frame"sv;
      }
      fan_out_video(session, frame_info, payload);
#else
      BOOST_LOG(error) << "PLANK Host was built without native video transport"sv;
      session::stop(*session);
#endif
    }

    shutdown_event->raise(true);
  }

  /**
   * @brief Submit raw Opus packets to the native transport.
   */
  void audioBroadcastThread() {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    auto packets = mail::man->queue<audio::packet_t>(mail::audio_packets);

    platf::set_thread_name("stream::audioBroadcast");
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    while (auto packet = packets->pop()) {
      if (shutdown_event->peek()) {
        break;
      }

      auto &channel_data = std::get<0>(*packet);
      auto *session = static_cast<session_t *>(channel_data);

#ifdef PLANK_TRANSPORT
      auto &packet_data = std::get<1>(*packet);
      if (!session->plank_transport_endpoint) {
        BOOST_LOG(error) << "Native audio packet has no PlankTransport endpoint"sv;
        session::stop(*session);
        continue;
      }

      PlankTransportNativeAudioPacketInfo packet_info {};
      packet_info.struct_size = sizeof(packet_info);
      packet_info.frame_samples = static_cast<std::uint16_t>(
        session->config.audio.packetDuration * 48
      );
      packet_info.pts = session->audio.timestamp;
      auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(
        session->plank_transport_endpoint.get()
      );
      const auto result = plank_transport_native_audio_send(
        endpoint, &packet_info, packet_data.begin(), packet_data.size()
      );
      if (result < PLANK_TRANSPORT_OK) {
        const auto state = plank_transport_native_endpoint_state(endpoint);
        if (result == PLANK_TRANSPORT_ERROR_INVALID_STATE ||
            state != PLANK_TRANSPORT_STATE_READY) {
          BOOST_LOG(info) << "PlankTransport native audio peer has closed"sv;
        } else {
          BOOST_LOG(error) << "PlankTransport native audio submission failed with result "sv
                           << result;
        }
        session::stop(*session);
      } else if (result == PLANK_TRANSPORT_DROPPED) {
        BOOST_LOG(warning) << "PlankTransport native audio queue replaced an old packet"sv;
      }
      fan_out_audio(session, packet_info, packet_data.begin(), packet_data.size());
#else
      BOOST_LOG(error) << "PLANK Host was built without native audio transport"sv;
      session::stop(*session);
#endif
      session->audio.timestamp += session->config.audio.packetDuration;
    }

    shutdown_event->raise(true);
  }

  /**
   * @brief Start the native PLANK media and control workers.
   */
  int start_broadcast(broadcast_ctx_t &ctx) {
    // PlankTransport owns the only active data-plane socket. These workers retain
    // the capture/encode and client-callback contracts without binding the
    // superseded GameStream control, video, or audio ports.
    ctx.video_thread = std::jthread {videoBroadcastThread};
    ctx.audio_thread = std::jthread {audioBroadcastThread};
    ctx.control_thread = std::jthread {controlBroadcastThread, &ctx};
    return 0;
  }

  /**
   * @brief Stop broadcast processing.
   */
  void end_broadcast(broadcast_ctx_t &ctx) {
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    broadcast_shutdown_event->raise(true);

    auto video_packets = mail::man->queue<video::packet_t>(mail::video_packets);
    auto audio_packets = mail::man->queue<audio::packet_t>(mail::audio_packets);

    // Minimize delay stopping video/audio threads
    video_packets->stop();
    audio_packets->stop();

    video_packets.reset();
    audio_packets.reset();

    BOOST_LOG(debug) << "Waiting for main video thread to end..."sv;
    ctx.video_thread.join();
    BOOST_LOG(debug) << "Waiting for main audio thread to end..."sv;
    ctx.audio_thread.join();
    BOOST_LOG(debug) << "Waiting for main control thread to end..."sv;
    ctx.control_thread.join();
    BOOST_LOG(debug) << "All broadcasting threads ended"sv;

    broadcast_shutdown_event->reset();
  }

  /**
   * @brief Run the session video capture and encode thread.
   *
   * @param session Active streaming or pairing session for the request.
   */
  void videoThread(session_t *session) {
    platf::set_thread_name("session::video");
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    BOOST_LOG(debug) << "Start capturing Video"sv;
    video::capture(session->mail, session->config.monitor, session);
  }

  /**
   * @brief Run the session audio capture and encode thread.
   *
   * @param session Active streaming or pairing session for the request.
   */
  void audioThread(session_t *session) {
    platf::set_thread_name("session::audio");
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    BOOST_LOG(debug) << "Start capturing Audio"sv;
    audio::capture(session->mail, session->config.audio, session);
  }

#ifdef PLANK_TRANSPORT
  void nativeInputThread(std::stop_token stop_token, session_t *session) {
    platf::set_thread_name("session::input");
    platf::adjust_thread_priority(platf::thread_priority_e::critical);
    auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session->plank_transport_endpoint.get());
    std::array<std::uint8_t, PLANK_TRANSPORT_INPUT_MAX_PAYLOAD_SIZE> payload {};

    while_starting_do_nothing(session->state);
    while (!stop_token.stop_requested() && !session->shutdown_event->peek()) {
      std::uint8_t type = 0;
      std::size_t payload_size = 0;
      const auto result = plank_transport_native_input_receive(
        endpoint, &type, payload.data(), payload.size(), &payload_size, 50
      );
      if (result == PLANK_TRANSPORT_TIMEOUT) {
        continue;
      }
      if (result != PLANK_TRANSPORT_OK) {
        const auto state = plank_transport_native_endpoint_state(endpoint);
        if (!stop_token.stop_requested() && !session->shutdown_event->peek()) {
          if (result == PLANK_TRANSPORT_ERROR_INVALID_STATE || state != PLANK_TRANSPORT_STATE_READY) {
            BOOST_LOG(info) << "KyProto native input peer closed"sv;
          } else {
            BOOST_LOG(error) << "KyProto native input receive failed: result="sv << result;
          }
          session::stop(*session);
        }
        return;
      }
      if (payload_size > payload.size()) {
        BOOST_LOG(error) << "Rejected oversized KyProto native input message: type="sv
                         << static_cast<unsigned>(type) << ", size="sv << payload_size;
        session::stop(*session);
        return;
      }
      if (is_viewer(session)) {
        // A viewer's input reaches the desktop only while the owner has
        // handed it control, and then through the controller's own input
        // devices. Clipboard offers and raw tablet reports never do.
        if (type == PLANK_TRANSPORT_INPUT_CLIPBOARD_OFFER || type == PLANK_TRANSPORT_INPUT_RAW_HID_WACOM) {
          continue;
        }
        auto controller = session->controller.lock();
        if (!controller) {
          continue;
        }
        {
          std::lock_guard lock {controller->shared_mutex};
          if (!controller->control_token.accepts_input(session->viewer_id)) {
            continue;
          }
        }
        if (!input::native(controller->input, type, payload.data(), payload_size)) {
          BOOST_LOG(warning) << "Ignoring malformed input from a shared screen viewer: type="sv
                             << static_cast<unsigned>(type);
        }
        continue;
      }
      if (attached_viewers.load() != 0 && type != PLANK_TRANSPORT_INPUT_CLIPBOARD_OFFER &&
          !owner_input_allowed(session, type, payload.data(), payload_size)) {
        continue;
      }
      if (type == PLANK_TRANSPORT_INPUT_CLIPBOARD_OFFER) {
        if (!handle_client_clipboard_offer(
              session, payload.data(), payload_size)) {
          BOOST_LOG(error) << "Rejected malformed PLANK clipboard offer from client"sv;
          session::stop(*session);
          return;
        }
        continue;
      }
      if (!input::native(session->input, type, payload.data(), payload_size)) {
        BOOST_LOG(error) << "Rejected malformed KyProto native input message: type="sv
                         << static_cast<unsigned>(type) << ", size="sv << payload_size;
        session::stop(*session);
        return;
      }
    }
  }
#endif

  namespace session {
    std::atomic_uint running_sessions;  ///< Running sessions.

    unsigned running_count() {
      return running_sessions.load();
    }

    /**
     * @brief Platform handle returned from stream setup.
     */
    state_e state(session_t &session) {
      return session.state.load(std::memory_order_relaxed);
    }

    void mark_setup_response_sent(session_t &session) {
      session.setup_response_sent.store(true, std::memory_order_release);
      if (is_viewer(&session)) {
        // Keyframe on join: the viewer sees nothing until the shared encoder
        // emits one, so ask for it now instead of waiting for loss recovery.
        if (auto controller = session.controller.lock()) {
          controller->video.idr_events->raise(true);
        }
      }
    }

    plank::shared_screen::role_e role(const session_t &session) {
      return session.role;
    }

    const config_t &stream_config(const session_t &session) {
      return session.config;
    }

    unsigned viewer_count() {
      return attached_viewers.load();
    }

    bool accepts_shared_messages(const session_t &session) {
      return stream::accepts_shared_messages(&session);
    }

    owner_answer_e ask_owner_to_admit(const std::shared_ptr<session_t> &controller, const std::string &account) {
      if (!controller || !stream::accepts_shared_messages(controller.get())) {
        return owner_answer_e::gone;
      }
      std::uint32_t id {};
      {
        std::lock_guard lock {join_requests.mutex};
        id = ++join_requests.next_id;
        if (id == 0) {
          id = ++join_requests.next_id;
        }
        join_requests.pending[id] = {controller.get(), 0};
      }
      BOOST_LOG(info) << "Shared screen: asking the owner whether "sv << account << " may watch"sv;
      queue_shared_message(controller.get(), shared_messages::join_request(id, account));

      const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds {shared_messages::answer_timeout_seconds};
      int answer = 0;
      bool gone = false;
      {
        std::unique_lock lock {join_requests.mutex};
        while (true) {
          answer = join_requests.pending[id].answer;
          gone = state(*controller) != state_e::RUNNING;
          if (answer != 0 || gone || std::chrono::steady_clock::now() >= deadline) {
            break;
          }
          join_requests.changed.wait_for(lock, 250ms);
        }
        join_requests.pending.erase(id);
      }
      if (answer == 1) {
        BOOST_LOG(info) << "Shared screen: the owner allowed "sv << account << " to watch"sv;
        return owner_answer_e::allowed;
      }
      if (answer == 2) {
        BOOST_LOG(info) << "Shared screen: the owner declined "sv << account;
        return owner_answer_e::declined;
      }
      if (gone) {
        return owner_answer_e::gone;
      }
      BOOST_LOG(info) << "Shared screen: the owner did not answer for "sv << account;
      queue_shared_message(controller.get(), shared_messages::request_cancel(id));
      return owner_answer_e::timed_out;
    }

    /**
     * @brief Stop the active streaming session and prevent new packets from being queued.
     */
    void stop(session_t &session) {
      while_starting_do_nothing(session.state);
      auto expected = state_e::RUNNING;
      auto already_stopping = !session.state.compare_exchange_strong(expected, state_e::STOPPING);
      if (already_stopping) {
        return;
      }

      session.shutdown_event->raise(true);
      session.cursorThread.request_stop();
      session.clipboardThread.request_stop();
      session.inputThread.request_stop();

      // A viewer has nothing to show without its controller's encoder.
      if (!is_viewer(&session) && attached_viewers.load() != 0 && session.broadcast_ref) {
        auto viewers = session.broadcast_ref->viewers.lock();
        for (auto *viewer : *session.broadcast_ref->viewers) {
          if (viewer->controller_id == &session) {
            BOOST_LOG(info) << "Ending shared screen viewer "sv << viewer->authenticated_account
                            << " because the controlling stream stopped"sv;
#ifdef PLANK_TRANSPORT
            stop(*viewer, PLANK_TRANSPORT_TERMINATION_GRACEFUL);
#else
            stop(*viewer);
#endif
          }
        }
      }
    }

    void stop(session_t &session, const std::uint32_t termination_reason) {
      stop(session);
#ifdef PLANK_TRANSPORT
      if (send_host_termination(&session, termination_reason) != 0) {
        BOOST_LOG(warning) << "Couldn't send PlankTransport termination code"sv;
      }
#else
      (void) termination_reason;
#endif
    }

    void notify_desktop_handoff(session_t &session) {
#ifdef PLANK_TRANSPORT
      if (state(session) != state_e::RUNNING || !session.plank_transport_endpoint) return;
      std::array<std::uint8_t, PLANK_TRANSPORT_CONTROL_HEADER_SIZE> packet {};
      std::size_t size = 0;
      if (plank_transport_control_encode(PLANK_TRANSPORT_CONTROL_HOST_DESKTOP_HANDOFF,
            nullptr, 0, packet.data(), packet.size(), &size) != 0) return;
      auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session.plank_transport_endpoint.get());
      if (plank_transport_native_data_send(endpoint, packet.data(), size) != PLANK_TRANSPORT_OK) {
        BOOST_LOG(warning) << "Couldn't announce desktop handoff; client will use ordinary reconnect status"sv;
      }
#endif
    }

    /**
     * @brief Log why a session's native endpoint ended and its transport totals.
     *
     * @param session Session being joined.
     */
    void log_endpoint_summary(session_t &session) {
#ifdef PLANK_TRANSPORT
      if (session.plank_transport_endpoint) {
        PlankTransportNativeStats stats {};
        stats.struct_size = sizeof(stats);
        auto *endpoint = static_cast<PlankTransportNativeEndpoint *>(session.plank_transport_endpoint.get());
        std::array<char, 1024> endpoint_error {};
        const auto endpoint_error_size = plank_transport_native_endpoint_last_error(
          endpoint, endpoint_error.data(), endpoint_error.size()
        );
        if (endpoint_error_size != 0) {
          BOOST_LOG(error) << "PlankTransport native endpoint ended: "sv
                           << endpoint_error.data();
        }
        if (plank_transport_native_endpoint_stats(endpoint, &stats) == PLANK_TRANSPORT_OK) {
          BOOST_LOG(info) << "PlankTransport native transport: video_sent="sv
                          << stats.video_frames_sent << " frames/"sv
                          << stats.video_bytes_sent << " bytes, send_queue_drops="sv
                          << stats.video_send_drops << "; audio_sent="sv
                          << stats.audio_packets_sent << " packets/"sv
                          << stats.audio_bytes_sent << " bytes, send_queue_drops="sv
                          << stats.audio_send_drops << "; input_received="sv
                          << stats.input_packets_received << "; data_sent="sv
                          << stats.data_packets_sent << " packets, data_received="sv
                          << stats.data_packets_received << " packets, QUIC_packets_lost="sv
                          << stats.quic_packets_lost << ", RTT="sv
                          << stats.quic_rtt_us << " us, KyProto_drops="sv
                          << stats.kyproto_packets_dropped;
        }
      }
#else
      (void) session;
#endif
    }

    /**
     * @brief Wait for a viewer's workers and detach it from the fan-out.
     *
     * A viewer owns no capture, encoder, input devices or display lease, so
     * none of the controller's teardown applies to it.
     *
     * @param session Viewer session.
     */
    void join_viewer(session_t &session) {
      if (session.cursorThread.joinable()) {
        session.cursorThread.join();
      }
      if (session.inputThread.joinable()) {
        session.inputThread.join();
      }
      session.controlEnd.view();

      unsigned remaining = 0;
      if (session.broadcast_ref) {
        auto viewers = session.broadcast_ref->viewers.lock();
        auto &list = *session.broadcast_ref->viewers;
        const auto found = std::find(list.begin(), list.end(), &session);
        if (found != list.end()) {
          list.erase(found);
          remaining = --attached_viewers;
        } else {
          remaining = attached_viewers.load();
        }
      }
      // Control returns to the owner when its holder leaves; a pending
      // request from this viewer is withdrawn.
      if (auto controller = session.controller.lock()) {
        bool was_holder = false;
        bool was_pending = false;
        {
          std::lock_guard lock {controller->shared_mutex};
          was_holder = controller->control_token.holder() == session.viewer_id;
          was_pending = controller->control_token.pending() == session.viewer_id;
          controller->control_token.leave(session.viewer_id);
        }
        if (was_pending) {
          queue_shared_message(controller.get(), shared_messages::request_cancel(session.viewer_id));
        }
        if (was_holder) {
          queue_shared_message(controller.get(), shared_messages::control_state(true, "returned"));
        }
        publish_watchers(controller.get());
      }
      log_endpoint_summary(session);
      if (session.admin_observer) {
        BOOST_LOG(info) << plank::shared_screen::admin_audit_line(session.authenticated_account, "observe"sv, false);
      }
      BOOST_LOG(info) << "Shared screen viewer "sv << session.authenticated_account
                      << " left [viewers: "sv << remaining << ']';
    }

    /**
     * @brief Wait for worker threads owned by the session to exit.
     */
    void join(session_t &session) {
      if (is_viewer(&session)) {
        join_viewer(session);
        return;
      }
      // Current Nvidia drivers have a bug where NVENC can deadlock the encoder thread with hardware-accelerated
      // GPU scheduling enabled. If this happens, we will terminate ourselves and the service can restart.
      // The alternative is that Sunshine can never start another session until it's manually restarted.
      auto task = []() {
        BOOST_LOG(fatal) << "Hang detected! Session failed to terminate in 10 seconds."sv;
        logging::log_flush();
        lifetime::debug_trap();
      };
      auto force_kill = task_pool.pushDelayed(task, 10s).task_id;
      auto fg = util::fail_guard([&force_kill]() {
        // Cancel the kill task if we manage to return from this function
        task_pool.cancel(force_kill);
      });

      BOOST_LOG(debug) << "Waiting for video to end..."sv;
      session.videoThread.join();
      BOOST_LOG(debug) << "Waiting for audio to end..."sv;
      session.audioThread.join();
      BOOST_LOG(debug) << "Waiting for local cursor monitor to end..."sv;
      if (session.cursorThread.joinable()) {
        session.cursorThread.join();
      }
      BOOST_LOG(debug) << "Waiting for clipboard monitor to end..."sv;
      if (session.clipboardThread.joinable()) {
        session.clipboardThread.join();
      }
      BOOST_LOG(debug) << "Waiting for native input to end..."sv;
      if (session.inputThread.joinable()) {
        session.inputThread.join();
      }
      BOOST_LOG(debug) << "Waiting for control to end..."sv;
      session.controlEnd.view();
      // Reset input on session stop to avoid stuck repeated keys
      BOOST_LOG(debug) << "Resetting Input..."sv;
      input::reset(session.input, session.input_connection_id);

      log_endpoint_summary(session);

#ifdef _WIN32
      // The reconnect window counts from the end of streaming, so stamp it now.
      plank::auth::touch_resume_ticket(session.authenticated_account, session.authenticated_peer);
#endif

      // If this is the last session, invoke the platform callbacks
      if (--running_sessions == 0) {
        bool revert_display_config {config::video.dd.config_revert_on_disconnect};
        if (proc::proc.running()) {
        } else {
          // We have no app running and also no clients anymore.
          revert_display_config = true;
          input::terminate_retained_input();
        }

        if (revert_display_config) {
          display_device::revert_configuration();
        }

        platf::streaming_will_stop();
#ifdef _WIN32
        plank::session::schedule_lock_after_disconnect([] {
          return running_sessions.load() == 0;
        });
#endif
        if (session.plank_display_lease) {
          const auto released = plank::session::release_display_lease(
            session.plank_display_lease_uid
          );
          if (released != plank::session::display_request_status::submitted) {
            BOOST_LOG(error) << "Unable to submit the temporary PLANK display-lease release"sv;
          }
        }
      }

      BOOST_LOG(debug) << "Session ended"sv;
    }

    /**
     * @brief Start the audio, video, and control workers for a streaming session.
     */
    int start(session_t &session, const std::string &addr_string) {
      (void) addr_string;
      if (!session.plank_transport_endpoint) {
        BOOST_LOG(error) << "Refusing to start a session without the required PlankTransport endpoint"sv;
        return -1;
      }

      session.input = input::alloc(session.mail, session.input_session_id, session.input_connection_id);

      session.broadcast_ref = broadcast.ref();
      if (!session.broadcast_ref) {
        return -1;
      }

#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
      if (clipboard_sync_enabled(&session) && session.clipboard) {
        session.clipboardThread = std::jthread {localClipboardThread, &session};
      }
#endif

      {
        auto sessions = session.broadcast_ref->sessions.lock();
        session.broadcast_ref->sessions->push_back(&session);
      }

      session.audioThread = std::jthread {audioThread, &session};
      session.videoThread = std::jthread {videoThread, &session};
#ifdef PLANK_TRANSPORT
      session.inputThread = std::jthread {nativeInputThread, &session};
#endif

      session.state.store(state_e::RUNNING, std::memory_order_relaxed);
#ifdef _WIN32
      // A stream resumed before the disconnect lock fired.
      plank::session::cancel_lock_after_disconnect();
#endif

      // If this is the first session, invoke the platform callbacks
      if (++running_sessions == 1) {
        platf::streaming_will_start();
      }

      return 0;
    }

    int start_viewer(session_t &session) {
      auto controller = session.controller.lock();
      if (!is_viewer(&session) || !controller || !session.plank_transport_endpoint ||
          state(*controller) != state_e::RUNNING || !controller->broadcast_ref) {
        BOOST_LOG(error) << "Refusing to start a shared screen viewer without a running controller"sv;
        return -1;
      }

      // Share the controller's broadcast context so the fan-out and the
      // control thread see this viewer next to its controller.
      session.broadcast_ref = broadcast.ref();
      if (!session.broadcast_ref) {
        return -1;
      }

      unsigned viewers_now = 0;
      {
        auto sessions = session.broadcast_ref->sessions.lock();
        session.broadcast_ref->sessions->push_back(&session);
      }
      {
        auto viewers = session.broadcast_ref->viewers.lock();
        session.broadcast_ref->viewers->push_back(&session);
        viewers_now = ++attached_viewers;
      }
#ifdef PLANK_TRANSPORT
      session.inputThread = std::jthread {nativeInputThread, &session};
#endif
      session.state.store(state_e::RUNNING, std::memory_order_release);

      if (session.admin_observer) {
        BOOST_LOG(info) << plank::shared_screen::admin_audit_line(session.authenticated_account, "observe"sv, true);
      }
      BOOST_LOG(info) << "Shared screen viewer "sv << session.authenticated_account
                      << " joined [viewers: "sv << viewers_now << ']';
      publish_watchers(controller.get());

      // The controller may have stopped while this viewer was being attached;
      // its stop() could not see the viewer yet.
      if (state(*controller) != state_e::RUNNING) {
        stop(session);
      }
      return 0;
    }

    std::shared_ptr<session_t> alloc_viewer(const std::shared_ptr<session_t> &controller, session_stream::launch_session_t &launch_session) {
      auto session = std::make_shared<session_t>();
      auto mail = std::make_shared<safe::mail_raw_t>();

      session->role = plank::shared_screen::role_e::viewer;
      session->controller = controller;
      session->controller_id = controller.get();
      session->awaiting_keyframe.store(true, std::memory_order_release);
      session->admin_observer = launch_session.admin_observer;
      session->viewer_id = ++next_viewer_id;
      if (session->viewer_id == 0) {
        session->viewer_id = ++next_viewer_id;
      }
      session->config = controller->config;
      session->shutdown_event = mail->event<bool>(mail::shutdown);
      session->authentication_session = launch_session.authentication_session;
      session->authenticated_account = launch_session.authenticated_account;
      session->plank_transport_endpoint = launch_session.plank_transport_endpoint;
      // Clipboard is never shared with a viewer, whatever the client offered.
      session->plank_client_features = launch_session.plank_feature_flags &
                                       ~plank::topology::feature_clipboard_sync;
      session->plank_feature_flags = session->plank_client_features;

      session->control.hdr_queue = mail->event<video::hdr_info_t>(mail::hdr);
      session->control.raw_hid_feedback_queue = mail->queue<std::vector<std::uint8_t>>(mail::raw_hid_feedback);
      session->control.cursor_shape_queue =
        mail->queue<std::vector<std::vector<std::uint8_t>>>(mail::cursor_shape);
      session->control.cursor_position_event =
        mail->event<PLANK_CURSOR_POSITION_WIRE_MESSAGE>(mail::cursor_position);
      session->control.clipboard_offer_queue =
        mail->event<std::vector<std::vector<std::uint8_t>>>(mail::clipboard_offer);
      session->video.idr_events = mail->event<bool>(mail::idr);
      session->video.invalidate_ref_frames_events = mail->event<std::pair<int64_t, int64_t>>(mail::invalidate_ref_frames);
      session->audio.timestamp = 0;
      session->state.store(state_e::STOPPED, std::memory_order_relaxed);
      session->mail = std::move(mail);
      return session;
    }

    /**
     * @brief Allocate and initialize platform input state for a stream.
     */
    std::shared_ptr<session_t> alloc(config_t &config, session_stream::launch_session_t &launch_session) {
      auto session = std::make_shared<session_t>();

      auto mail = std::make_shared<safe::mail_raw_t>();

      session->shutdown_event = mail->event<bool>(mail::shutdown);
      // One controlling stream per graphical worker. Retain its input devices
      // across reconnect/takeover without a caller-controlled client identifier.
      session->input_session_id = "plank-desktop";
      session->plank_display_lease = launch_session.plank_display_lease;
      session->plank_display_lease_uid =
        launch_session.plank_display_lease_uid;
      session->authentication_session = launch_session.authentication_session;
      session->authenticated_account = launch_session.authenticated_account;
      session->authenticated_peer = launch_session.authenticated_peer;
      session->plank_client_features = launch_session.plank_feature_flags;
      session->plank_transport_endpoint = launch_session.plank_transport_endpoint;
      session->plank_feature_flags = launch_session.plank_feature_flags;

      if (session->plank_display_lease &&
          plank::session::activate_display_lease(
            session->plank_display_lease_uid
          ) != plank::session::display_request_status::submitted) {
        BOOST_LOG(error) << "Unable to activate the temporary PLANK display lease"sv;
      }

      session->config = config;

      session->control.hdr_queue = mail->event<video::hdr_info_t>(mail::hdr);
      session->control.raw_hid_feedback_queue = mail->queue<std::vector<std::uint8_t>>(mail::raw_hid_feedback);
      session->control.cursor_shape_queue =
        mail->queue<std::vector<std::vector<std::uint8_t>>>(mail::cursor_shape);
      session->control.cursor_position_event =
        mail->event<PLANK_CURSOR_POSITION_WIRE_MESSAGE>(mail::cursor_position);
      session->control.clipboard_offer_queue =
        mail->event<std::vector<std::vector<std::uint8_t>>>(mail::clipboard_offer);
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
      if ((launch_session.plank_feature_flags & plank::topology::feature_clipboard_sync) != 0) {
        if (auto clipboard = platf::x11::clipboard_t::make()) {
          session->clipboard = std::make_shared<platf::x11::clipboard_t>(std::move(*clipboard));
        } else {
          BOOST_LOG(error) << "Unable to initialize X11 clipboard bridge for PLANK sync"sv;
        }
      }
#endif
      session->video.idr_events = mail->event<bool>(mail::idr);
      session->video.invalidate_ref_frames_events = mail->event<std::pair<int64_t, int64_t>>(mail::invalidate_ref_frames);
      session->audio.timestamp = 0;

      session->state.store(state_e::STOPPED, std::memory_order_relaxed);

      session->mail = std::move(mail);

      return session;
    }
  }  // namespace session
}  // namespace stream
