/**
 * @file src/stream.h
 * @brief Declarations for the streaming protocols.
 */
#pragma once

// standard includes
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

// lib includes
#include <boost/asio.hpp>

// local includes
#include "audio.h"
#include "crypto.h"
#include "plank_shared_screen.h"
#include "video.h"

namespace stream {
  constexpr auto VIDEO_STREAM_PORT = 9;  ///< GameStream base-port offset used for the video UDP stream.
  constexpr auto CONTROL_PORT = 10;  ///< GameStream base-port offset used for the control channel.
  constexpr auto AUDIO_STREAM_PORT = 11;  ///< GameStream base-port offset used for the audio UDP stream.

  struct session_t;

  /**
   * @brief Stream configuration shared by capture and network senders.
   */
  struct config_t {
    audio::config_t audio;  ///< Audio capture configuration for the stream.
    video::config_t monitor;  ///< Video capture and encoder configuration for the selected monitor.

    int packetsize;  ///< Maximum payload size for network packets.
    int minRequiredFecPackets;  ///< Minimum recovery packets required before FEC is emitted.
    int mlFeatureFlags;  ///< Moonlight feature flags negotiated for this session.
    int controlProtocolType;  ///< GameStream control protocol variant selected by the client.
    int audioQosType;  ///< Audio QoS type.
    int videoQosType;  ///< Video QoS type.

  };

  namespace session {
    /**
     * @brief Enumerates supported state options.
     */
    enum class state_e : int {
      STOPPED,  ///< The session is stopped
      STOPPING,  ///< The session is stopping
      STARTING,  ///< The session is starting
      RUNNING,  ///< The session is running
    };

    /**
     * @brief Allocate and initialize platform input state for a stream.
     *
     * @param config Configuration values to apply.
     * @param launch_session Launch session.
     * @return Allocated object or identifier, or an error value on failure.
     */
    std::shared_ptr<session_t> alloc(config_t &config, session_stream::launch_session_t &launch_session);
    /**
     * @brief Allocate a view-only session fed by a running controller's encoder.
     *
     * The viewer copies the controller's stream configuration and owns only
     * its own transport endpoint; it never captures, encodes or injects input.
     *
     * @param controller Running controller session.
     * @param launch_session Viewer launch session carrying its endpoint and account.
     * @return Allocated viewer session.
     */
    std::shared_ptr<session_t> alloc_viewer(const std::shared_ptr<session_t> &controller, session_stream::launch_session_t &launch_session);
    /**
     * @brief Attach a view-only session to its controller's media fan-out.
     *
     * @param session Viewer from alloc_viewer().
     * @return 0 on success; nonzero when the controller is gone.
     */
    int start_viewer(session_t &session);
    /**
     * @brief Role of a session.
     *
     * @param session Streaming session.
     * @return Controller or viewer.
     */
    plank::shared_screen::role_e role(const session_t &session);
    /**
     * @brief Stream configuration negotiated for a session.
     *
     * @param session Streaming session.
     * @return The session's configuration.
     */
    const config_t &stream_config(const session_t &session);
    /**
     * @brief Number of view-only sessions currently attached.
     *
     * @return Attached viewer count.
     */
    unsigned viewer_count();

    /**
     * @brief Number of attached viewers other than silent admin observers.
     *
     * @return Viewers anyone may be told about.
     */
    unsigned visible_viewer_count();

    /**
     * @brief Whether a session's client understands shared screen messages.
     *
     * @param session Streaming session.
     * @return True when shared_screen is on and the client negotiated the bit.
     */
    bool accepts_shared_messages(const session_t &session);

    /**
     * @brief The owner's answer to a watch request.
     */
    enum class owner_answer_e {
      allowed,  ///< The owner allowed it.
      declined,  ///< The owner declined it.
      timed_out,  ///< The owner did not answer in time.
      gone,  ///< The controller stopped or cannot answer.
    };

    /**
     * @brief Ask the controller's client whether an account may watch, and wait for the answer.
     *
     * Blocks the caller for at most the shared screen answer timeout.
     *
     * @param controller Running controller.
     * @param account Account asking to watch.
     * @return The owner's answer.
     */
    owner_answer_e ask_owner_to_admit(const std::shared_ptr<session_t> &controller, const std::string &account);
    /**
     * @brief Start a streaming session for the supplied peer address.
     *
     * @param session Active streaming or pairing session for the request.
     * @param addr_string Addr string.
     * @return Start status.
     */
    int start(session_t &session, const std::string &addr_string);
    /**
     * @brief Stop a streaming session and prevent more packets from being queued.
     *
     * @param session Active streaming or pairing session for the request.
     */
    void stop(session_t &session);
    /**
     * @brief Stop a session after notifying its client of the Host reason.
     *
     * Input processing is stopped before the reason is queued so a displaced
     * client cannot deliver another input event during session handoff.
     *
     * @param session Active streaming session.
     * @param termination_reason PLANK Host termination reason.
     */
    void stop(session_t &session, std::uint32_t termination_reason);
    void notify_desktop_handoff(session_t &session);
    /**
     * @brief Wait for worker threads owned by the session to exit.
     *
     * @param session Active streaming or pairing session for the request.
     */
    void join(session_t &session);
    /**
     * @brief Platform handle returned from stream setup.
     *
     * @param session Active streaming or pairing session for the request.
     * @return Current lifecycle state for the stream session.
     */
    state_e state(session_t &session);
    /**
     * @brief Record that the native setup reply has been delivered to the client.
     *
     * Control-channel data such as cursor shapes is held until this is called.
     *
     * @param session Active streaming session.
     */
    void mark_setup_response_sent(session_t &session);

    /**
     * @brief Number of controller streams currently running; viewers are not counted.
     *
     * @return Running stream count.
     */
    unsigned running_count();
  }  // namespace session
}  // namespace stream
