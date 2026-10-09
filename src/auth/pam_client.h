/**
 * @file src/auth/pam_client.h
 * @brief Unprivileged Sunshine client for the local PAM broker.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pam_broker_protocol.h"

namespace plank::auth {
  /**
   * @brief Result of advancing a PAM conversation.
   */
  struct step_t {
    /**
     * @brief State returned by the broker.
     */
    enum class state_e {
      challenge,  ///< Caller must collect and submit prompt responses.
      authenticated,  ///< PAM authentication and session open succeeded.
      denied,  ///< PAM or protocol processing failed.
    } state;

    std::vector<prompt_t> prompts;  ///< PAM messages when state is `challenge`.
    phase_e phase = phase_e::protocol;  ///< Completed or failed operation phase.
    int pam_status = 0;  ///< PAM status when state is terminal.
  };

  /**
   * @brief Own one local PAM broker connection and PAM session.
   */
  class pam_client_t {
  public:
    /**
     * @brief Create a disconnected PAM client.
     */
    pam_client_t() = default;

    /**
     * @brief Close the broker connection and PAM session.
     */
    ~pam_client_t();

    pam_client_t(const pam_client_t &) = delete;
    pam_client_t &operator=(const pam_client_t &) = delete;
    pam_client_t(pam_client_t &&other) noexcept;
    pam_client_t &operator=(pam_client_t &&other) noexcept;

    /**
     * @brief Obtain a supervisor-delegated broker connection and start authentication.
     *
     * @param transaction_id Nonzero transaction identifier.
     * @param username Operating-system account name.
     * @param remote_host Auditable source host label.
     * @param tty Logical remote service terminal.
     * @return First PAM challenge or a terminal result.
     */
    step_t begin(std::uint64_t transaction_id,
                 std::string_view username, std::string_view remote_host,
                 std::string_view tty);

    /**
     * @brief Submit one response per preceding PAM message.
     *
     * @param responses Prompt responses; informational entries must be empty.
     * @param arrived When the request reached the server; a second-factor wait counts its round budget from here.
     * @return Next PAM challenge or a terminal result.
     */
    step_t respond(std::vector<std::string> responses,
                   std::chrono::steady_clock::time_point arrived = std::chrono::steady_clock::now());

    /**
     * @brief Close the authenticated PAM session and local socket.
     */
    void close();

    /**
     * @brief Check whether this object owns a broker connection.
     *
     * @return True while connected.
     */
    bool connected() const;

#ifdef SUNSHINE_TESTS
    /**
     * @brief Adopt one connected socket for protocol unit tests.
     *
     * @param descriptor Connected test socket.
     * @param transaction_id Test transaction identifier.
     * @return Client owning the supplied descriptor.
     */
    static pam_client_t adopt_for_test(int descriptor, std::uint64_t transaction_id);

    /**
     * @brief Read one broker step in protocol unit tests.
     *
     * @return Decoded broker step.
     */
    step_t read_step_for_test();
#endif

  private:
    /**
     * @brief Read and decode the next broker challenge or result.
     *
     * @return Decoded step, or protocol denial on malformed input.
     */
    step_t read_step();

    int descriptor_ = -1;  ///< Connected Unix socket.
    std::uint64_t transaction_id_ = 0;  ///< Active transaction identifier.
    std::size_t expected_responses_ = 0;  ///< Entries required by the last challenge.
    bool authenticated_ = false;  ///< Whether the broker opened the PAM session.
  };
}  // namespace plank::auth
