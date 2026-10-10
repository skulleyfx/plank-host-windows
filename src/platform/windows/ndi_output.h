/**
 * @file src/platform/windows/ndi_output.h
 * @brief Optional NDI output of the host's screens (Windows).
 */
#pragma once

// standard includes
#include <memory>
#include <string>
#include <string_view>

// local includes
#include "src/platform/common.h"
#include "src/plank_ndi.h"

namespace platf::ndi_output {
  /**
   * @brief Start publishing the host's screens as NDI sources.
   *
   * Does nothing (returns null) unless `ndi_output` is `on` or `available` in
   * host.conf. With `on` the helper runs from now until the object is
   * destroyed. With `available` the helper starts switched off and is started
   * and stopped by set_enabled(). Destroying the returned object stops
   * everything. Never throws and never blocks the caller.
   */
  std::unique_ptr<platf::deinit_t> start();

  /// What the host reports about NDI right now.
  struct status_t {
    plank::ndi::report_e report {plank::ndi::report_e::unavailable};
    std::string source_names;  ///< Published source name(s); only meaningful when the report is on or always.
  };

  /**
   * @brief Current NDI state. Cheap and non-blocking (the runtime lookup is
   * cached for a few seconds); safe to call from the HTTPS thread.
   */
  status_t status();

  enum class toggle_result_e {
    ok,  ///< The requested state is now in effect (or was already).
    unavailable,  ///< ndi_output is off, or the helper / NDI runtime is missing.
    always_on,  ///< ndi_output = on: not switchable.
  };

  /**
   * @brief Switch NDI on or off at runtime. Returns at once; the helper is
   * started or stopped in the background. Safe against rapid toggling.
   *
   * @param on Requested state.
   * @param session_active A PLANK controller session is running right now;
   * switching on then ties NDI to that session (see ndi_auto_off_minutes).
   * @param who Account that asked, for the log line.
   */
  toggle_result_e set_enabled(bool on, bool session_active, std::string_view who);
}  // namespace platf::ndi_output
