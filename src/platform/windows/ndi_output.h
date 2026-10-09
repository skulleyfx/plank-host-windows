/**
 * @file src/platform/windows/ndi_output.h
 * @brief Optional NDI output of the host's screens (Windows).
 */
#pragma once

// standard includes
#include <memory>

// local includes
#include "src/platform/common.h"

namespace platf::ndi_output {
  /**
   * @brief Start publishing the host's screens as NDI sources.
   *
   * Does nothing (returns null) unless `ndi_output = on` in host.conf. When it
   * is on but the NDI runtime is not installed, logs one line and returns null.
   * Otherwise starts a supervisor thread that owns one capture thread per
   * published screen; destroying the returned object stops and joins them all.
   * Never throws and never blocks the caller.
   */
  std::unique_ptr<platf::deinit_t> start();
}  // namespace platf::ndi_output
