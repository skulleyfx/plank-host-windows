#pragma once
#include <iostream>
// The standalone regression harness replaces diagnostics only; it compiles
// the production backend and uses real X11 connections against Xvfb.
#define BOOST_LOG(level) std::cerr
