/**
 * @file src/plank_win32_compat.h
 * @brief Minimal POSIX shims for the Windows (MinGW) host build.
 *
 * PLANK's shared sources use a small number of POSIX facilities that MinGW does
 * not provide. This header supplies only those, so the shims live in one place
 * rather than being repeated per translation unit.
 *
 * It deliberately does NOT emulate authentication, sessions or sockets - those
 * need real Windows implementations, not shims. See AUTH-AND-DUO.md.
 */
#pragma once

#ifdef _WIN32

  #include <cstddef>

  // Deliberately does NOT include <windows.h>. Doing so pulls in winsock.h,
  // which collides with the winsock2.h that Boost.Asio requires and produces
  // "#error WinSock.h has already been included".

  // MinGW's <sys/types.h> has no uid_t. PLANK uses it as an opaque account
  // identifier; a real Windows implementation would carry a SID instead.
  #ifndef PLANK_HAVE_UID_T
    #define PLANK_HAVE_UID_T 1
using uid_t = unsigned int;
  #endif

  // glibc's explicit_bzero has no MinGW equivalent. A volatile byte loop gives
  // the same guarantee (the writes cannot be optimised away) without needing
  // <windows.h> for SecureZeroMemory.
  #ifndef explicit_bzero
namespace plank::compat {
  inline void secure_zero(void *pointer, std::size_t length) {
    auto *bytes = static_cast<volatile unsigned char *>(pointer);
    while (length-- > 0) {
      *bytes++ = 0;
    }
  }
}  // namespace plank::compat
    #define explicit_bzero(ptr, len) ::plank::compat::secure_zero((ptr), (len))
  #endif

#endif  // _WIN32
