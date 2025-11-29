#pragma once
#include <string>
#include <iostream>

/**
 * Minimal ANSI terminal helper.
 *
 * Provides:
 *   - color escape sequences
 *   - automatic disabling via term::g_enabled
 *   - Windows 10 VT sequence enabling (best-effort)
 *
 * On *nix terminals this is a no-op.
 */

#if defined(_WIN32)
  #ifndef NOMINMAX
  #  define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
  #  define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
  #  define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
#endif

namespace term {

inline bool g_enabled = true;

inline const char* reset()   { return g_enabled ? "\x1b[0m"  : ""; }
inline const char* bold()    { return g_enabled ? "\x1b[1m"  : ""; }
inline const char* dim()     { return g_enabled ? "\x1b[2m"  : ""; }
inline const char* red()     { return g_enabled ? "\x1b[31m" : ""; }
inline const char* green()   { return g_enabled ? "\x1b[32m" : ""; }
inline const char* yellow()  { return g_enabled ? "\x1b[33m" : ""; }
inline const char* blue()    { return g_enabled ? "\x1b[34m" : ""; }
inline const char* magenta() { return g_enabled ? "\x1b[35m" : ""; }
inline const char* cyan()    { return g_enabled ? "\x1b[36m" : ""; }
inline const char* gray()    { return g_enabled ? "\x1b[90m" : ""; }

inline void enable_vt() {
#if defined(_WIN32)
    if (!g_enabled) return;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, mode);
#else
    // nothing
#endif
}

inline std::string colorize(const std::string& s, const char* color) {
    if (!g_enabled) return s;
    return std::string(color) + s + reset();
}

} // namespace term
