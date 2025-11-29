#pragma once

/**
 * Cross-platform symbol visibility macros.
 *
 * - On Windows, expands to __declspec(dllexport) / __declspec(dllimport)
 * - On Linux/macOS, uses GCC visibility attributes when building shared libs
 *
 * Every public C API function should use CPING_API.
 * Internal functions should use CPING_LOCAL.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef CPING_BUILDING_DLL
    #define CPING_API __declspec(dllexport)
  #else
    #define CPING_API
  #endif
  #define CPING_LOCAL
#else
  #if __GNUC__ >= 4
    #ifdef CPING_BUILDING_DLL
      #define CPING_API   __attribute__((visibility("default")))
    #else
      #define CPING_API
    #endif
    #define CPING_LOCAL __attribute__((visibility("hidden")))
  #else
    #define CPING_API
    #define CPING_LOCAL
  #endif
#endif
