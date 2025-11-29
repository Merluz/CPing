# ============================================================================
# FindNpcap.cmake
#
# Locate the Npcap SDK on Windows.
#
# Usage:
#   find_package(Npcap REQUIRED)
#
# Provides:
#   Npcap_FOUND           - Whether the SDK was found
#   NPCAP_INCLUDE_DIRS    - Include path containing pcap.h
#   NPCAP_LIBRARIES       - List of required import libraries (wpcap, Packet, Ws2_32)
#   NPCAP_RUNTIME_DIR     - Optional: directory containing wpcap.dll (runtime)
#
# Notes:
#   - We do NOT search system PATH or default CMake locations: only SDK roots.
#   - Users can override detection by setting the NPCAP_SDK environment variable.
#   - Runtime detection (DLL folder) is optional and best-effort.
# ============================================================================

include_guard(GLOBAL)

# --- 1) Candidate Npcap SDK root directories -------------------------------
set(_NPCAP_CANDIDATE_ROOTS "")

# Allow explicit environment override
if(DEFINED ENV{NPCAP_SDK})
  list(APPEND _NPCAP_CANDIDATE_ROOTS "$ENV{NPCAP_SDK}")
endif()

# Common installation paths
list(APPEND _NPCAP_CANDIDATE_ROOTS
  "C:/Program Files/Npcap SDK"
  "C:/Npcap SDK"
  "C:/Program Files (x86)/Npcap SDK"
)

# --- 2) Locate include directory containing pcap.h -------------------------
find_path(NPCAP_INCLUDE_DIR
  NAMES pcap.h
  PATHS ${_NPCAP_CANDIDATE_ROOTS}
  PATH_SUFFIXES Include include
  NO_DEFAULT_PATH
)

# --- 3) Library folder suffix (x64 / x86) ---------------------------------
set(_NPCAP_LIB_SUFFIXES "")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  list(APPEND _NPCAP_LIB_SUFFIXES "Lib/x64" "lib/x64" "Lib")
else()
  list(APPEND _NPCAP_LIB_SUFFIXES "Lib" "lib")
endif()

# --- 4) Locate import libraries -------------------------------------------
find_library(NPCAP_WPCAP_LIB
  NAMES wpcap
  PATHS ${_NPCAP_CANDIDATE_ROOTS}
  PATH_SUFFIXES ${_NPCAP_LIB_SUFFIXES}
  NO_DEFAULT_PATH
)

find_library(NPCAP_PACKET_LIB
  NAMES Packet
  PATHS ${_NPCAP_CANDIDATE_ROOTS}
  PATH_SUFFIXES ${_NPCAP_LIB_SUFFIXES}
  NO_DEFAULT_PATH
)

# --- 5) Add Winsock dependency on Windows ---------------------------------
set(_NPCAP_WIN_DEPS "")
if(WIN32)
  list(APPEND _NPCAP_WIN_DEPS Ws2_32)
endif()

# --- 6) Standard package result handling -----------------------------------
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Npcap
  REQUIRED_VARS
    NPCAP_INCLUDE_DIR
    NPCAP_WPCAP_LIB
    NPCAP_PACKET_LIB
  FAIL_MESSAGE
    "Npcap SDK not found. Install the SDK or set NPCAP_SDK to its root path."
)

# --- 7) Export results ------------------------------------------------------
if(Npcap_FOUND)
  set(NPCAP_INCLUDE_DIRS ${NPCAP_INCLUDE_DIR})
  set(NPCAP_LIBRARIES
    ${NPCAP_WPCAP_LIB}
    ${NPCAP_PACKET_LIB}
    ${_NPCAP_WIN_DEPS}
  )

  # Detect runtime folder (DLL location) — best-effort.
  # Typical paths:
  #   C:/Windows/System32/Npcap
  #   C:/Windows/System32
  #   C:/Windows/SysWOW64
  unset(NPCAP_RUNTIME_DIR CACHE)

  foreach(_rtpath
      "C:/Windows/System32/Npcap"
      "C:/Windows/System32"
      "C:/Windows/SysWOW64"
  )
    if(EXISTS "${_rtpath}/wpcap.dll")
      set(NPCAP_RUNTIME_DIR "${_rtpath}")
      break()
    endif()
  endforeach()

  mark_as_advanced(
    NPCAP_INCLUDE_DIR
    NPCAP_WPCAP_LIB
    NPCAP_PACKET_LIB
  )
endif()
