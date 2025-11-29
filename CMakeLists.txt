cmake_minimum_required(VERSION 3.21)
project(CPing VERSION 1.0.0 LANGUAGES CXX)

# =====================================================================
# Global configuration
# =====================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Remove lib prefix on Windows
if(WIN32)
    set(CMAKE_SHARED_LIBRARY_PREFIX "")
    set(CMAKE_STATIC_LIBRARY_PREFIX "")
endif()

# Output directories (multi-config safe)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(CMAKE_CONFIGURATION_TYPES)
  foreach(cfg ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${cfg} CFGU)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CFGU} ${CMAKE_BINARY_DIR}/bin/${cfg})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CFGU} ${CMAKE_BINARY_DIR}/lib/${cfg})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CFGU} ${CMAKE_BINARY_DIR}/lib/${cfg})
  endforeach()
endif()

# =====================================================================
# Sources
# =====================================================================
set(CPING_COMMON
    src/util.cpp
    src/capi.cpp
)

if(WIN32)
  list(APPEND CPING_PLATFORM
      src/ping_win.cpp
      src/win/win_route.cpp
      src/win/win_pcap.cpp
      src/win/win_icmp.cpp
      src/engine.cpp
  )
else()
  list(APPEND CPING_PLATFORM
      src/engine_linux.cpp
      src/ping_linux.cpp
  )
endif()

# =====================================================================
# Dependencies (Npcap)
# =====================================================================
if(WIN32)
  list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
  find_package(Npcap REQUIRED)
endif()

# =====================================================================
# Object library
# =====================================================================
add_library(cping_obj OBJECT
    ${CPING_COMMON}
    ${CPING_PLATFORM}
)

target_include_directories(cping_obj
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
  target_include_directories(cping_obj PRIVATE ${NPCAP_INCLUDE_DIRS})
endif()

# =====================================================================
# Static library
# =====================================================================
add_library(cping_static STATIC $<TARGET_OBJECTS:cping_obj>)
add_library(CPing::cping_static ALIAS cping_static)

set_target_properties(cping_static PROPERTIES OUTPUT_NAME "cping_static")

target_include_directories(cping_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
  target_link_libraries(cping_static PRIVATE ${NPCAP_LIBRARIES} Ws2_32 Iphlpapi)
else()
  target_link_libraries(cping_static PRIVATE pthread)
endif()

# =====================================================================
# Shared library (DLL / SO)
# =====================================================================
add_library(cping_shared SHARED $<TARGET_OBJECTS:cping_obj>)
add_library(CPing::cping ALIAS cping_shared)

set_target_properties(cping_shared PROPERTIES
    OUTPUT_NAME "cping"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

target_compile_definitions(cping_shared PRIVATE CPING_BUILDING_DLL)

target_include_directories(cping_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
  target_link_libraries(cping_shared PRIVATE ${NPCAP_LIBRARIES} Ws2_32 Iphlpapi)
else()
  target_link_libraries(cping_shared PRIVATE pthread)
endif()

# =====================================================================
# CLI executable
# =====================================================================
add_executable(cping
    src/main.cpp
    src/cli.cpp
    src/runner.cpp
    src/stats.cpp
    src/export.cpp
)

target_link_libraries(cping PRIVATE cping_static)

# =====================================================================
# Tests
# =====================================================================
enable_testing()

add_executable(cping_tests tests/ping_tests.cpp)
target_link_libraries(cping_tests PRIVATE cping_static)

# =====================================================================
# Install rules
# =====================================================================
install(TARGETS cping_shared cping_static
    EXPORT CPingTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(TARGETS cping RUNTIME DESTINATION bin)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT CPingTargets
    FILE CPingConfig.cmake
    NAMESPACE CPing::
    DESTINATION lib/cmake/CPing
)
