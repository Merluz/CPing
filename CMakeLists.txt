cmake_minimum_required(VERSION 3.21)
project(CPing VERSION 1.0.0 LANGUAGES CXX)

if (WIN32 AND NOT MSVC)
    message(FATAL_ERROR "CPing on Windows must be built with MSVC")
endif()


# =====================================================================
# Global configuration
# =====================================================================
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

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

if(WIN32)
    add_executable(cping_windows_engine_tests tests/windows_engine_tests.cpp)
    target_include_directories(cping_windows_engine_tests PRIVATE src ${NPCAP_INCLUDE_DIRS})
    target_link_libraries(cping_windows_engine_tests PRIVATE cping_static)
    foreach(case IN ITEMS init stop capture-failure)
        add_test(NAME cping_windows_engine_${case} COMMAND cping_windows_engine_tests ${case})
        set_tests_properties(cping_windows_engine_${case} PROPERTIES TIMEOUT 12)
    endforeach()

    add_executable(cping_windows_probe_ttl_tests tests/windows_probe_ttl_tests.cpp)
    target_include_directories(cping_windows_probe_ttl_tests PRIVATE src)
    target_link_libraries(cping_windows_probe_ttl_tests PRIVATE cping_static)
    add_test(NAME cping_windows_probe_ttl COMMAND cping_windows_probe_ttl_tests)

    option(CPING_ENABLE_NPCAP_SMOKE "Run the Windows engine smoke test with the Npcap driver" OFF)
    if(CPING_ENABLE_NPCAP_SMOKE)
        add_executable(cping_windows_engine_idle_smoke tests/windows_engine_idle_smoke.cpp)
        target_include_directories(cping_windows_engine_idle_smoke PRIVATE ${NPCAP_INCLUDE_DIRS})
        target_link_libraries(cping_windows_engine_idle_smoke PRIVATE cping_static)
        add_test(NAME cping_windows_engine_idle_smoke COMMAND cping_windows_engine_idle_smoke)
        set_tests_properties(cping_windows_engine_idle_smoke PROPERTIES TIMEOUT 10)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(cping_linux_tests tests/linux_ping_tests.cpp)
    target_include_directories(cping_linux_tests PRIVATE src)
    target_link_libraries(cping_linux_tests PRIVATE cping_static)
    target_link_options(cping_linux_tests PRIVATE LINKER:--wrap=recvmsg)
    set_target_properties(cping_linux_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
    add_test(NAME cping_linux_ttl_metadata COMMAND cping_linux_tests metadata)
endif()

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
