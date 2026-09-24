cmake_minimum_required(VERSION 3.20)

project(OpticalPathPlanner
  VERSION 1.0.0
  DESCRIPTION "Deterministic vendor-neutral optical path planner for the Fabric OS stack"
  HOMEPAGE_URL "https://github.com/summonlabs/Optical-Path-Planner"
  LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(OPP_BUILD_TESTS "Build the Optical Path Planner test suites" ON)
option(OPP_BUILD_EXAMPLES "Build the public API examples" ON)
option(OPP_BUILD_BENCHMARKS "Build the guarded benchmarks" ON)
option(OPP_BUILD_TOOLS "Build the opp CLI and the oppd inspection service" ON)
option(OPP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(OPP_ENABLE_ASAN "Build with AddressSanitizer when the toolchain supports it" OFF)
option(OPP_ENABLE_ANALYZE "Build with the MSVC static analyzer (/analyze)" OFF)

set(CMAKE_CXX_STANDARD 20 CACHE STRING "C++ standard")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(OPP_SOURCES
  src/canonical.cpp
  src/constraints.cpp
  src/evidence.cpp
  src/fileio.cpp
  src/ids.cpp
  src/plan.cpp
  src/planner.cpp
  src/proto.cpp
  src/request.cpp
  src/request_io.cpp
  src/result.cpp
  src/search.cpp
  src/selftest.cpp
  src/service.cpp
  src/sha256.cpp
  src/snapshot_io.cpp
  src/spectrum.cpp
  src/status.cpp
  src/synthetic.cpp
  src/store.cpp
  src/topology.cpp
  src/validate.cpp
  src/version.cpp
)

add_library(OpticalPathPlanner ${OPP_SOURCES})
add_library(SummonSoftwareLabs::OpticalPathPlanner ALIAS OpticalPathPlanner)

target_include_directories(OpticalPathPlanner
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_include_directories(OpticalPathPlanner PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(OpticalPathPlanner PUBLIC cxx_std_20)
set_target_properties(OpticalPathPlanner PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  POSITION_INDEPENDENT_CODE ON)

if(BUILD_SHARED_LIBS)
  target_compile_definitions(OpticalPathPlanner PRIVATE OPP_BUILDING_SHARED)
  target_compile_definitions(OpticalPathPlanner PUBLIC OPP_SHARED)
endif()

find_package(Threads REQUIRED)
target_link_libraries(OpticalPathPlanner PUBLIC Threads::Threads)

if(WIN32)
  target_link_libraries(OpticalPathPlanner PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# Strict compiler configuration: /W4 /WX /permissive- on MSVC, -Wall -Wextra
# -Wpedantic -Werror elsewhere.
# ---------------------------------------------------------------------------
function(opp_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(OPP_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(OPP_ENABLE_ANALYZE)
      target_compile_options(${target} PRIVATE /analyze /analyze:external- /analyze:quiet)
    endif()
    if(OPP_ENABLE_ASAN)
      # Debug information is required for usable AddressSanitizer reports.
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO /DEBUG)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    if(OPP_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(OPP_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

opp_apply_strict_options(OpticalPathPlanner)

if(MSVC)
  # The C runtime marks the ISO C file APIs as deprecated; this runtime uses them
  # deliberately for the flush-to-device step of atomic writes.
  target_compile_definitions(OpticalPathPlanner PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Stages the AddressSanitizer runtime next to an executable so that instrumented
# binaries (including child processes spawned by tests) run without a PATH change.
function(opp_stage_asan_runtime target)
  if(MSVC AND OPP_ENABLE_ASAN AND OPP_ASAN_RUNTIME_DIR)
    file(GLOB _opp_asan_dlls "${OPP_ASAN_RUNTIME_DIR}/clang_rt.asan_*.dll")
    foreach(dll IN LISTS _opp_asan_dlls)
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" "$<TARGET_FILE_DIR:${target}>")
    endforeach()
  endif()
endfunction()

if(MSVC AND OPP_ENABLE_ASAN)
  get_filename_component(_opp_compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
  file(GLOB _opp_asan_runtimes "${_opp_compiler_dir}/clang_rt.asan_dynamic-*.dll")
  if(_opp_asan_runtimes)
    set(OPP_ASAN_RUNTIME_DIR "${_opp_compiler_dir}" CACHE INTERNAL "ASan runtime directory")
    message(STATUS "  ASan runtime:      ${_opp_compiler_dir}")
  else()
    message(WARNING "AddressSanitizer was requested but no runtime was found next to cl.exe")
  endif()
endif()

# ---------------------------------------------------------------------------
# Installation and package export
# ---------------------------------------------------------------------------
install(TARGETS OpticalPathPlanner
  EXPORT OpticalPathPlannerTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT OpticalPathPlannerTargets
  FILE OpticalPathPlannerTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpticalPathPlanner)

configure_package_config_file(
  cmake/OpticalPathPlannerConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/OpticalPathPlannerConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpticalPathPlanner)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/OpticalPathPlannerConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/OpticalPathPlannerConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/OpticalPathPlannerConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpticalPathPlanner)

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
if(OPP_BUILD_TOOLS)
  add_subdirectory(apps)
endif()
if(OPP_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(OPP_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
if(OPP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "OpticalPathPlanner ${PROJECT_VERSION} (planning rules ${PROJECT_VERSION_MAJOR}.0.0)")
message(STATUS "  AddressSanitizer: ${OPP_ENABLE_ASAN}")
message(STATUS "  Static analyzer:  ${OPP_ENABLE_ANALYZE}")
