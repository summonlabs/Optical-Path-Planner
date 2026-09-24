cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer of the installed OpticalPathPlanner package.
#
# This project is deliberately NOT part of the Optical Path Planner build: it exists to prove that
# the installed package is usable from a separate CMake project with no access to the source tree.
#
#   cmake -S consumer -B <build> -DCMAKE_PREFIX_PATH=<install-prefix>
#   cmake --build <build> --config Release
#   <build>/consumer_plan_check
project(OpticalPathPlannerConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpticalPathPlanner CONFIG REQUIRED)

if(NOT TARGET SummonSoftwareLabs::OpticalPathPlanner)
  message(FATAL_ERROR "SummonSoftwareLabs::OpticalPathPlanner was not exported by the installed package")
endif()

message(STATUS "OpticalPathPlanner package version: ${OpticalPathPlanner_VERSION}")

add_executable(consumer_plan_check main.cpp)
target_link_libraries(consumer_plan_check PRIVATE SummonSoftwareLabs::OpticalPathPlanner)

if(MSVC)
  target_compile_options(consumer_plan_check PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus /EHsc)
else()
  target_compile_options(consumer_plan_check PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
