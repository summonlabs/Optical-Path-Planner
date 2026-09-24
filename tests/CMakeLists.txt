set(OPP_TEST_SUITES
  core
  oracle
  adversarial
  race
)

foreach(suite IN LISTS OPP_TEST_SUITES)
  add_executable(opp_tests_${suite} test_main.cpp test_support.cpp process_support.cpp ${suite}_tests.cpp)
  target_link_libraries(opp_tests_${suite} PRIVATE SummonSoftwareLabs::OpticalPathPlanner)
  target_include_directories(opp_tests_${suite} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  opp_apply_strict_options(opp_tests_${suite})
  if(WIN32)
    target_compile_definitions(opp_tests_${suite} PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(opp_tests_${suite} PRIVATE ws2_32)
  endif()
  # The race suite orchestrates real oppd processes through the built binary.
  target_compile_definitions(opp_tests_${suite} PRIVATE OPP_DAEMON_BINARY="$<TARGET_FILE:oppd>")
  target_compile_definitions(opp_tests_${suite} PRIVATE OPP_CLI_BINARY="$<TARGET_FILE:opp_cli>")
  add_dependencies(opp_tests_${suite} oppd opp_cli)
  add_test(NAME ${suite} COMMAND opp_tests_${suite})
  opp_stage_asan_runtime(opp_tests_${suite})
endforeach()
