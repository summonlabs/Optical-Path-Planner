add_executable(opp_cli opp_cli.cpp)
target_link_libraries(opp_cli PRIVATE SummonSoftwareLabs::OpticalPathPlanner)
opp_apply_strict_options(opp_cli)
opp_stage_asan_runtime(opp_cli)

add_executable(oppd oppd.cpp)
target_link_libraries(oppd PRIVATE SummonSoftwareLabs::OpticalPathPlanner)
opp_apply_strict_options(oppd)
opp_stage_asan_runtime(oppd)

install(TARGETS opp_cli oppd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
