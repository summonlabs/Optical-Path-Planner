set(OPP_EXAMPLES
  example_quickstart
  example_constraints
  example_evidence
  example_service
)

foreach(example IN LISTS OPP_EXAMPLES)
  add_executable(${example} ${example}.cpp)
  target_link_libraries(${example} PRIVATE SummonSoftwareLabs::OpticalPathPlanner)
  opp_apply_strict_options(${example})
  opp_stage_asan_runtime(${example})
endforeach()
