cmake_minimum_required(VERSION 2.8)

PROJECT(tiny-asn1)

find_package(PkgConfig)
pkg_search_module(libcheck REQUIRED
  check
)

include_directories(${libcheck_INCLUDE_DIRS} ../src)
set(LIBS ${LIBS}
  tiny-asn1
  ${libcheck_LIBRARIES}
  pthread # this should be included with libcheck_LIBRARIES. For some reason, it is not
)


execute_process(
  COMMAND ./prep_test.sh
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  RESULT_VARIABLE prep_test_result
)

add_executable(test_tiny-asn1 test.c )
target_link_libraries(test_tiny-asn1 ${LIBS})

add_test(NAME test_tiny-asn1
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_tiny-asn1
)
