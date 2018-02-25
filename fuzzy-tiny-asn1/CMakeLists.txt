cmake_minimum_required(VERSION 2.8)

PROJECT(tiny-asn1)

enable_testing()

ADD_SUBDIRECTORY(src build)
ADD_SUBDIRECTORY(test test/build)
ADD_SUBDIRECTORY(examples examples/build)

include(CTest)

# add a target to generate API documentation with Doxygen
find_package(Doxygen)
set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf)
add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
