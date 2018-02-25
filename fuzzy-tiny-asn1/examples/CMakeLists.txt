cmake_minimum_required(VERSION 2.8)

PROJECT(tiny-asn1)

include_directories(${TINY-ASN1_INCLUDE_PATH})
include_directories(${CMAKE_SOURCE_DIR}/src)
MESSAGE(INCDE: ${TINY-ASN1_INCLUDE_PATH})

add_executable(parse_cms parse_cms.c)
target_link_libraries(parse_cms tiny-asn1)
