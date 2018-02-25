cmake_minimum_required(VERSION 2.8)

PROJECT(tiny-asn1)

SET(LIB_SRC
  tiny-asn1.c
  tiny-asn1.h
 )
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -Werror")
SET(TINY-ASN1_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
MESSAGE(INCDE_OR: ${TINY-ASN1_INCLUDE_PATH})
add_library(tiny-asn1 ${LIB_SRC})
