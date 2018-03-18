add_library(mmtracer SHARED mmtracer.c)
find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")

endif(NOT DynamoRIO_FOUND)
configure_DynamoRIO_client(mmtracer)
use_DynamoRIO_extension(mmtracer drmgr)
