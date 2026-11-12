# kmstool_reply. Builds against an installed aws-nitro-enclaves-sdk-c at commit
# f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923 (v0.4.6), the commit enclave/Dockerfile already builds.
# Configure with the same prefix as the SDK, for example -DCMAKE_PREFIX_PATH=/usr.
cmake_minimum_required(VERSION 3.9)
project(kmstool-reply C)

find_package(aws-nitro-enclaves-sdk-c REQUIRED)

# The SDK's exported target names LibJsonC::Json. json-c's own package does not
# define that name, and the SDK find-module is not on the consumer module path.
if(NOT TARGET LibJsonC::Json)
  find_library(JSONC_LIB NAMES libjson-c.a json-c PATHS /usr/lib64 /usr/lib REQUIRED)
  find_path(JSONC_INC NAMES json-c/json.h PATHS /usr/include REQUIRED)
  add_library(LibJsonC::Json UNKNOWN IMPORTED)
  set_target_properties(LibJsonC::Json PROPERTIES
    IMPORTED_LOCATION "${JSONC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${JSONC_INC}")
endif()

add_executable(kmstool_reply main.c)
set_target_properties(kmstool_reply PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
target_compile_options(kmstool_reply PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(kmstool_reply AWS::aws-nitro-enclaves-sdk-c)

install(TARGETS kmstool_reply RUNTIME DESTINATION bin)
