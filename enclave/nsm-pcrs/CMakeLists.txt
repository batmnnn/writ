# writ-nsm-pcrs. Links the libnsm.so and nsm.h that enclave/Dockerfile builds from
# aws-nitro-enclaves-nsm-api at commit 4b851f3006c6fa98f23dcffb2cba03b39de9b8af and installs
# under /usr. Configure with the same prefix, for example -DCMAKE_PREFIX_PATH=/usr.
cmake_minimum_required(VERSION 3.9)
project(writ-nsm-pcrs C)

find_library(NSM_LIB NAMES nsm PATHS /usr/lib64 /usr/lib REQUIRED)
find_path(NSM_INC NAMES nsm.h PATHS /usr/include REQUIRED)

add_executable(writ-nsm-pcrs main.c)
set_target_properties(writ-nsm-pcrs PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
target_compile_options(writ-nsm-pcrs PRIVATE -Wall -Wextra -Werror)
target_include_directories(writ-nsm-pcrs PRIVATE "${NSM_INC}")
target_link_libraries(writ-nsm-pcrs "${NSM_LIB}")

install(TARGETS writ-nsm-pcrs RUNTIME DESTINATION bin)
