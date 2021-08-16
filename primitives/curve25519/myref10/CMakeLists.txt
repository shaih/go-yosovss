cmake_minimum_required(VERSION 3.20)
project(myref10 C)

set(CMAKE_C_STANDARD 11)
add_compile_options(-Wall -Wextra -pedantic)

# Add directories for extra cmake files, e.g. to find NTK and other libraries
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(sodium)
# define the following variables (see ./cmake/FindSodium.make)
#   sodium_FOUND
#   sodium_INCLUDE_DIR
#   sodium_LIBRARY_DEBUG
#   sodium_LIBRARY_RELEASE

include_directories(.)

add_library(myref10
        myref10.c
        myref10.h myref10.c myref10.h
        private/chacha20_ietf_ext.h
        private/common.h
        private/ed25519_ref10.h
        private/ed25519_ref10_fe_25_5.h
        private/ed25519_ref10_fe_51.h
        private/implementations.h
        private/mutex.h
        private/quirks.h
        private/sse2_64_32.h
        ed25519_ref10.c
        ref10/fe_51/base.h
        ref10/fe_51/base2.h
        ref10/fe_51/constants.h
        ref10/fe_51/fe.h
        ref10/fe_25_5/base.h
        ref10/fe_25_5/base2.h
        ref10/fe_25_5/constants.h
        ref10/fe_25_5/fe.h)

target_include_directories(myref10 PUBLIC
        ${sodium_INCLUDE_DIR}
        )

target_link_libraries(myref10 PUBLIC
        ${sodium_LIBRARY_RELEASE}
        )

add_executable(main
        main/main.c)

target_link_libraries(main PRIVATE myref10)
