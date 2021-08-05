cmake_minimum_required(VERSION 3.20)
project(vss)

set(CMAKE_CXX_STANDARD 17)

# Add directories for extra cmake files, e.g. to find NTK and other libraries
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(NTL)
# define the following variables (see ./cmake/FindNTL.make)
#   NTL_FOUND
#   NTL_LIBRARIES
#   NTL_INCLUDE_PATHS

include_directories(.)

add_library(vss
        algebra.hpp
        parity.cpp
        parity_go.h parity_go.cpp parity.h)

target_include_directories(vss PUBLIC
        ${NTL_INCLUDE_PATHS}
        )
