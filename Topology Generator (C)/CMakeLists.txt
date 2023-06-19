cmake_minimum_required(VERSION 3.24)
project(topology C)
set(GCC_COVERAGE_COMPILE_FLAGS "-Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(topology
        gen.c
        gen.h
        main.c
        types.h)
