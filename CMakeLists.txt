# MIT License
# 
# Copyright (c) 2015-2024 Vector 35 Inc
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.24)
set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64")
project(NativePredicateSolver CXX)

set(CMAKE_CXX_STANDARD 17)

set(HEADLESS 1)
find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h mediumlevelilinstruction.h
        # List of paths to search for the clone of the api
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
)
add_subdirectory(${BN_API_PATH} api)

set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "Build Z3 as a static library" FORCE)
set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "Don't build Z3 executable" FORCE)
set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "Don't build Z3 test executables" FORCE)
set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "Don't build Z3 examples" FORCE)
set(Z3_BUILD_PYTHON_BINDINGS OFF CACHE BOOL "Don't build Python bindings" FORCE)
set(Z3_BUILD_DOTNET_BINDINGS OFF CACHE BOOL "Don't build .NET bindings" FORCE)
set(Z3_BUILD_JAVA_BINDINGS OFF CACHE BOOL "Don't build Java bindings" FORCE)
add_subdirectory(z3)

if(TARGET libz3)
    target_include_directories(libz3 INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/z3/src/api/c++>
    )
endif()

if(NOT TARGET z3::libz3)
    add_library(z3::libz3 ALIAS libz3)
endif()

add_library(${PROJECT_NAME} SHARED library.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC binaryninjaapi z3::libz3)

bn_install_plugin(${PROJECT_NAME})
