cmake_minimum_required(VERSION 3.26)
project(xuclid)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin)

find_package(OpenSSL REQUIRED)

add_executable(xuclid main.cpp)
target_link_libraries(xuclid PRIVATE OpenSSL::SSL)
