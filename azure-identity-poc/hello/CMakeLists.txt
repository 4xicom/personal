# CMakeList.txt : CMake project for hello, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.10)


project ("hello")

find_package(azure-identity-cpp CONFIG REQUIRED)
# Add source to this project's executable.
add_executable (hello "hello.cpp" "hello.h")

target_link_libraries(hello PRIVATE  Azure::azure-identity)
# TODO: Add tests and install targets if needed.
