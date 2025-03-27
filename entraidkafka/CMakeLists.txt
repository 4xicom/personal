cmake_minimum_required(VERSION 3.10)

project(EntraIdKafka)

# Find the library
find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(RdKafka CONFIG REQUIRED)



# Add your library
add_library(EntraIdKafka STATIC
    src/entraidkafka.cpp
    src/entraidwindowscert.cpp
)

# add_library(entraidkafka SHARED entraidkafka.cpp entraidkafka.h)

# Link your library 

target_link_libraries(EntraIdKafka PRIVATE  Azure::azure-core Azure::azure-identity)
target_link_libraries(EntraIdKafka PRIVATE  OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(EntraIdKafka PRIVATE  RdKafka::rdkafka RdKafka::rdkafka++)


# Add include directories
target_include_directories(EntraIdKafka PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>   # for headers when building
    $<INSTALL_INTERFACE:include>  # for client in install mode
)
# Install the library and its headers
install(TARGETS EntraIdKafka
        EXPORT EntraIdKafka_targets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

install(FILES inc/entraidkafka.h DESTINATION include)


# Generate and install *-targets.cmake 
install(EXPORT EntraIdKafka_targets
        FILE EntraIdKafka-targets.cmake
        NAMESPACE EntraIdKafka::
        DESTINATION share/EntraIdKafka)

# Generate the config file in the current binary dir (this ensures it's not placed directly in source)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/EntraIdKafka-config.cmake"
"include(CMakeFindDependencyMacro)\n"
"find_dependency(azure-identity-cpp CONFIG REQUIRED)\n"
"find_dependency(OpenSSL CONFIG REQUIRED)\n"
"find_dependency(RdKafka CONFIG REQUIRED)\n"
"include(\"\${CMAKE_CURRENT_LIST_DIR}/EntraIdKafka-targets.cmake\")\n"
)

# Install the generated config file
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/EntraIdKafka-config.cmake"
        DESTINATION share/EntraIdKafka)
