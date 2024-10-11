cmake_minimum_required (VERSION 3.10)


project ("entraidkafkaclient")

find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(Rdkafka CONFIG REQUIRED)
find_package(entraidkafka CONFIG REQUIRED)

# Add source to this project's executable.
add_executable (entraidkafkaclient "entraidkafkaclient.cpp" "entraidkafkaclient.h")

target_link_libraries(entraidkafkaclient PRIVATE  Azure::azure-identity)
target_link_libraries(entraidkafkaclient PRIVATE  OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(entraidkafkaclient PRIVATE  RdKafka::rdkafka RdKafka::rdkafka++)
target_link_libraries(entraidkafkaclient PRIVATE  entraidkafka::entraidkafka)

