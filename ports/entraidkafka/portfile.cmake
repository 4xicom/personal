vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO 4xicom/personal
    REF 4bbb4bcdb358339ffa0dcc2119292b329d8a7cb4
    SHA512 b6013e795d266890e63e09b18a85d3a8aa09de443f96bc9a9ffee792f53a86dae39553e12d4e2165c790be9f5202c895a61c3b92297e22ee84f095bd1c2e0160
    HEAD_REF master
)


vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/public/cpp/entraidkafka"
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME "entraidkafka")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

configure_file("${CMAKE_CURRENT_LIST_DIR}/usage" "${CURRENT_PACKAGES_DIR}/share/${PORT}/usage" COPYONLY)