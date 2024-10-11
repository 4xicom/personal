vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO 4xicom/personal
    REF c690a29a856e9537ce6a63282424fa35d0bb666d
    SHA512 0
    HEAD_REF master
)


vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/public/cpp/entraidkafka"
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME "entraidkafka")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

configure_file("${CMAKE_CURRENT_LIST_DIR}/usage" "${CURRENT_PACKAGES_DIR}/share/${PORT}/usage" COPYONLY)