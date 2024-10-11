vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO 4xicom/personal
    REF 15efe822069c82757fd5bbe82440a8acd8be1886
    SHA512 8fdae4b4ed5be37bc6bc208f73d74446edbe873524076a51694780503ee2e91a35321a8ebc36220d310db225f39aa500123bacb0eb8e7f71342717739425f51a
    HEAD_REF master
)


vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/entraidkafka"
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME "entraidkafka")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

configure_file("${CMAKE_CURRENT_LIST_DIR}/usage" "${CURRENT_PACKAGES_DIR}/share/${PORT}/usage" COPYONLY)