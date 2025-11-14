cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME storagebox)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

include_directories(src/include)

set(EXTENSION_SOURCES
    src/storagebox_extension.cpp
    src/storagebox_filesystem.cpp
    src/storagebox_ssh_integration.cpp
    src/storagebox_secrets.cpp
    src/httpfs.cpp
    src/httpfs_curl_client.cpp
    src/http_state.cpp
    src/crypto.cpp
    src/hash_functions.cpp
    src/ssh_client.cpp
)

# Use pkg-config to find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(LIBSSH2 REQUIRED libssh2)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link against OpenSSL, CURL, and libssh2
target_include_directories(${EXTENSION_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS} ${LIBSSH2_INCLUDE_DIRS})
target_link_libraries(${EXTENSION_NAME} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${LIBSSH2_LIBRARIES})

target_include_directories(${LOADABLE_EXTENSION_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS} ${LIBSSH2_INCLUDE_DIRS})
target_link_libraries(${LOADABLE_EXTENSION_NAME} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${LIBSSH2_LIBRARIES})

install(
    TARGETS ${EXTENSION_NAME}
    EXPORT "${DUCKDB_EXPORT_SET}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
