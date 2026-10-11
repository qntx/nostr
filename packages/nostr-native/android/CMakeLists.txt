project(QntxNostrNative)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME QntxNostrNative)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Vendored libsecp256k1 modules needed by cpp/nostr_native.c (its single-TU include of
# vendor/secp256k1/src/secp256k1.c reads these defines).
add_definitions(-DENABLE_MODULE_EXTRAKEYS -DENABLE_MODULE_SCHNORRSIG)

# C glue + C++ hybrid. nostr_native.c itself includes the vendored secp256k1.c — the only
# separately-compiled vendor sources are the two precomputed tables below.
file(GLOB_RECURSE shared_files RELATIVE ${CMAKE_SOURCE_DIR}
     "../cpp/**.cpp" "../cpp/**.c" "src/main/cpp/**.cpp"
)

add_library(${PACKAGE_NAME} SHARED
            ${shared_files}
            "../vendor/secp256k1/src/precomputed_ecmult.c"
            "../vendor/secp256k1/src/precomputed_ecmult_gen.c"
)

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/QntxNostrNative+autolinking.cmake)

include_directories(
        "../cpp"
        "../vendor/secp256k1/include"
)

find_library(LOG_LIB log)

target_link_libraries(
        ${PACKAGE_NAME}
        ${LOG_LIB}
        android
)
