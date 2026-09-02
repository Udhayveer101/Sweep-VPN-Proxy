cmake_minimum_required(VERSION 3.20)
project(sweepovpn CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Path to the vendored openvpn3 checkout (DataPlane/openvpn/openvpn3).
set(OPENVPN3_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../openvpn/openvpn3" CACHE PATH
    "openvpn3 source tree")

add_library(sweepovpn STATIC
    src/sweepovpn.cpp
    ${OPENVPN3_DIR}/client/ovpncli.cpp
    ${OPENVPN3_DIR}/openvpn/crypto/data_epoch.cpp
)

target_include_directories(sweepovpn PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENVPN3_DIR}
    ${OPENVPN3_DIR}/client
)

# USE_TUN_BUILDER is what makes ovpncli.cpp route tun setup through
# TunBuilderBase instead of opening a utun itself. openvpn3 defines it
# automatically for iOS; on macOS it has to be asked for, and we want the same
# code path on both so there is only one behaviour to reason about.
target_compile_definitions(sweepovpn PRIVATE
    USE_TUN_BUILDER
    USE_ASIO
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
    HAVE_LZ4
    USE_OPENSSL
)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LZ4 REQUIRED liblz4)
find_package(fmt REQUIRED)

# asio, xxhash and jsoncpp are consumed as headers here; only fmt, lz4 and
# OpenSSL contribute objects we have to link.
find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)
find_path(XXHASH_INCLUDE_DIR xxhash.h REQUIRED)

target_include_directories(sweepovpn PRIVATE
    ${LZ4_INCLUDE_DIRS}
    ${ASIO_INCLUDE_DIR}
    ${XXHASH_INCLUDE_DIR}
)
# pkg-config hands back bare -l flags, which the linker cannot resolve without
# the matching search paths.
target_link_directories(sweepovpn PUBLIC ${LZ4_LIBRARY_DIRS})

target_link_libraries(sweepovpn PUBLIC
    OpenSSL::SSL OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    fmt::fmt
)

if(APPLE)
    target_compile_definitions(sweepovpn PRIVATE OPENVPN_PLATFORM_MAC)
endif()

# Standalone end-to-end check. Not part of the app; it exists so the packet
# path can be proven against a real relay without building the whole thing.
add_executable(harness test/harness.c)
target_link_libraries(harness PRIVATE sweepovpn)
set_target_properties(harness PROPERTIES LINKER_LANGUAGE CXX)
