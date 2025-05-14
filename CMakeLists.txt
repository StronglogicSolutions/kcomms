cmake_minimum_required(VERSION 3.15)
project(signal_server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Third-party directories
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)

# Default to Linux
set(TARGET_OS "Linux" CACHE STRING "Target OS: Linux, Windows, or Darwin")
if(TARGET_OS STREQUAL "Windows")
  set(CMAKE_SYSTEM_NAME Windows)
  set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
  set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
  set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
  set(CMAKE_AR x86_64-w64-mingw32-ar)
  set(CMAKE_RANLIB x86_64-w64-mingw32-ranlib)
  set(BOOST_ROOT /usr/local/boost-windows)
  set(SQLITE3_LIBRARY /usr/local/sqlite-windows/lib/libsqlite3.a)
  set(OPENSSL_ROOT_DIR /usr/local/openssl-windows)
  set(LIBSIGNAL_LIB /usr/local/libsignal-windows/lib/libsignal_protocol.a)
  set(SQLITECPP_INCLUDE_DIR /usr/local/sqlitecpp-windows/include)
  set(SQLITECPP_LIBRARY /usr/local/sqlitecpp-windows/lib/libSQLiteCpp.a)
elseif(TARGET_OS STREQUAL "Darwin")
  set(CMAKE_SYSTEM_NAME Darwin)
  set(CMAKE_C_COMPILER x86_64-apple-darwin24.5.0-clang)
  set(CMAKE_CXX_COMPILER x86_64-apple-darwin24.5.0-clang++)
  set(CMAKE_AR x86_64-apple-darwin24.5.0-ar)
  set(CMAKE_RANLIB x86_64-apple-darwin24.5.0-ranlib)
  set(CMAKE_OSX_SYSROOT /usr/local/osxcross/SDK/MacOSX14.5.sdk)
  set(BOOST_ROOT /usr/local/boost-darwin)
  set(SQLITE3_LIBRARY /usr/local/sqlite-darwin/lib/libsqlite3.a)
  set(OPENSSL_ROOT_DIR /usr/local/openssl-darwin)
  set(LIBSIGNAL_LIB /usr/local/libsignal-darwin/lib/libsignal_protocol.a)
  set(SQLITECPP_INCLUDE_DIR /usr/local/sqlitecpp-darwin/include)
  set(SQLITECPP_LIBRARY /usr/local/sqlitecpp-darwin/lib/libSQLiteCpp.a)
else()
  set(LIBSIGNAL_LIB libsignal-protocol-c) # Reference the CMake target
  #  set(LIBSIGNAL_LIB ${CMAKE_BINARY_DIR}/libsignal_protocol_c/src/libsignal-protocol-c.a)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Boost: Build Asio and System
set(BOOST_INCLUDE_LIBRARIES asio system)
set(BOOST_ENABLE_CMAKE ON)
add_subdirectory(${THIRD_PARTY_DIR}/boost boost EXCLUDE_FROM_ALL)
set(Boost_LIBRARIES Boost::asio Boost::system)

# SQLiteCpp: Build with SQLite dependency
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "Disable SQLiteCpp tests")
if(TARGET_OS STREQUAL "Windows" OR TARGET_OS STREQUAL "Darwin")
  add_library(SQLite3 STATIC IMPORTED)
  set_property(TARGET SQLite3 PROPERTY IMPORTED_LOCATION ${SQLITE3_LIBRARY})
  add_library(SQLiteCpp STATIC IMPORTED)
  set_property(TARGET SQLiteCpp PROPERTY IMPORTED_LOCATION ${SQLITECPP_LIBRARY})
else()
  add_subdirectory(${THIRD_PARTY_DIR}/sqlitecpp sqlitecpp EXCLUDE_FROM_ALL)
endif()

# nlohmann/json: Header-only
add_subdirectory(${THIRD_PARTY_DIR}/nlohmann_json nlohmann_json EXCLUDE_FROM_ALL)

# libsignal-protocol-c
add_subdirectory(${THIRD_PARTY_DIR}/libsignal_protocol_c libsignal_protocol_c EXCLUDE_FROM_ALL)

# klogger
add_subdirectory(${THIRD_PARTY_DIR}/klogger klogger EXCLUDE_FROM_ALL)

# Server executable
add_executable(signal_server
  server/main.cpp
  server/server.cpp
  server/database.cpp
)

target_link_libraries(signal_server
  PRIVATE
    ${Boost_LIBRARIES}
    SQLiteCpp
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    PRIVATE klogger::klog
    #    $<$<PLATFORM_ID:Windows>:ws2_32>
)

target_include_directories(signal_server
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
    ${THIRD_PARTY_DIR}/klogger/src
    $<$<OR:$<PLATFORM_ID:Windows>,$<PLATFORM_ID:Darwin>>:${SQLITECPP_INCLUDE_DIR}>
)

# Client executable
add_executable(signal_client
  client/main.cpp
  client/client.cpp
  client/storage.cpp
  client/cli.cpp
)

target_link_libraries(signal_client
  PRIVATE
    ${Boost_LIBRARIES}
    SQLiteCpp
    nlohmann_json::nlohmann_json
    #OpenSSL::SSL
    #OpenSSL::Crypto
    ${CMAKE_BINARY_DIR}/libsignal_protocol_c/src/libsignal-protocol-c.a
    ssl
    crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

target_include_directories(signal_client
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
    ${THIRD_PARTY_DIR}/libsignal_protocol_c/src
    ${THIRD_PARTY_DIR}/klogger/src
    $<$<OR:$<PLATFORM_ID:Windows>,$<PLATFORM_ID:Darwin>>:${SQLITECPP_INCLUDE_DIR}>
)
