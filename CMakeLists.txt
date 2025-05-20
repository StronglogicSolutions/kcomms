cmake_minimum_required(VERSION 3.15)
project(kcomms_server)

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
  set(SQLITECPP_INCLUDE_DIR /usr/local/sqlitecpp-darwin/include)
  set(SQLITECPP_LIBRARY /usr/local/sqlitecpp-darwin/lib/libSQLiteCpp.a)
else()

# Path to libsodium (built in third_party/sodium)
set(SODIUM_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/sodium")
set(SODIUM_LIB "${SODIUM_SOURCE_DIR}/src/libsodium/.libs/libsodium.a")
set(SODIUM_INCLUDE_DIR "${SODIUM_SOURCE_DIR}/src/libsodium/include")

# Verify libsodium library exists
if(NOT EXISTS ${SODIUM_LIB})
    message(FATAL_ERROR "libsodium library not found at ${SODIUM_LIB}. Please build libsodium in ${SODIUM_SOURCE_DIR}.")
endif()
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

# klogger
add_subdirectory(${THIRD_PARTY_DIR}/klogger klogger EXCLUDE_FROM_ALL)

# Server executable
add_executable(kcomms_server
  server/main.cpp
  server/server.cpp
  server/database.cpp
)

target_link_libraries(kcomms_server
  PRIVATE
    ${Boost_LIBRARIES}
    SQLiteCpp
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    PRIVATE klogger::klog
    #    $<$<PLATFORM_ID:Windows>:ws2_32>
)

target_include_directories(kcomms_server
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
    ${THIRD_PARTY_DIR}/klogger/src
    $<$<OR:$<PLATFORM_ID:Windows>,$<PLATFORM_ID:Darwin>>:${SQLITECPP_INCLUDE_DIR}>
)

# Client executable
add_executable(kcomms_client
  client/main.cpp
  client/client.cpp
  client/cli.cpp
)

target_link_libraries(kcomms_client
  PRIVATE
    ${Boost_LIBRARIES}
    SQLiteCpp
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SODIUM_LIB}
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

target_include_directories(kcomms_client
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
    ${SODIUM_INCLUDE_DIR}
    ${THIRD_PARTY_DIR}/klogger/src
    $<$<OR:$<PLATFORM_ID:Windows>,$<PLATFORM_ID:Darwin>>:${SQLITECPP_INCLUDE_DIR}>
)
