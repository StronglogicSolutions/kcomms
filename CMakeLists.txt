cmake_minimum_required(VERSION 3.15)
project(signal_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Third-party directories
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)

# Boost: Build only Asio and System
set(BOOST_INCLUDE_LIBRARIES asio system)
set(BOOST_ENABLE_CMAKE ON)
add_subdirectory(${THIRD_PARTY_DIR}/boost boost EXCLUDE_FROM_ALL)

# SQLiteCpp: Build with SQLite dependency
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "Disable SQLiteCpp tests")
add_subdirectory(${THIRD_PARTY_DIR}/sqlitecpp sqlitecpp EXCLUDE_FROM_ALL)

# nlohmann/json: Header-only library
add_subdirectory(${THIRD_PARTY_DIR}/nlohmann_json nlohmann_json EXCLUDE_FROM_ALL)

# libsignal-protocol-c
add_subdirectory(${THIRD_PARTY_DIR}/libsignal_protocol_c libsignal_protocol_c EXCLUDE_FROM_ALL)

# Server executable
add_executable(signal_server
  server/main.cpp
  server/server.cpp
  server/database.cpp
)

target_link_libraries(signal_server
  PRIVATE
    Boost::asio
    Boost::system
    SQLiteCpp
    nlohmann_json::nlohmann_json
)

target_include_directories(signal_server
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
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
    Boost::asio
    Boost::system
    SQLiteCpp
    nlohmann_json::nlohmann_json
    ${CMAKE_BINARY_DIR}/libsignal_protocol_c/src/libsignal-protocol-c.a
    ssl
    crypto
)

target_include_directories(signal_client
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
    ${THIRD_PARTY_DIR}/libsignal_protocol_c/src
)
