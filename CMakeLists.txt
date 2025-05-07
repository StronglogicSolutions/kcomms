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

# Signal server executable
add_executable(signal_server
  main.cpp
  server.cpp
  database.cpp
)

# Link libraries
target_link_libraries(signal_server
  PRIVATE
    Boost::asio
    Boost::system
    SQLiteCpp
    nlohmann_json::nlohmann_json
)

# Include directories (if needed)
target_include_directories(signal_server
  PRIVATE
    ${THIRD_PARTY_DIR}/boost
    ${THIRD_PARTY_DIR}/sqlitecpp/include
    ${THIRD_PARTY_DIR}/nlohmann_json/include
)
