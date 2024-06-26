cmake_minimum_required(VERSION 3.22)
project(Hash)

set(CMAKE_CXX_STANDARD 17)

add_executable(Hash sample/hash.cpp)

include_directories(/opt/homebrew/opt/openssl@3/include)
target_link_libraries(${PROJECT_NAME} /opt/homebrew/opt/openssl@3/lib/libcrypto.a)
