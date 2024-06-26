cmake_minimum_required(VERSION 3.22)
project(HybridEncryption)

set(CMAKE_CXX_STANDARD 17)

add_executable(HybridEncryption
        sample/hybridencryption.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY /sample)
include_directories(/opt/homebrew/opt/openssl@3/include)
target_link_libraries(${PROJECT_NAME} /opt/homebrew/opt/openssl@3/lib/libcrypto.a)
