cmake_minimum_required(VERSION 3.22)
project(EncryptionModes)

set(CMAKE_CXX_STANDARD 17)

add_executable(EncryptionModes
        sample/emodes.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY /sample)
include_directories(/opt/homebrew/opt/openssl@3/include)
target_link_libraries(${PROJECT_NAME} /opt/homebrew/opt/openssl@3/lib/libcrypto.a)
