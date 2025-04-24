cmake_minimum_required(VERSION 3.16)
project(api CXX)

set(CMAKE_CXX_STANDARD 20)

find_package(userver REQUIRED COMPONENTS core)

add_executable(${PROJECT_NAME} main.cpp
    cors_middleware.hpp
    reports_handler.hpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE userver::core)