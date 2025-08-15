cmake_minimum_required(VERSION 3.16)
project(create_ca_by_openssl VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL配置
option(USE_OPENSSL "Enable OpenSSL support" ON)
if(USE_OPENSSL)
    message(STATUS "OpenSSL support enabled")
    message(STATUS "OpenSSL headers: ${CMAKE_SOURCE_DIR}/include")
    message(STATUS "OpenSSL libraries: ${CMAKE_SOURCE_DIR}/lib")
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加子目录
add_subdirectory(src)

# 设置编译选项
if(MSVC)
    add_compile_options(/W4)
    # Windows下可能需要这些定义来避免OpenSSL的警告
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# 设置调试信息
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        add_compile_options(/Zi)
    else()
        add_compile_options(-g)
    endif()
endif()
