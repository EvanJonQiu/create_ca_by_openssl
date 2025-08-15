# 设置源文件
set(SOURCES
    main.cpp
    certificate_creator.cpp
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 设置包含目录
target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
)

# 设置库文件目录
target_link_directories(${PROJECT_NAME} 
    PRIVATE 
        ${CMAKE_SOURCE_DIR}/lib
)

# 链接OpenSSL静态库
if(WIN32)
    # Windows平台使用.lib文件
    target_link_libraries(${PROJECT_NAME} 
        PRIVATE
            libssl.lib
            libcrypto.lib
            ws2_32.lib      # Windows Socket库
            crypt32.lib     # 加密API库
            advapi32.lib    # 高级Windows 32 API
    )
else()
    # Linux/macOS平台使用.a文件
    target_link_libraries(${PROJECT_NAME} 
        PRIVATE
            libssl.a
            libcrypto.a
    )
endif()

# 设置目标属性
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "create_ca_by_openssl"
)
