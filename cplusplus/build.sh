#!/bin/bash
echo "Building create_ca_by_openssl project..."

# 创建构建目录
mkdir -p build
cd build

# 配置项目
cmake .. -DCMAKE_BUILD_TYPE=Release

# 构建项目
make -j$(nproc)

echo "Build completed!"
