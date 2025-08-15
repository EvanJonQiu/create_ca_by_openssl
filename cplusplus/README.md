# create_ca_by_openssl C++ Project

这是一个使用CMake构建的C++项目，集成了OpenSSL库。

## 项目结构

```
cplusplus/
├── CMakeLists.txt          # 主CMake配置文件
├── src/
│   ├── CMakeLists.txt      # 源文件CMake配置
│   └── main.cpp            # 主程序源文件
├── include/                 # 头文件目录
│   └── openssl/            # OpenSSL头文件
├── lib/                     # 静态库目录
│   ├── libssl.lib          # OpenSSL SSL库 (Windows)
│   └── libcrypto.lib       # OpenSSL Crypto库 (Windows)
├── build.bat               # Windows构建脚本
├── build.sh                # Linux/macOS构建脚本
└── .gitignore             # Git忽略文件
```

## 构建要求

- CMake 3.16 或更高版本
- 支持C++17的编译器
- Windows: Visual Studio 2022 或更高版本
- Linux/macOS: GCC 7+ 或 Clang 5+
- OpenSSL库文件（已包含在项目中）

## OpenSSL集成

项目已预配置OpenSSL支持：

- **头文件**: 位于 `include/openssl/` 目录
- **静态库**: 位于 `lib/` 目录
- **自动链接**: CMake自动链接所需的OpenSSL库

### OpenSSL版本信息

程序运行时会显示：
- OpenSSL版本字符串
- OpenSSL版本号
- 库初始化状态

## 构建步骤

### Windows

1. 双击运行 `build.bat`
2. 或者手动执行：
   ```cmd
   mkdir build
   cd build
   cmake .. -G "Visual Studio 17 2022" -A x64
   cmake --build . --config Release
   ```

### Linux/macOS

1. 运行构建脚本：
   ```bash
   chmod +x build.sh
   ./build.sh
   ```
2. 或者手动执行：
   ```bash
   mkdir build
   cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   make -j$(nproc)
   ```

## 运行程序

构建完成后，可执行文件位于 `build/bin/` 目录下：

```bash
# Windows
build\bin\Release\create_ca_by_openssl.exe

# Linux/macOS
build/bin/create_ca_by_openssl
```

运行后应该看到OpenSSL版本信息和初始化成功消息。

## 配置选项

- `CMAKE_BUILD_TYPE`: 构建类型 (Debug/Release)
- `CMAKE_CXX_STANDARD`: C++标准版本 (默认17)
- `USE_OPENSSL`: 是否启用OpenSSL支持 (默认ON)

## 添加更多OpenSSL功能

在 `src/main.cpp` 中可以添加更多OpenSSL功能：

```cpp
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

// 创建证书
// 生成密钥对
// 签名验证
// 等等...
```

## 清理构建

```bash
rm -rf build/          # Linux/macOS
rmdir /s build         # Windows
```

## 故障排除

如果遇到链接错误：

1. 确保 `lib/` 目录包含正确的库文件
2. 检查库文件是否与目标平台匹配
3. 验证CMake版本是否满足要求
