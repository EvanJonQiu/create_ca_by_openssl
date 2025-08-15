@echo off
echo Building create_ca_by_openssl project...

REM 创建构建目录
if not exist "build" mkdir build
cd build

REM 配置项目 - 使用VS2022
cmake .. -G "Visual Studio 17 2022" -A x64

REM 构建项目
cmake --build . --config Release

echo Build completed!
pause
