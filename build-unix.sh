#!/bin/bash
# Linux/macOS build script for vscpl2drv-logger

mkdir -p build
cd build

# Configure with Unix Makefiles generator explicitly
cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug

# Build the project
make

echo "Build completed!"