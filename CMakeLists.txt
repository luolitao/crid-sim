cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Set the name of your project here
set(SUPPORTED_TARGETS esp32)
project(esp32-rid-sim)

# 启用 Unity 测试支持
# include(IdfTest)

# Optional: Suppress specific warnings if needed (not recommended for format issues, fix the source)
# add_compile_options("-Wno-format")
