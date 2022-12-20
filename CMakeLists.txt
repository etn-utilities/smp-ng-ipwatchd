cmake_minimum_required(VERSION 3.10)
project(ipwatchd)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/.gitignore" "*")

include(GNUInstallDirs)

add_subdirectory(src)
