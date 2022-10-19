cmake_minimum_required(VERSION 3.0.0)

project(parsepe)

add_executable(memloader memory_loader.cc section_table.cc va_foa.cc memory_loader.h memory_main.cc)

# add_executable()