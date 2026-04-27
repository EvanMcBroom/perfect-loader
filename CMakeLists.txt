cmake_minimum_required(VERSION 3.24.0)
project(perfect-loader
    VERSION "2.0"
    DESCRIPTION "A perfect loader implementation"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/perfect-loader"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Define an object library to build equivalent shared and static libraries
add_library(pl OBJECT)
set_property(TARGET pl PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories(pl PUBLIC include)
add_library(pl_shared SHARED $<TARGET_OBJECTS:pl>)
add_library(pl_static STATIC $<TARGET_OBJECTS:pl>)
set_target_properties(pl_shared PROPERTIES OUTPUT_NAME pl)
set_target_properties(pl_static PROPERTIES OUTPUT_NAME pl)
target_include_directories(pl_shared PUBLIC include)
target_include_directories(pl_static PUBLIC include)

target_sources(pl PRIVATE
    include/perfect_loader.h
    include/perfect_loader.hpp
    include/pl/hook.hpp
    include/pl/lazy.hpp
    include/pl/mmap.hpp
    include/pl/pe.hpp
    include/pl/types.hpp
)

if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    add_executable(run)
    target_link_libraries(run PRIVATE pl_static)

    add_library(testdll SHARED)
endif()

add_subdirectory(source)