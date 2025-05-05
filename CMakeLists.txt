cmake_minimum_required(VERSION 3.24.0)
project(perfect-loader
    VERSION "1.0"
    DESCRIPTION "A perfect loader implementation"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/perfect-loader"
    LANGUAGES C CXX
)
if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    set(MAIN_PROJECT TRUE)
    set(CLIB pl)
else()
    set(MAIN_PROJECT FALSE)
    set(PROJECT_NAME "library_pl++")
    set(CLIB library_pl)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE
    include/perfect_loader.hpp
    include/pl/hook.hpp
    include/pl/lazy.hpp
    include/pl/mmap.hpp
    include/pl/pe.hpp
    include/pl/types.hpp
)
target_include_directories(${PROJECT_NAME} PUBLIC include)
set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)


add_library(${CLIB} SHARED)
target_sources(${CLIB} PRIVATE include/perfect_loader.h)
target_link_libraries(${CLIB} PRIVATE ${PROJECT_NAME})

if (${MAIN_PROJECT})
    add_executable(run)
    target_link_libraries(run PRIVATE ${CLIB} ${PROJECT_NAME})

    add_library(testdll SHARED)
    target_link_libraries(testdll PRIVATE ${PROJECT_NAME})
endif()

add_subdirectory(source)
