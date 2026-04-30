target_sources(pl PRIVATE
    appcompat.cpp
    hook.cpp
    loader.cpp
    mmap.cpp
    pl.cpp
    options.cpp
)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_sources(pl PRIVATE pic_x64.asm)
endif()
target_link_libraries(pl_shared PUBLIC Shlwapi.lib)
target_link_libraries(pl_static PUBLIC Shlwapi.lib)

if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    target_sources(run PRIVATE run.cpp)

    target_sources(testdll PRIVATE dllmain.cpp)
    
    if (PL_BUILD_GUI)
        target_sources(gui PRIVATE gui.cpp gui_icons.rc)
        target_link_libraries(gui PRIVATE d3d11.lib)
    endif()
endif()