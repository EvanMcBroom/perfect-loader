target_sources(pl PRIVATE
    appcompat.cpp
    evasion.cpp
    hook.cpp
    loader.cpp
    mmap.cpp
    pl.cpp
)
target_link_libraries(pl_shared PUBLIC KtmW32.lib)
target_link_libraries(pl_static PUBLIC KtmW32.lib)

if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    target_sources(run PRIVATE run.cpp)

    target_sources(testdll PRIVATE dllmain.cpp)
endif()