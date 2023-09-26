target_sources(${PROJECT_NAME} PRIVATE
    hook.cpp
    loader.cpp
    mmap.cpp
)
target_link_libraries(${PROJECT_NAME} PUBLIC KtmW32.lib)

if (${MAIN_PROJECT})
    target_sources(run PRIVATE run.cpp)
    target_link_libraries(run PRIVATE ${PROJECT_NAME})
    
    target_sources(testdll PRIVATE dllmain.cpp)
    target_link_libraries(testdll PRIVATE ${PROJECT_NAME})
endif()