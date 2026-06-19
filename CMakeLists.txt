cmake_minimum_required(VERSION 3.22)

project(Demida LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Demida is Windows-only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(demida_core STATIC
    src/cli.cpp
    src/imports.cpp
    src/pe_image.cpp
    src/process.cpp
    src/unpacker.cpp
)

target_include_directories(demida_core PUBLIC
    include
)

target_link_libraries(demida_core PUBLIC
    advapi32
    psapi
    dbghelp
)

target_compile_definitions(demida_core PUBLIC
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(demida_core PRIVATE
        /W4
        /permissive-
    )
endif()

add_executable(demida
    src/main.cpp
)

target_link_libraries(demida PRIVATE
    demida_core
)
