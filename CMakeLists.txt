# CMake script for gamepwnage
# https://github.com/bitwaree/gamepwnage

cmake_minimum_required(VERSION 3.20)

# project config
project(gamepwnage VERSION 0.0.0)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_definitions(-DGPWN_USING_BUILD_CONFIG)

# enable debug
if(GPWN_DEBUG_BUILD MATCHES "true")
    add_compile_definitions(-DGPWN_DEBUG)
endif()

if(USING_SIMD MATCHES "true")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        add_compile_definitions(-DUSING_NEON)
        add_compile_options(-mfpu=neon -mfloat-abi=hard)
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        add_compile_definitions(-DUSING_AVX2)
        add_compile_options(-mavx2)
    endif()
endif()

# build lib
if(WIN32)
    # in case of windows
    # configure the source files
    set(SOURCE_FILES "src/windows/mem.c" "src/windows/mem_ex.c" "src/windows/nop.c" "src/windows/nop_ex.c" "src/windows/hook86.c")
    set(HEADER_FILES "src/windows/mem.h" "src/windows/nop.h" "src/windows/hook86.h")
    # set visual studio flags
    if(MSVC)
        # Set the C and C++ compiler flags
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()

    # Set the runtime library to static for all configurations
    # set(CMAKE_C_RUNTIME_LIBRARY "Multi-Threaded")
    # set(CMAKE_CXX_RUNTIME_LIBRARY "Multi-Threaded")
    # build the lib
    if(BUILD_SHARED_LIB MATCHES "true")
        add_definitions("-DSHARED_LIB")
        add_library(gamepwnage SHARED ${SOURCE_FILES})
    else()
        # in case of dll
        # add_definitions("-DSTATIC_LIB")
        add_library(gamepwnage STATIC ${SOURCE_FILES})
    endif()

    install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
    install(TARGETS gamepwnage LIBRARY DESTINATION lib)

else()
    # for linux
    set(SOURCE_FILES

    "src/dynlib.c"
    "src/extras.c"
    "src/inlinehook.c"
    "src/mem.c"
    "src/memscan.c"
    "src/nop.c"
    "src/plthook.c"
    "src/proc.c"
    "src/vftable.c")

    set(HEADER_FILES

    "include/gamepwnage/dynlib.h"
    "include/gamepwnage/extras.h"
    "include/gamepwnage/inlinehook.h"
    "include/gamepwnage/mem.h"
    "include/gamepwnage/memscan.h"
    "include/gamepwnage/nop.h"
    "include/gamepwnage/plthook.h"
    "include/gamepwnage/proc.h"
    "include/gamepwnage/vftable.h")

    # set arm specific stuffs
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        # if it's arm and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/armhook.c")
        set(HEADER_FILES ${HEADER_FILES} "include/gamepwnage/armhook.h")
    endif()
    # set x86 specific files
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        # if it's x86 and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/hook86.c")
        set(HEADER_FILES ${HEADER_FILES} "include/gamepwnage/hook86.h")
    endif()

    if(BUILD_SHARED_LIB MATCHES "true")
        add_library(gamepwnage SHARED ${SOURCE_FILES})
        add_definitions(-DEXPORT_SYM)
    else()
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHARED_LIB")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHARED_LIB")
        add_library(gamepwnage STATIC ${SOURCE_FILES})
    endif()
    target_include_directories(gamepwnage PUBLIC "include/gamepwnage")
    # install script
    install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
    install(TARGETS gamepwnage LIBRARY DESTINATION lib)
endif()
