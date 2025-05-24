# CMake script for gamepwnage
# https://github.com/bitwaree/gamepwnage

cmake_minimum_required(VERSION 3.20)

# project config
project(gamepwnage VERSION 0.0.0)

# build lib
if(WIN32)
    # in case of windows

else()
    # in case of unix based systems

    set(SOURCE_FILES "src/mem.c" "src/nop.c" "src/proc.c")
    set(HEADER_FILES "src/config.h" "src/mem.h" "src/nop.h" "src/proc.h")

    # set arm specific stuffs
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        # if it's arm and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/armhook.c")
	set(HEADER_FILES ${HEADER_FILES} "src/armhook.h")
    endif()
    # set x86 specific files
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        # if it's x86 and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/hook86.c")
	set(HEADER_FILES ${HEADER_FILES} "src/hook86.h")
    endif()

    if(BUILD_SHARED_LIB MATCHES "true")
        add_library(gamepwnage SHARED ${SOURCE_FILES})
    else()
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHARED_LIB")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHARED_LIB")
        add_library(gamepwnage STATIC ${SOURCE_FILES})
    endif()
    # install script
    install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
    install(TARGETS gamepwnage LIBRARY DESTINATION lib)
endif()

