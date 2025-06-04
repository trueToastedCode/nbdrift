cmake_minimum_required(VERSION 3.31.6)
project(nbdrift)

# Configure LSPlant to build only a static library (disable shared library)
set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "Build LSPlant as static library only" FORCE)

# Ensure liblzma is built as a static library (disable shared libraries)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build libraries as static" FORCE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -fno-exceptions \
    -fno-rtti \
    -fvisibility=hidden \
    -fvisibility-inlines-hidden"
)

if(NOT DEFINED ANDROID_NDK)
    message(FATAL_ERROR "ANDROID_NDK is not set.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# include LSPlant
add_subdirectory(LSPlant/lsplant/src/main/jni)

# include Dobby
add_subdirectory(Dobby)

# include xz
add_subdirectory(xz)

set(MY_DATA_PATH "${CMAKE_CURRENT_SOURCE_DIR}/dummy_10000000.bin")

# First process the path substitution using CMake's string command
string(REPLACE "/" "_" SYM_PREFIX "${MY_DATA_PATH}")
string(REPLACE "." "_" SYM_PREFIX "${SYM_PREFIX}")
string(REPLACE "-" "_" SYM_PREFIX "${SYM_PREFIX}")

add_custom_command(
    OUTPUT classes_dex_data.o
    COMMAND ${CMAKE_OBJCOPY}
        "--input-target" "binary"
        "--output-target" "elf64-littleaarch64"
        "--binary-architecture" "aarch64"
        "--redefine-sym" "_binary_${SYM_PREFIX}_start=classes_dex_data_start"
        "--redefine-sym" "_binary_${SYM_PREFIX}_end=classes_dex_data_end"
        "--redefine-sym" "_binary_${SYM_PREFIX}_size=classes_dex_data_size"
        "${MY_DATA_PATH}"
        "classes_dex_data.o"
    DEPENDS "${MY_DATA_PATH}"
    COMMENT "Embedding dummy cdata with simplified symbols"
)

add_library(${MODULE_NAME}
    SHARED
    main.cpp
    elf_img/elf_img.cpp
    find_init_array/find_init_array.cpp
    classes_dex_data.o
)

target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/include
)

target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/LSPlant/lsplant/src/main/jni/include
)

target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/xz/src/liblzma/api
)

target_link_libraries(${MODULE_NAME} 
    PRIVATE
    log 
    dobby_static
    lsplant_static
    liblzma
)
