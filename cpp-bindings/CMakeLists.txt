cmake_minimum_required(VERSION 3.8.0)
project(rabe-cpp-bindings)

# -----------------------------------------
# Most of the variables used transitively used here like compiler or linker
# flags are set in the sysroot file (WasiToolchain.cmake) and are defined in
# the build environment file (faasmtools/build.py)
# -----------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # For Faasm functions, we add `_faasm_zygote` as an exported symbol
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -Xlinker --export=_faasm_zygote"
    )
    message(STATUS "Detected wasm build (sysroot=$ENV{FAASM_WASM_SYSROOT})")
endif ()

add_library(rabe-cpp rabe_bindings.cpp tless_aes.cpp)

if (CMAKE_SYSTEM_NAME STREQUAL "WASI")
    target_compile_definitions(rabe-cpp __faasm)
    target_link_libraries(rabe-cpp PUBLIC rabe)
else ()
    target_link_libraries(rabe-cpp PUBLIC /usr/local/lib/librabe.a)
endif ()

