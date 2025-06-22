cmake_minimum_required(VERSION 3.10)

project(StealthAPI
    VERSION 1.0
    DESCRIPTION "StealthAPI: runtime API/syscall resolution & stealth evasion"
    LANGUAGES C
)

# build as a static library
add_library(StealthAPI STATIC
    api_hashing.c
    exports.c
    strings.c
    unhook.c
    whispers.c
)

# enable warnings and set C standard
target_compile_features(StealthAPI PUBLIC c_std_11)
if(MSVC)
    target_compile_options(StealthAPI PRIVATE /W4 /WX)
else()
    target_compile_options(StealthAPI PRIVATE -Wall -Wextra -pedantic -Werror)
endif()

# make headers available to consumers
target_include_directories(StealthAPI
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# on Windows link against necessary system libraries
if(WIN32)
    target_link_libraries(StealthAPI
        PUBLIC
            # ntdll is implicitly available; link against kernel32 for Toolhelp32Snapshot, etc.
            kernel32
            advapi32
            user32
    )
endif()
