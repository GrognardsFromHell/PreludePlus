set(SOURCES_MINHOOK
        "src/buffer.c"
        "src/hook.c"
        "src/trampoline.c"
        )

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(SOURCES_HDE "src/hde/hde64.c")
else ()
    set(SOURCES_HDE "src/hde/hde32.c")
endif ()

add_library(minhook STATIC ${SOURCES_MINHOOK} ${SOURCES_HDE})

target_include_directories(
        minhook PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
        $<INSTALL_INTERFACE:include>
)

target_include_directories(minhook PRIVATE "src")
target_include_directories(minhook PRIVATE "src/hde")
