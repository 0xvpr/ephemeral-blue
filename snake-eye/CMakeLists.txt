project( snake-eye
         VERSION        1.0.0
         LANGUAGES      CXX
)

include_directories( ${CMAKE_CURRENT_SOURCE_DIR} )
include_directories( ${CMAKE_SOURCE_DIR}/${PROJECT_NAME} )

add_compile_definitions(VC_EXTRALEAN=1)
add_compile_definitions(WIN32_LEAN_AND_MEAN=1)

add_executable(
    ${PROJECT_NAME}
         main.cpp
         utility.cpp
         verifier.cpp
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        OUTPUT_NAME ${PROJECT_NAME}
        PREFIX "vpr-"
)

target_compile_options(
    ${PROJECT_NAME}
    PRIVATE 
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
        $<$<CXX_COMPILER_ID:MSVC>:/WX>
        $<$<CXX_COMPILER_ID:MSVC>:/O2>
        $<$<CXX_COMPILER_ID:MSVC>:/MT>
        $<$<CXX_COMPILER_ID:GNU>:-Ofast>
        $<$<CXX_COMPILER_ID:GNU>:-Wall>
        $<$<CXX_COMPILER_ID:GNU>:-Wextra>
        $<$<CXX_COMPILER_ID:GNU>:-Werror>
        $<$<CXX_COMPILER_ID:GNU>:-Wshadow>
#       $<$<CXX_COMPILER_ID:GNU>:-Wpedantic>
        $<$<CXX_COMPILER_ID:GNU>:-Wconversion>
        $<$<CXX_COMPILER_ID:GNU>:-Wno-unused-value>
        $<$<CXX_COMPILER_ID:GNU>:-Wno-cast-function-type>
        $<$<CXX_COMPILER_ID:GNU>:-Wno-missing-field-initializers>
        $<$<CXX_COMPILER_ID:GNU>:-fPIE>
        $<$<CXX_COMPILER_ID:GNU>:-fno-ident>
        $<$<CXX_COMPILER_ID:GNU>:-ffast-math>
        $<$<CXX_COMPILER_ID:GNU>:-funroll-loops>
        $<$<CXX_COMPILER_ID:GNU>:-fvisibility=hidden>
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        wintrust
        #common_static
)
