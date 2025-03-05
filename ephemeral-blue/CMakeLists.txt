project( ephemeral-blue
         VERSION        2.0.1
         LANGUAGES      CXX
)

include_directories( ${CMAKE_CURRENT_SOURCE_DIR} )
include_directories( ${CMAKE_SOURCE_DIR}/${PROJECT_NAME} )

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
