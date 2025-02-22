cmake_minimum_required( VERSION 3.23.0 )

set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_CXX_STANDARD          23 )

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib )

project( vpr-ephemeral-blue )

## Main targets
add_subdirectory( ephemeral-blue )

## Test targets
#add_subdirectory( test )
