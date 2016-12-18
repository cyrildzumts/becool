cmake_minimum_required(VERSION 2.6)
project (Server)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set (INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_LINK_LIBS  "${LIBRARY_OUTPUT_PATH}/libcommon.a")
link_directories(../lib)
FILE(GLOB_RECURSE SERVER_SRCS "include/*.h" "src/*.cpp")
include_directories(include ../common/inclue)
link_directories(/home/cyrildz/Project/Beaglib/lib/static)
set(INLCUDE_LIB_PATHS include )
set(INLCUDE_LIB_PATHS ${INCLUDE_LIB_PATHS} include ../common/include )


add_executable(${PROJECT_NAME}  ${SERVER_SRCS})
#target_link_libraries(common_shared)
target_link_libraries(${PROJECT_NAME}  common_shared)
#add_custom_target(server_headers SOURCES ${SERVER_HEADERS})
