cmake_minimum_required(VERSION 2.6)
project (Client)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set (INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set (PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_LINK_LIBS  "${LIBRARY_OUTPUT_PATH}/libcommon.a")
link_directories(../lib)

FILE(GLOB_RECURSE CLIENT_SRCS "include/*.h" "src/*.cpp")
include_directories(include ../common/inclue)
set(INLCUDE_LIB_PATHS ../include )
set(INLCUDE_LIB_PATHS ${INCLUDE_LIB_PATHS} include ../common/include )


add_executable(${PROJECT_NAME}  ${CLIENT_SRCS})
target_link_libraries(${PROJECT_NAME} ${PROJECT_LINK_LIBS})

#add_custom_target(server_headers SOURCES ${SERVER_HEADERS})
