set(CMAKE_BUILD_TYPE Release)
include_directories(include)

file (GLOB SRC_FILES "*.cpp"  "include/*.h")


add_library(common_shared SHARED ${SRC_FILES})
target_link_libraries(common_shared /usr/lib/x86_64-linux-gnu/libsctp.so)
#target_compile_options(common_shared PUBLIC -lsctp)
set_target_properties(common_shared PROPERTIES OUTPUT_NAME common)
add_library(common_static STATIC ${SRC_FILES})
target_link_libraries(common_static /usr/lib/x86_64-linux-gnu/libsctp.so)
#target_compile_options(common_static PRIVATE -lsctp)
set_target_properties(common_static PROPERTIES OUTPUT_NAME common)


