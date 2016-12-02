set(CMAKE_BUILD_TYPE Release)
include_directories(include)

file (GLOB SRC_FILES "*.cpp"  "include/*.h")


add_library(common_shared SHARED ${SRC_FILES})
set_target_properties(common_shared PROPERTIES OUTPUT_NAME common)
add_library(common_static STATIC ${SRC_FILES})
set_target_properties(common_static PROPERTIES OUTPUT_NAME common)


