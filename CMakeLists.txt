cmake_minimum_required(VERSION 2.8)
project(decompsh)

add_executable(${PROJECT_NAME}
	main.cc
)

target_compile_definitions(${PROJECT_NAME} PUBLIC -DPROJECT_PATH=\"${PROJECT_SOURCE_DIR}\")