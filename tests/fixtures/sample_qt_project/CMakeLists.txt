cmake_minimum_required(VERSION 3.20)
project(SampleQtProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Test)

add_executable(sample_app src/main.cpp)
target_link_libraries(sample_app PRIVATE Qt6::Core Qt6::Widgets)

add_executable(sample_tests tests/test_widget.cpp)
target_link_libraries(sample_tests PRIVATE Qt6::Core Qt6::Test)

enable_testing()
add_test(NAME widget-tests COMMAND sample_tests)
