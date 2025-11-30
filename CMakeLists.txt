cmake_minimum_required(VERSION 3.28)
project(freetpfix)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "")
set(TARGET "vcruntime140_1")

add_library(${TARGET}
    SHARED
    "main.cpp"
    "exports.def"
)

set_target_properties(${TARGET}
    PROPERTIES
    PREFIX ""
    IMPORT_PREFIX ""
)