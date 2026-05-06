add_executable(fb-cli main.cpp)
target_link_libraries(fb-cli PRIVATE fb::core)
target_compile_features(fb-cli PRIVATE cxx_std_20)
