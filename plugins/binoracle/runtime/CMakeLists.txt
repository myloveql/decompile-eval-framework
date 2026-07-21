cmake_minimum_required(VERSION 3.16)
project(binoracle_runtime C ASM)

add_library(binoracle_runtime OBJECT
    abi_trampoline.S
    deterministic_stubs.c
    guard_memory.c
    observation.c
    runner_main.c
)
target_compile_features(binoracle_runtime PRIVATE c_std_11)
target_compile_options(binoracle_runtime PRIVATE -Wall -Wextra -Werror)
