#define _POSIX_C_SOURCE 200809L
#include "binoracle_runtime.h"

#include <time.h>

uint64_t binoracle_now_us(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000000ULL + (uint64_t)value.tv_nsec / 1000ULL;
}

void binoracle_hex_encode(
    const unsigned char *data,
    size_t size,
    char *output
) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < size; ++index) {
        output[index * 2U] = digits[data[index] >> 4U];
        output[index * 2U + 1U] = digits[data[index] & 15U];
    }
    output[size * 2U] = '\0';
}
