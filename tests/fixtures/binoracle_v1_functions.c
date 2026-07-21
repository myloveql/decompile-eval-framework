#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int binoracle_counter = 0;

int add(int left, int right) { return left + right; }

void set_value(int *output) { *output = 42; }

void fill_bytes(unsigned char *output, size_t size) {
    memset(output, 0x5a, size);
}

void update_global(void) { binoracle_counter += 7; }

int read_value(const int *input) { return *input; }

int null_safe(const int *input) { return input == NULL ? 17 : *input; }

void crash_now(void) { *(volatile int *)0 = 1; }

void loop_forever(void) {
    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
}

void write_right(unsigned char *output) { output[4] = 1; }

void write_left(unsigned char *output) { output[-1] = 1; }

void copy_four(unsigned char *output) {
    static const unsigned char value[4] = {1, 2, 3, 4};
    memcpy(output, value, sizeof(value));
}

void clear_four(unsigned char *output) { memset(output, 0, 4); }

unsigned char *identity_pointer(unsigned char *input) { return input + 2; }

int increment(int value) { return value + 1; }

int sum_three(int first, int second, int third) {
    return first + second + third;
}
