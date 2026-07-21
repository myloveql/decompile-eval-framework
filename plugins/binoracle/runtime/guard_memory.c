#define _GNU_SOURCE
#include "binoracle_runtime.h"

#include <sys/mman.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>

int binoracle_guard_allocate(
    struct GuardObject *object,
    size_t size,
    int place_right
) {
    if (object == NULL || size == 0 || size > BINORACLE_MAX_OBJECT_BYTES) {
        return -1;
    }
    memset(object, 0, sizeof(*object));
    long queried_page = sysconf(_SC_PAGESIZE);
    if (queried_page <= 0) {
        return -1;
    }
    size_t page = (size_t)queried_page;
    size_t accessible_size = ((size + page - 1U) / page) * page;
    size_t mapping_size = accessible_size + 2U * page;
    unsigned char *mapping = mmap(
        NULL, mapping_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );
    if (mapping == MAP_FAILED) {
        return -1;
    }
    unsigned char *accessible = mapping + page;
    if (mprotect(accessible, accessible_size, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mapping_size);
        return -1;
    }
    object->mapping = mapping;
    object->mapping_size = mapping_size;
    object->accessible = accessible;
    object->accessible_size = accessible_size;
    object->payload = place_right ? accessible + accessible_size - size : accessible;
    object->payload_size = size;
    object->page_size = page;
    return 0;
}

void binoracle_guard_release(struct GuardObject *object) {
    if (object != NULL && object->mapping != NULL) {
        munmap(object->mapping, object->mapping_size);
        memset(object, 0, sizeof(*object));
    }
}

const char *binoracle_fault_class(
    const struct GuardObject *object,
    uintptr_t address,
    int64_t *relative_offset
) {
    if (object == NULL || object->mapping == NULL) {
        return "outside_known_object";
    }
    uintptr_t payload = (uintptr_t)object->payload;
    if (relative_offset != NULL) {
        *relative_offset = (int64_t)(address - payload);
    }
    uintptr_t mapping = (uintptr_t)object->mapping;
    uintptr_t left_guard_end = mapping + object->page_size;
    uintptr_t right_guard = (uintptr_t)object->accessible + object->accessible_size;
    if (address >= mapping && address < left_guard_end) {
        return "obj0_left_guard";
    }
    if (address >= right_guard && address < right_guard + object->page_size) {
        return "obj0_right_guard";
    }
    if (address >= payload && address < payload + object->payload_size) {
        return "obj0_payload";
    }
    if (address >= (uintptr_t)object->accessible && address < right_guard) {
        return "obj0_accessible_padding";
    }
    return "outside_known_object";
}
