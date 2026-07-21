#ifndef BINORACLE_RUNTIME_H
#define BINORACLE_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#define BINORACLE_MAX_OBJECT_BYTES (16U * 1024U)
#define BINORACLE_MAX_OBJECTS 3U
#define BINORACLE_MAX_OBJECT_ID 64U
#define BINORACLE_MAX_GLOBALS 32U
#define BINORACLE_MAX_GLOBAL_BYTES 256U
#define BINORACLE_MAX_VIRTUAL_READ_BYTES (64U * 1024U)
#define BINORACLE_MAX_EXTERNAL_EVENTS 64U
#define BINORACLE_MAX_EXTERNAL_EVENT_TEXT 256U
#define BINORACLE_MAX_EXTERNAL_EVENT_BYTES 256U

struct CallFrame {
    uint64_t gpr[6];
    uint64_t return_rax;
    uint64_t return_rdx;
    void *target;
};

void binoracle_call(struct CallFrame *frame);

struct GuardObject {
    unsigned char *mapping;
    size_t mapping_size;
    unsigned char *accessible;
    size_t accessible_size;
    unsigned char *payload;
    size_t payload_size;
    size_t page_size;
};

int binoracle_guard_allocate(struct GuardObject *object, size_t size, int place_right);
void binoracle_guard_release(struct GuardObject *object);
const char *binoracle_fault_class(const struct GuardObject *object, uintptr_t address,
                                  int64_t *relative_offset);

struct BinOracleGlobal {
    const char *name;
    unsigned char *address;
    size_t size;
};

void *binoracle_target_address(void);
extern struct BinOracleGlobal binoracle_globals[];
extern const size_t binoracle_global_count;

uint64_t binoracle_now_us(void);
void binoracle_hex_encode(const unsigned char *data, size_t size, char *output);

/* Deterministic target-only replacements for puts(3) and read(2). */
struct BinOracleExternalEvent {
    unsigned int sequence;
    unsigned int kind;
    int fd;
    size_t requested;
    size_t returned;
    size_t text_size;
    size_t data_size;
    int text_truncated;
    int data_truncated;
    unsigned char text[BINORACLE_MAX_EXTERNAL_EVENT_TEXT];
    unsigned char data[BINORACLE_MAX_EXTERNAL_EVENT_BYTES];
};

void binoracle_stubs_configure(const unsigned char *read_bytes, size_t read_size);
void binoracle_stubs_enable(int enabled);
void binoracle_stubs_set_event_sink(
    struct BinOracleExternalEvent *events,
    size_t max_events,
    volatile size_t *event_count,
    volatile int *truncated
);
void binoracle_stubs_reset_events(void);
size_t binoracle_stubs_copy_events(
    struct BinOracleExternalEvent *events,
    size_t max_events,
    int *truncated
);

#endif
