#define _GNU_SOURCE
#include "binoracle_runtime.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static const unsigned char *read_data;
static size_t read_size;
static size_t read_offset;
static int stubs_enabled;
static struct BinOracleExternalEvent local_events[BINORACLE_MAX_EXTERNAL_EVENTS];
static struct BinOracleExternalEvent *event_sink = local_events;
static size_t event_capacity = BINORACLE_MAX_EXTERNAL_EVENTS;
static volatile size_t *shared_event_count;
static volatile int *shared_events_truncated;
static size_t event_count;
static int events_truncated;

enum { BINORACLE_EVENT_PUTS = 1, BINORACLE_EVENT_READ = 2 };

static void record_event(
    unsigned int kind,
    int fd,
    size_t requested,
    size_t returned,
    const unsigned char *text,
    size_t text_size,
    const unsigned char *data,
    size_t data_size
) {
    if (event_count >= event_capacity) {
        events_truncated = 1;
        if (shared_events_truncated) {
            *shared_events_truncated = 1;
        }
        return;
    }
    struct BinOracleExternalEvent *event = &event_sink[event_count++];
    if (shared_event_count) {
        *shared_event_count = event_count;
    }
    event->sequence = (unsigned int)event_count;
    event->kind = kind;
    event->fd = fd;
    event->requested = requested;
    event->returned = returned;
    event->text_truncated = text_size > BINORACLE_MAX_EXTERNAL_EVENT_TEXT;
    event->data_truncated = data_size > BINORACLE_MAX_EXTERNAL_EVENT_BYTES;
    event->text_size = event->text_truncated
        ? BINORACLE_MAX_EXTERNAL_EVENT_TEXT : text_size;
    event->data_size = event->data_truncated
        ? BINORACLE_MAX_EXTERNAL_EVENT_BYTES : data_size;
    if (event->text_size) {
        __builtin_memcpy(event->text, text, event->text_size);
    }
    if (event->data_size) {
        __builtin_memcpy(event->data, data, event->data_size);
    }
}

void binoracle_stubs_configure(const unsigned char *data, size_t size) {
    read_data = data;
    read_size = size;
    read_offset = 0;
}

void binoracle_stubs_enable(int enabled) {
    stubs_enabled = enabled;
}

void binoracle_stubs_set_event_sink(
    struct BinOracleExternalEvent *output,
    size_t max_events,
    volatile size_t *output_count,
    volatile int *truncated
) {
    event_sink = output ? output : local_events;
    event_capacity = output ? max_events : BINORACLE_MAX_EXTERNAL_EVENTS;
    shared_event_count = output_count;
    shared_events_truncated = truncated;
    binoracle_stubs_reset_events();
}

void binoracle_stubs_reset_events(void) {
    event_count = 0;
    events_truncated = 0;
    if (shared_event_count) {
        *shared_event_count = 0;
    }
    if (shared_events_truncated) {
        *shared_events_truncated = 0;
    }
}

size_t binoracle_stubs_copy_events(
    struct BinOracleExternalEvent *output,
    size_t max_events,
    int *truncated
) {
    size_t count = event_count < max_events ? event_count : max_events;
    if (count) {
        __builtin_memcpy(output, event_sink, count * sizeof(*output));
    }
    if (truncated) {
        *truncated = events_truncated || event_count > max_events;
    }
    return count;
}

int puts(const char *text) {
    if (stubs_enabled) {
        /* glibc annotates ``text`` as nonnull, so the comparison must happen
         * through an unattributed local pointer to remain -Wnonnull-compare
         * clean under -Werror. The defensive NULL check is preserved in case
         * a target ever calls puts with a malformed pointer. */
        const char *cursor = text;
        size_t size = cursor ? __builtin_strnlen(cursor, BINORACLE_MAX_EXTERNAL_EVENT_TEXT + 1U) : 0;
        record_event(
            BINORACLE_EVENT_PUTS,
            -1,
            0,
            0,
            (const unsigned char *)text,
            size,
            NULL,
            0
        );
    }
    /* Do not let target output affect the runner protocol. */
    return 0;
}

ssize_t read(int fd, void *buffer, size_t count) {
    if (!stubs_enabled) {
        return (ssize_t)syscall(SYS_read, fd, buffer, count);
    }
    size_t returned = 0;
    if (read_offset < read_size) {
        size_t available = read_size - read_offset;
        returned = count > available ? available : count;
        __builtin_memcpy(buffer, read_data + read_offset, returned);
        read_offset += returned;
    }
    record_event(
        BINORACLE_EVENT_READ,
        fd,
        count,
        returned,
        NULL,
        0,
        (const unsigned char *)buffer,
        returned
    );
    return (ssize_t)returned;
}
