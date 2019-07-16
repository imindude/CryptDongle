/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "buffer.h"

/* ****************************************************************************************************************** */

#define BLOCKFIFO_CREATE(NAME, LENGTH, BYTES)\
    static uint32_t __##NAME##_write_pos = 0;\
    static uint32_t __##NAME##_read_pos = 0;\
    static uint32_t __##NAME##_size = 0;\
    static uint8_t  __##NAME##_write_buf[BYTES * LENGTH];\
    \
    static bool fifo_##NAME##_add(uint8_t * c)\
    {\
        if (__##NAME##_size < LENGTH)\
        {\
            memmove(__##NAME##_write_buf + __##NAME##_write_pos * BYTES, c, BYTES);\
            __##NAME##_write_pos ++;\
            if (__##NAME##_write_pos >= LENGTH)\
                __##NAME##_write_pos = 0;\
            __##NAME##_size++;\
            return true;\
        }\
        return false;\
    }\
    \
    static bool fifo_##NAME##_take(uint8_t * c)\
    {\
        if (c)\
            memmove(c, __##NAME##_write_buf + __##NAME##_read_pos * BYTES, BYTES);\
        if ( __##NAME##_size > 0)\
        {\
            __##NAME##_read_pos ++;\
            if (__##NAME##_read_pos >= LENGTH)\
                __##NAME##_read_pos = 0;\
            __##NAME##_size --;\
            return true;\
        }\
        return false;\
    }\
    \
    static uint32_t fifo_##NAME##_size()\
    {\
        return __##NAME##_size;\
    }\
    \
    BLOCKFIFO bf_##NAME =\
    {\
            .add  = fifo_##NAME##_add,\
            .take = fifo_##NAME##_take,\
            .size = fifo_##NAME##_size,\
    };\

#define BYTEARRAY_CREATE(NAME, LENGTH)\
    static uint8_t __##NAME##_write_buf[LENGTH];\
    static uint32_t __##NAME##_write_pos = 0;\
    \
    static uint32_t ba_##NAME##_add_byte(uint8_t b)\
    {\
        if ((__##NAME##_write_pos + 1) < LENGTH)\
        {\
            __##NAME##_write_buf[__##NAME##_write_pos] = b;\
            __##NAME##_write_pos ++;\
            return __##NAME##_write_pos;\
        }\
        return 0;\
    }\
    \
    static uint32_t ba_##NAME##_add_bytes(uint8_t *ba, uint32_t len)\
    {\
        if ((__##NAME##_write_pos + len) < LENGTH)\
        {\
            memcpy(__##NAME##_write_buf + __##NAME##_write_pos, ba, len);\
            __##NAME##_write_pos += len;\
            return __##NAME##_write_pos;\
        }\
        return 0;\
    }\
    \
    static void ba_##NAME##_flush()\
    {\
        memset(__##NAME##_write_buf, 0, LENGTH);\
        __##NAME##_write_pos = 0;\
    }\
    \
    static void* ba_##NAME##_head()\
    {\
        return (void*)__##NAME##_write_buf;\
    }\
    \
    \
    static void* ba_##NAME##_get()\
    {\
        return (void*)(__##NAME##_write_buf + __##NAME##_write_pos);\
    }\
    \
    static bool ba_##NAME##_set(uint32_t pos)\
    {\
        if (pos < LENGTH)\
        {\
            __##NAME##_write_pos = pos;\
            return true;\
        }\
        return false;\
    }\
    \
    static uint32_t ba_##NAME##_size()\
    {\
        return __##NAME##_write_pos;\
    }\
    \
    static uint32_t ba_##NAME##_limit()\
    {\
        return LENGTH;\
    }\
    \
    BYTEARRAY ba_##NAME =\
    {\
            .add_byte  = ba_##NAME##_add_byte,\
            .add_bytes = ba_##NAME##_add_bytes,\
            .flush     = ba_##NAME##_flush,\
            .head      = ba_##NAME##_head,\
            .get       = ba_##NAME##_get,\
            .set       = ba_##NAME##_set,\
            .size      = ba_##NAME##_size,\
            .limit     = ba_##NAME##_limit,\
    };\

/* ****************************************************************************************************************** */

BLOCKFIFO_CREATE(usbhid, 128, 64)

BYTEARRAY_CREATE(hidif, 4096)

/* end of file ****************************************************************************************************** */
