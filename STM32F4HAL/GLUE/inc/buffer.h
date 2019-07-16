/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __FIFO_H__
#define __FIFO_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ****************************************************************************************************************** */

typedef struct _BLOCKFIFO
{
    bool        (*add)(uint8_t*);
    bool        (*take)(uint8_t *);
    uint32_t    (*size)(void);
}
BLOCKFIFO;

typedef struct _BYTEARRAY
{
    uint32_t    (*add_byte)(uint8_t);
    uint32_t    (*add_bytes)(uint8_t*, uint32_t);
    void        (*flush)(void);
    void*       (*head)(void);
    void*       (*get)(void);
    bool        (*set)(uint32_t);
    uint32_t    (*size)(void);
    uint32_t    (*limit)(void);
}
BYTEARRAY;

#define BLOCKFIFO_CREATE_H(NAME)    BLOCKFIFO   bf_##NAME;
#define BYTEARRAY_CREATE_H(NAME)    BYTEARRAY   ba_##NAME;

/* ****************************************************************************************************************** */

BLOCKFIFO_CREATE_H(usbhid)

BYTEARRAY_CREATE_H(hidif)

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __FIFO_H__ */

/* end of file ****************************************************************************************************** */
