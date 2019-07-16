/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __MISC_H__
#define __MISC_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

uint16_t    get_crc16_ccitt(uint16_t crc, uint8_t *bytes, size_t size);
uint8_t     der_encoding(uint8_t *sign, uint8_t *der);
int         mbedtls_if_rng(void *handle, unsigned char *output, size_t len);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __MISC_H__ */

/* end of file ****************************************************************************************************** */