/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __PIN_H__
#define __PIN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

bool    pin_request(uint8_t *msg, uint16_t len, uint32_t now_ms);
bool    pin_keepalive(uint32_t now_ms);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __PIN_H__ */

/* end of file ****************************************************************************************************** */
