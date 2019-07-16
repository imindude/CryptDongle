/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __HIDIF_H__
#define __HIDIF_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stdint.h>

/* ****************************************************************************************************************** */

/**
 * version, etc.
 */

#define HIDIF_PROTOCOL_VERSION      2
#define HIDIF_INVALID_CID           0
#define HIDIF_BROADCAST_CID         0xFFFFFFFF

/**
 * USBHID command
 */

#define HIDIF_PING                  0x01
#define HIDIF_MSG                   0x03
#define HIDIF_LOCK                  0x04    // optional
#define HIDIF_INIT                  0x06
#define HIDIF_WINK                  0x08    // optional
#define HIDIF_CBOR                  0x10
#define HIDIF_CANCEL                0x11
#define HIDIF_KEEPALIVE             0x3B
#define HIDIF_ERROR                 0x3F
// vendor command (0x40 ~ 0x7F)
#define HIDIF_PIN                   0x54
#define HIDIF_CIPHER                0x55

/* ****************************************************************************************************************** */

DeviceState hidif_process(uint32_t now_ms);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __HIDIF_H__ */

/* end of file ****************************************************************************************************** */
