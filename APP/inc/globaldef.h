/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __GLOBALDEF_H__
#define __GLOBALDEF_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ****************************************************************************************************************** */

#define DEVICE_NAME         "COPY&MAKE CRYPT DONGLE with KEY EXCHANGER"

#define ECC_PUB_KEY_SIZE    65      // format(1) + X(32) + y(32)
#define ECC_PRI_KEY_SIZE    32
#define HASH_SIZE           32      // SHA256
#define SIGN_DER_MAX_SIZE   80

#define AES_KEY_SIZE        32

#define ECC_PUBK_X_POS      0
#define ECC_PUBK_Y_POS      32

#define ECC_PUB_X_SIZE      32
#define ECC_PUB_Y_SIZE      32

#define DEV_UID_LEN         32//128
#define DEV_PIN_LEN         64

#define DEVICE_MAJOR_VER    1
#define DEVICE_MINOR_VER    0

/* ****************************************************************************************************************** */

struct DeviceVersion
{
    uint8_t     major_;
    uint8_t     minor_;
    uint32_t    build_;
};
typedef struct DeviceVersion    DeviceVersion;

enum DeviceState
{
    _DeviceState_Idle,
    _DeviceState_Busy,
    _DeviceState_Wink
};
typedef enum DeviceState    DeviceState;

/* ****************************************************************************************************************** */

extern uint8_t          device_uid[];
extern DeviceVersion    device_ver;

extern const uint8_t    fido_certificate[];
extern const uint8_t    fido_private_key[];
extern const uint16_t   fido_certificate_size;
extern const uint16_t   fido_private_key_size;

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __GLOBALDEF_H__ */

/* end of file ****************************************************************************************************** */
