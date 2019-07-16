/**
 * *********************************************************************************************************************
 * @brief       Custom Protocol definitions
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __CUSTOMDEF_H__
#define __CUSTOMDEF_H__

/* ****************************************************************************************************************** */

/**
 * PIN class
 */

#define PIN_CLASS                       0x54

/**
 * PIN instruction
 */

#define PIN_GETTER                      0x10
#define PIN_SETTER                      0x11

/**
 * PIN signal
 */

#define PIN_BEEP_MS                     500
#define PIN_BEEEEP_MS                   2000

#define PIN_NONE                        0
#define PIN_BEEP                        1
#define PIN_BEEEEP                      2

#define PIN_MIN_LEN                     4

/**
 * PIN status code
 */

#define PIN_SW_NO_ERROR                 0x9000
#define PIN_SW_VERIFY_FAILED            0x9004
#define PIN_SW_CONFIRM                  0x9100
#define PIN_SW_NOT_SATISFIED            0x6985
#define PIN_SW_TIMEOUT                  0x6800
#define PIN_SW_WRONG_DATA               0x6A80
#define PIN_SW_ERR_OTHER                0x6F00

/**
 * CIPHER V1 spec.
 * - magic word                      : 0x23561448
 * - message digest algorithm        : SHA-256
 * - symmetric encryption algorithm  : AESCBC-256
 * - asymmetric encryption algorithm : RSA-2048
 */
/* ****************************************************************************************************************** */

/**
 * CIPHER version V1
 */

#define CIPHER_MAGIC_WORD               0x23561448
#define CIPHER_SEED_SIZE                128
#define CIPHER_MD_SIZE                  32
#define CIPHER_BLOCK_IV_SIZE            16
#define CIPHER_BLOCK_KEY_SIZE           32
#define CIPHER_BLOCK_SIZE               2048

#define CIPHER_SIGN_TAG_SEED            0x10
#define CIPHER_SIGN_TAG_MD              0x11

#define CIPHER_TAG_LEN_SIZE             3

/**
 * CIPHER command class
 */

#define CIPHER_CLASS                    0x55

/**
 * CIPHER command instruction
 *  : extension of FIDO (0x40 ~ 0xBF)
 */

#define CIPHER_VERSION                  0x50
#define CIPHER_KEY                      0x51
#define CIPHER_ENCRYPTION               0x52

/**
 * CIPHER command param 1
 */

#define CIPHER_PARAM_SET                0x10
#define CIPHER_PARAM_GET                0x11

/**
 * CIPHER command param 2
 */

#define CIPHER_PARAM_INIT               0x20
#define CIPHER_PARAM_DO                 0x21
#define CIPHER_PARAM_DONE               0x22
#define CIPHER_PARAM_SIGN               0x23
#define CIPHER_PARAM_TERM               0x24

/**
 * CIPHER status code
 */

#define CIPHER_SW_NO_ERROR              0x9000
#define CIPHER_SW_NOT_SATISFIED         0x6985
#define CIPHER_SW_WRONG_DATA            0x6A80
#define CIPHER_SW_WRONG_LENGTH          0x6700
#define CIPHER_SW_WRONG_KEY             0x6800
#define CIPHER_SW_INVALID_CLA           0x6E00
#define CIPHER_SW_INVALID_INS           0x6D00
#define CIPHER_SW_INVALID_PARAM         0x6C00
#define CIPHER_SW_ERR_OTHER             0x6F00

/* ****************************************************************************************************************** */

#endif  /* __CUSTOMDEF_H__ */

/* end of file ****************************************************************************************************** */
