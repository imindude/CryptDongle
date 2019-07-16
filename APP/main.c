/**
 * *********************************************************************************************************************
 * @brief       USB based cryptography dongle firmware
 * @author      imindude@gmail.com
 * @note        openssl usage
 *
 *              ECC (prime256v1 = secp256r1 = P-NIST256)
 *               > openssl ecparam -genkey -name prime256v1 -out key.pem
 *               > openssl ec -inform PEM -outform DER -in key.pem -out key.der
 *
 *              RSA
 *               > openssl genrsa -out key.pem 2048
 *               > openssl rsa -inform PEM -outform DER -in key.pem -out key.der
 *
 *              Self-Cert.
 *               > openssl req -new -sha256 -key key.pem -out key.csr
 *               > openssl req -x509 -days 3650 -sha256 -key key.pem -in key.csr -out key.cert.pem
 *               > openssl x509 -inform PEM -outform DER -in key.cert.pem -out key.cert.der
 *               > openssl x509 -inform PEM -outform DER -text -in key.cert.pem -out key.cert.der.txt
 *
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "glue.h"
#include "build_number.h"
#include "globaldef.h"
#include "storage.h"
#include "hidif.h"

/* ****************************************************************************************************************** */

#define VERSION_MAJOR       1
#define VERSION_MINOR       0

/* ****************************************************************************************************************** */

uint8_t         device_uid[DEV_UID_LEN];
DeviceVersion   device_ver;

const uint8_t   fido_certificate[] =
{
        0x30, 0x82, 0x02, 0x0e, 0x30, 0x82, 0x01, 0xb4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
        0x84, 0xdc, 0x29, 0x9e, 0xad, 0x01, 0xe3, 0xd9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x04, 0x03, 0x02, 0x30, 0x62, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x4b, 0x52, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x01, 0x20, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x43, 0x6f, 0x70, 0x79, 0x26, 0x4d,
        0x61, 0x6b, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x4d, 0x52,
        0x2e, 0x44, 0x55, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x69, 0x6d, 0x69, 0x6e, 0x64, 0x75, 0x64, 0x65, 0x40, 0x67,
        0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x33,
        0x31, 0x32, 0x30, 0x39, 0x34, 0x33, 0x35, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x33, 0x30,
        0x39, 0x30, 0x39, 0x34, 0x33, 0x35, 0x32, 0x5a, 0x30, 0x62, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x4b, 0x52, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x01, 0x20, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x43, 0x6f,
        0x70, 0x79, 0x26, 0x4d, 0x61, 0x6b, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x07, 0x4d, 0x52, 0x2e, 0x44, 0x55, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x69, 0x6d, 0x69, 0x6e, 0x64, 0x75,
        0x64, 0x65, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4c, 0xf6, 0x69, 0xf1, 0xb2, 0x8e, 0xe9, 0x49, 0x1d,
        0x8f, 0xe9, 0x28, 0xa2, 0x2c, 0xea, 0x9c, 0xd2, 0x67, 0x87, 0x57, 0x01, 0xeb, 0x40, 0x26, 0x24,
        0xb0, 0xd3, 0x7e, 0x19, 0x82, 0x96, 0xec, 0xb3, 0x14, 0xfe, 0xb6, 0x77, 0xfd, 0x4c, 0xd5, 0xc1,
        0x1d, 0x7e, 0xa5, 0x74, 0x5a, 0x61, 0xaa, 0x1d, 0xfc, 0xb7, 0xc1, 0x7d, 0x02, 0x1a, 0xe2, 0xf0,
        0x30, 0x1b, 0xfb, 0xf7, 0xa2, 0xcf, 0x51, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x12, 0x52, 0x91, 0x2f, 0x31, 0x51, 0x9e, 0xb9, 0x24, 0xbb,
        0x42, 0x70, 0xce, 0x74, 0x1e, 0x07, 0x55, 0x12, 0xf2, 0xd9, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
        0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x12, 0x52, 0x91, 0x2f, 0x31, 0x51, 0x9e, 0xb9, 0x24,
        0xbb, 0x42, 0x70, 0xce, 0x74, 0x1e, 0x07, 0x55, 0x12, 0xf2, 0xd9, 0x30, 0x0f, 0x06, 0x03, 0x55,
        0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x39,
        0xfe, 0x03, 0x31, 0xc8, 0x7a, 0x8d, 0x21, 0x8d, 0xc4, 0x22, 0x27, 0x70, 0x34, 0x35, 0xde, 0x25,
        0xfb, 0xa0, 0x0a, 0xd2, 0x1e, 0x26, 0x79, 0x58, 0x32, 0xce, 0xdc, 0x5e, 0xbc, 0x89, 0xc2, 0x02,
        0x21, 0x00, 0xc3, 0xac, 0x41, 0x8b, 0xaa, 0x0c, 0xd4, 0x26, 0x12, 0xda, 0x84, 0xf6, 0x8e, 0x44,
        0x3c, 0x30, 0x16, 0x2c, 0x3b, 0x93, 0x3b, 0x2e, 0x5c, 0x1f, 0xf6, 0x11, 0xcb, 0x8b, 0x5d, 0x05,
        0x21, 0xec
};
const uint8_t   fido_private_key[] =
{
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x05, 0xcc, 0xfb, 0xdc, 0xdf, 0x3a, 0x6f, 0xa0, 0xdd,
        0x3f, 0xda, 0x92, 0x3a, 0x35, 0xf5, 0x57, 0x28, 0xbd, 0x23, 0x2d, 0x92, 0xac, 0x4f, 0xf2, 0x47,
        0x3f, 0xe3, 0x39, 0xd8, 0xcb, 0xbf, 0x2c, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x4c, 0xf6, 0x69, 0xf1, 0xb2, 0x8e, 0xe9,
        0x49, 0x1d, 0x8f, 0xe9, 0x28, 0xa2, 0x2c, 0xea, 0x9c, 0xd2, 0x67, 0x87, 0x57, 0x01, 0xeb, 0x40,
        0x26, 0x24, 0xb0, 0xd3, 0x7e, 0x19, 0x82, 0x96, 0xec, 0xb3, 0x14, 0xfe, 0xb6, 0x77, 0xfd, 0x4c,
        0xd5, 0xc1, 0x1d, 0x7e, 0xa5, 0x74, 0x5a, 0x61, 0xaa, 0x1d, 0xfc, 0xb7, 0xc1, 0x7d, 0x02, 0x1a,
        0xe2, 0xf0, 0x30, 0x1b, 0xfb, 0xf7, 0xa2, 0xcf, 0x51
};
const uint16_t  fido_certificate_size = sizeof(fido_certificate);
const uint16_t  fido_private_key_size = sizeof(fido_private_key);

#if 0
const uint8_t   crypt_private_key[] = {
        0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdf, 0xbe, 0xfd, 0x0a,
        0x78, 0x90, 0x1a, 0x55, 0xbb, 0x7d, 0x7f, 0x33, 0x6e, 0xf7, 0x30, 0x1d, 0x2d, 0x64, 0x33, 0x60,
        0x86, 0x21, 0x97, 0xa8, 0x7a, 0x4c, 0x02, 0x3e, 0x26, 0x8e, 0xe0, 0xba, 0xa1, 0x79, 0xd2, 0x80,
        0x5a, 0xd2, 0xbb, 0xd9, 0xc1, 0xe1, 0x24, 0x01, 0xec, 0x3a, 0xf9, 0x8a, 0x0c, 0xdc, 0x22, 0xf6,
        0x2a, 0x46, 0x9a, 0x5e, 0xc4, 0x21, 0xc5, 0x1d, 0x37, 0x78, 0xea, 0x14, 0x03, 0x63, 0x6f, 0xf9,
        0xe3, 0xa1, 0x2c, 0x9c, 0xe0, 0x6b, 0x2c, 0x27, 0x4c, 0x94, 0x60, 0xd7, 0xe7, 0x18, 0x54, 0x03,
        0xec, 0x37, 0xc1, 0x83, 0x54, 0xb6, 0xcd, 0x9d, 0xf3, 0xbb, 0x8f, 0x38, 0xe3, 0xaf, 0x27, 0x05,
        0xa1, 0xe3, 0xa3, 0xb0, 0x10, 0x47, 0xed, 0xef, 0xe1, 0x28, 0xcb, 0x21, 0x2f, 0xd6, 0xb8, 0x89,
        0x74, 0x3b, 0x34, 0xce, 0x25, 0x07, 0x63, 0x15, 0x9e, 0xe1, 0x97, 0xc3, 0xb4, 0xed, 0xa5, 0xd7,
        0x2b, 0xa5, 0xfd, 0x44, 0xf3, 0x1c, 0x5e, 0xaa, 0x41, 0x78, 0xb1, 0xea, 0x21, 0xb7, 0xb3, 0xba,
        0xca, 0x37, 0xac, 0xb0, 0x9d, 0x2e, 0x73, 0xea, 0x93, 0xb7, 0xb9, 0xac, 0x55, 0x7f, 0x40, 0x6b,
        0x6c, 0x5c, 0x36, 0x9c, 0x10, 0xee, 0x91, 0x26, 0xf2, 0xf1, 0x89, 0xc5, 0x7d, 0x1c, 0x42, 0x9a,
        0x89, 0x7a, 0xf5, 0x18, 0x89, 0x4b, 0x1d, 0x0d, 0x03, 0x4b, 0xc6, 0x96, 0x14, 0xa5, 0x7b, 0x12,
        0xa2, 0x32, 0xf0, 0x0c, 0xc3, 0x34, 0xfd, 0xb4, 0x2c, 0x91, 0x78, 0xe8, 0xfc, 0xdd, 0x76, 0x4b,
        0x4a, 0xf9, 0x04, 0x5f, 0x4b, 0xaa, 0xc4, 0x66, 0xb4, 0x3d, 0x82, 0xb7, 0x6b, 0x2c, 0xe0, 0x08,
        0xb7, 0x17, 0xd0, 0xed, 0xd1, 0x03, 0x59, 0x50, 0x72, 0xd8, 0x50, 0xfd, 0x3c, 0x07, 0xcb, 0xcb,
        0x4d, 0xa7, 0xa2, 0xca, 0x98, 0xcc, 0xa3, 0xd5, 0xfe, 0xea, 0x04, 0x03, 0x02, 0x03, 0x01, 0x00,
        0x01, 0x02, 0x82, 0x01, 0x00, 0x41, 0x9d, 0x4d, 0xb1, 0x8b, 0x67, 0x9f, 0x01, 0x73, 0x49, 0x3b,
        0x4b, 0x47, 0x08, 0x60, 0x68, 0xbe, 0x0d, 0xfb, 0x6f, 0x1c, 0x06, 0xaf, 0xe5, 0xed, 0x6f, 0x6a,
        0xdc, 0xf5, 0x0b, 0xc3, 0x65, 0x97, 0xc3, 0x14, 0xf3, 0x25, 0x2f, 0x55, 0x7d, 0x67, 0x78, 0xf1,
        0xc9, 0x4a, 0x90, 0x84, 0xeb, 0x72, 0x18, 0x00, 0x7c, 0xb6, 0x2b, 0x1c, 0x4c, 0x1c, 0x32, 0x57,
        0x0e, 0xd9, 0x5c, 0xb1, 0x30, 0x8b, 0x49, 0xd6, 0xe5, 0xae, 0x56, 0x6e, 0xb1, 0xd6, 0xb2, 0x37,
        0x31, 0x93, 0x28, 0x94, 0x39, 0xdc, 0x80, 0x6a, 0xea, 0xf7, 0x93, 0xe6, 0x40, 0xf0, 0x4f, 0xe7,
        0x7e, 0xa1, 0xa2, 0x68, 0x3e, 0xe3, 0xae, 0x52, 0xc0, 0x39, 0x18, 0x7b, 0xc1, 0x3f, 0x15, 0x08,
        0xf6, 0xe6, 0xcd, 0xc2, 0xbc, 0x09, 0xbe, 0x6b, 0x41, 0x8b, 0xff, 0x6c, 0xdd, 0xe3, 0x48, 0x06,
        0x4b, 0xa9, 0xdb, 0x38, 0x58, 0xd4, 0xc2, 0x35, 0xbd, 0xfb, 0xe4, 0xab, 0x18, 0x6f, 0x9e, 0xe9,
        0x36, 0xc5, 0x86, 0xd4, 0xc5, 0xb2, 0x46, 0x97, 0x5a, 0xab, 0xf7, 0x46, 0x09, 0x47, 0x19, 0xec,
        0xc6, 0xcc, 0xcb, 0xf5, 0x11, 0x3e, 0x0d, 0x6b, 0xe0, 0xe9, 0xba, 0x8a, 0x24, 0x54, 0xc3, 0x15,
        0x0f, 0xcf, 0x0b, 0x61, 0xfc, 0xe6, 0xe6, 0x6a, 0xa2, 0x4c, 0xbf, 0x9c, 0xbd, 0xbf, 0x93, 0x95,
        0xb6, 0x88, 0xfe, 0x37, 0x9f, 0x06, 0xeb, 0x64, 0x56, 0x73, 0x7b, 0xb4, 0xee, 0xe6, 0x07, 0xa6,
        0xb4, 0x17, 0x6f, 0xb8, 0x5c, 0xa4, 0xda, 0x18, 0xe0, 0x7c, 0x17, 0x23, 0x64, 0x1e, 0x14, 0x86,
        0xe0, 0x51, 0x94, 0x2c, 0xc8, 0x2f, 0x6d, 0x7e, 0x42, 0x77, 0xad, 0xbc, 0x65, 0xf7, 0xe8, 0x7f,
        0x2f, 0xd3, 0xef, 0x67, 0x6a, 0x9a, 0x41, 0x74, 0x30, 0x04, 0x90, 0x17, 0xcc, 0xf3, 0x07, 0x21,
        0x9f, 0x38, 0x9b, 0x6d, 0xe1, 0x02, 0x81, 0x81, 0x00, 0xf6, 0x17, 0x24, 0xa7, 0x22, 0x1b, 0x16,
        0xf6, 0x02, 0xc6, 0x53, 0xe7, 0x46, 0x94, 0x6c, 0xbc, 0x6b, 0x52, 0x2d, 0xfd, 0x41, 0x89, 0xec,
        0x4e, 0xed, 0xe1, 0x93, 0x39, 0xa1, 0xc9, 0x5d, 0xe8, 0xd9, 0x27, 0x5c, 0x58, 0x33, 0x23, 0xaa,
        0x18, 0x50, 0xaf, 0x2c, 0x0a, 0xbc, 0x4b, 0x05, 0xeb, 0xe2, 0x15, 0x18, 0x1b, 0x2f, 0xfa, 0xa7,
        0xa2, 0xb7, 0xc5, 0xf6, 0x02, 0x77, 0xd6, 0x79, 0xbc, 0xe5, 0x6a, 0x4e, 0x84, 0xb8, 0xc9, 0x02,
        0xc9, 0xb7, 0xde, 0x4b, 0xb0, 0x25, 0xf8, 0xf4, 0x98, 0xe4, 0xd2, 0xad, 0xca, 0xff, 0x03, 0x3b,
        0xa1, 0x5d, 0xe1, 0x6f, 0xe9, 0x2b, 0xe6, 0x53, 0xfc, 0x88, 0x55, 0x9f, 0x4f, 0xd5, 0x50, 0x4a,
        0x28, 0xda, 0x3b, 0xe8, 0x13, 0x21, 0x4c, 0xea, 0xcf, 0xb8, 0xf6, 0xf4, 0xe3, 0x55, 0xbc, 0x95,
        0x60, 0x19, 0x64, 0xa6, 0x84, 0x5c, 0x31, 0x0c, 0x93, 0x02, 0x81, 0x81, 0x00, 0xe8, 0xc1, 0x81,
        0x62, 0x86, 0x87, 0xba, 0xc6, 0xd6, 0x58, 0x07, 0x68, 0xc0, 0xb6, 0xec, 0xa8, 0xbc, 0x9c, 0xfe,
        0x12, 0x34, 0xb2, 0x25, 0xa9, 0x21, 0xd9, 0xd5, 0x4a, 0xf5, 0x54, 0xb9, 0xc2, 0xe2, 0x7c, 0x9a,
        0x28, 0x38, 0xa7, 0xc9, 0x85, 0xcd, 0xb5, 0x74, 0x2d, 0x3f, 0xa0, 0x2c, 0x99, 0x67, 0x68, 0x7d,
        0x3e, 0xfb, 0x46, 0x8d, 0x9e, 0x5c, 0x5a, 0x04, 0x9b, 0x64, 0x5a, 0x81, 0x53, 0x96, 0xe8, 0xdd,
        0x8a, 0x92, 0x1f, 0xed, 0x85, 0x2d, 0xe9, 0x12, 0xf6, 0x95, 0x78, 0x60, 0xc5, 0x14, 0xfb, 0x60,
        0x1a, 0x76, 0xef, 0x98, 0xe1, 0x13, 0x0f, 0x9b, 0x95, 0x02, 0x8b, 0xdf, 0x4c, 0x12, 0xad, 0x82,
        0xfa, 0x26, 0xc9, 0xd4, 0x6e, 0x08, 0x57, 0x97, 0x7d, 0x9d, 0x00, 0x06, 0x94, 0x36, 0xf7, 0x8d,
        0x4a, 0xed, 0x5a, 0x93, 0xc3, 0x32, 0xe8, 0x52, 0x0e, 0x97, 0x9e, 0x40, 0xd1, 0x02, 0x81, 0x81,
        0x00, 0xcc, 0x9e, 0xcf, 0xb6, 0x3c, 0xd0, 0xa3, 0x95, 0xe9, 0x16, 0xb9, 0x9b, 0x3b, 0x7f, 0x9c,
        0xae, 0x4a, 0xda, 0x69, 0x2d, 0x04, 0xba, 0xc7, 0x07, 0x96, 0x1a, 0x93, 0x8d, 0x3f, 0x2e, 0x2d,
        0x6c, 0xb8, 0x6b, 0x57, 0x08, 0x6b, 0x75, 0x43, 0x30, 0xb6, 0x9e, 0x01, 0x13, 0xe8, 0x1e, 0xc5,
        0x8c, 0xae, 0x4e, 0xf5, 0xdd, 0x5d, 0x56, 0xa0, 0xde, 0xd6, 0xc9, 0xbe, 0xd5, 0xac, 0x89, 0x64,
        0x6e, 0x21, 0x9f, 0xf4, 0x2b, 0xbd, 0x6e, 0x3e, 0x68, 0x35, 0xff, 0x9b, 0x95, 0x9a, 0xed, 0x57,
        0x8c, 0x6d, 0xef, 0x93, 0xdc, 0x8f, 0x90, 0x43, 0x9b, 0xd8, 0x70, 0xe3, 0xd9, 0xd0, 0xcb, 0xd2,
        0x97, 0xcf, 0x50, 0xca, 0x87, 0xda, 0x09, 0xc9, 0xb0, 0x10, 0x4d, 0xf1, 0x99, 0x3e, 0x7e, 0x33,
        0x5c, 0x87, 0x22, 0xa8, 0xdb, 0x02, 0x66, 0x2d, 0x1a, 0x5b, 0xe2, 0xe9, 0xe6, 0x72, 0xb5, 0xc2,
        0x0b, 0x02, 0x81, 0x80, 0x51, 0xe2, 0x41, 0xb2, 0x77, 0xc1, 0xa8, 0x63, 0xeb, 0x64, 0x6c, 0xb6,
        0xdd, 0x95, 0x7d, 0x0c, 0x9f, 0xce, 0x5b, 0x53, 0xec, 0x56, 0x00, 0x09, 0xd0, 0x6e, 0xe2, 0x2a,
        0xcc, 0xc4, 0x51, 0xd5, 0xcd, 0xf8, 0x28, 0x03, 0x9e, 0x6a, 0xe8, 0xea, 0xb9, 0xc3, 0xec, 0x6b,
        0x3e, 0xc7, 0x0a, 0xe9, 0xad, 0x07, 0x85, 0x88, 0x72, 0xbe, 0x0f, 0x74, 0x76, 0xe8, 0xf4, 0x55,
        0xf6, 0xa8, 0x20, 0x77, 0x57, 0xcf, 0xf4, 0xa0, 0x9b, 0x67, 0xc0, 0x17, 0xea, 0x5e, 0xe4, 0xdc,
        0xfb, 0x18, 0xae, 0x72, 0xa7, 0x3f, 0x08, 0x40, 0x47, 0x37, 0x63, 0x81, 0x4b, 0x43, 0x62, 0x68,
        0xb9, 0xcc, 0x9b, 0x72, 0x17, 0xe0, 0x13, 0x04, 0x0e, 0x41, 0x53, 0x0a, 0xa2, 0xc4, 0xad, 0xf6,
        0xf3, 0x14, 0xdf, 0x3b, 0xa5, 0x5a, 0xd1, 0xca, 0x5a, 0x56, 0x53, 0x45, 0x88, 0xd3, 0x52, 0x8a,
        0xef, 0xac, 0x2d, 0x01, 0x02, 0x81, 0x80, 0x4e, 0xf8, 0x52, 0x8b, 0x45, 0xfd, 0x21, 0x67, 0x18,
        0x78, 0xcc, 0xc9, 0xca, 0xda, 0x1f, 0x6d, 0x09, 0x37, 0xa0, 0x55, 0x5c, 0x53, 0xb2, 0x6f, 0xb6,
        0x31, 0x78, 0xf3, 0x1c, 0x1d, 0xd2, 0x11, 0xee, 0x70, 0x62, 0x3d, 0x0d, 0xc7, 0x9e, 0x7f, 0x49,
        0xd6, 0x3b, 0x5a, 0x5b, 0x4a, 0x8d, 0x30, 0xe6, 0x2f, 0x67, 0xa1, 0xcd, 0x89, 0xe4, 0x9a, 0xe8,
        0xc7, 0x59, 0xf4, 0xf8, 0x0f, 0x91, 0x6c, 0x49, 0xf5, 0x06, 0x49, 0xdd, 0x40, 0xc2, 0xea, 0x79,
        0x53, 0xf0, 0x92, 0x29, 0xe2, 0x0a, 0x2e, 0x81, 0x58, 0xce, 0x91, 0x9b, 0x48, 0x02, 0x80, 0x9b,
        0x25, 0x96, 0xff, 0x08, 0x22, 0xb6, 0xae, 0xad, 0x58, 0x99, 0xa3, 0x82, 0xcd, 0x5f, 0xaa, 0x93,
        0x23, 0x9f, 0x67, 0x1d, 0x08, 0xb0, 0x24, 0x11, 0x9a, 0x12, 0x58, 0xe9, 0x83, 0x89, 0x3d, 0xd9,
        0xe0, 0x3f, 0x7e, 0xba, 0xd5, 0x09, 0xdd
};
const uint16_t  crypt_private_key_size = sizeof(crypt_private_key);
#endif

/* ****************************************************************************************************************** */

static void device_init(void)
{
    if (storage_dev_read(device_uid, NULL) == false)
    {
//        storage_dev_reset();
//        rng_get_bytes(device_uid, DEV_UID_LEN);

        uint32_t    *uid_base = (uint32_t*)UID_BASE;

        *(uint32_t*)(&device_uid[0]) = uid_base[0];
        *(uint32_t*)(&device_uid[4]) = uid_base[1];
        *(uint32_t*)(&device_uid[8]) = uid_base[2];

//        DeviceKey   device_key;
//
//        rng_get_bytes(device_key.seed_, DEV_SEED_SIZE);
//        storage_write(&device_id, &device_key);
//
//        memset(&device_key, 0, sizeof(DeviceKey));
    }

    device_ver.major_ = DEVICE_MAJOR_VER;
    device_ver.minor_ = DEVICE_MINOR_VER;
    device_ver.build_ = BUILD_NUMBER;
}

static void state_notify(uint32_t now_ms, DeviceState state)
{
    /**
     * for BLUE led
     */
    static int8_t   dimming     = 0;
    static int8_t   dimming_dir = 0;
    static uint32_t dimming_ms  = 0;

    /**
     * for RED led
     */
    static int8_t   blinky_on = 0;
    static uint32_t blinky_ms = 0;

    switch (state)
    {
    case _DeviceState_Idle:

        if ((now_ms - dimming_ms) >= 10)
        {
            dimming_ms = now_ms;

            if (dimming <= 0)
                dimming_dir = 1;
            if (dimming >= 100)
                dimming_dir = -1;

            if (dimming_dir > 0)
                dimming++;
            else
                dimming--;
        }

        blinky_ms = 0;
        blinky_on = 0;

        break;

    case _DeviceState_Busy:

        if ((now_ms - blinky_ms) >= 250)
        {
            blinky_ms = now_ms;

            if (blinky_on > 0)
                blinky_on = 0;
            else
                blinky_on = 100;
        }

        dimming     = 0;
        dimming_dir = 0;
        dimming_ms  = 0;

        break;

    case _DeviceState_Wink:

        if ((now_ms - blinky_ms) >= 125)
        {
            blinky_ms = now_ms;

            if (blinky_on > 0)
                blinky_on = 0;
            else
                blinky_on = 100;
        }

        dimming     = 0;
        dimming_dir = 0;
        dimming_ms  = 0;

        break;

    default:

        dimming     = 0;
        dimming_dir = 0;
        dimming_ms  = 0;

        blinky_ms = 0;
        blinky_on = 0;

        break;
    }

    led_brightness(_LED_BLUE, dimming);
    led_brightness(_LED_RED, blinky_on);
}

int main(void)
{
    HAL_Init();

    rng_init();
    button_init();
    led_init();

    device_init();
    usbhid_init();

    uint32_t    now_ms;
    DeviceState state;

    while (1)
    {
        now_ms = get_millis();

        state = hidif_process(now_ms);

        state_notify(now_ms, state);
    }

    return 0;
}

/* ****************************************************************************************************************** */

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    rng_get_bytes(output, len);
    *olen = len;

    return 0;
}

/* end of file ****************************************************************************************************** */