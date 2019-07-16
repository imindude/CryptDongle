# STM32F4Discovery FIDO Dongle

STM32F4Discovery based FIDO dongle.

## Dev. environment

- Atollic TrueSTUDIO for STM32

## Opensources

- hmac : https://github.com/ogay/hmac
- micro-ecc : https://github.com/kmackay/micro-ecc
- tiny-AES-c : https://github.com/kokke/tiny-AES-c
- tinycbor : https://github.com/intel/tinycbor

## HAL

- STM32F4Discovery
- STM32F4xx_HAL_Driver
- STM32_USB_Device_Library

## Reference

- Solo : https://github.com/solokeys/solo

## CIPHER protocol

- CIPHER_VERSION : 0x50

| byte index | context            |
| ---------- | ------------------ |
| 0          | magic word >> 24   |
| 1          | magic word >> 16   |
| 2          | magic word >>  8   |
| 3          | magic word >>  0   |
| 4          | version major      |
| 5          | version minor      |
| 6          | build number >> 24 |
| 7          | build number >> 16 |
| 8          | build number >>  8 |
| 9          | build number >>  0 |
