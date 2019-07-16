/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#ifndef __GLUE_H__
#define __GLUE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stdint.h>
#include <stdbool.h>

/* ****************************************************************************************************************** */

typedef enum _LED
{
    _LED_BLUE,
    _LED_RED,
}
LED;

/* ****************************************************************************************************************** */

uint32_t    get_millis(void);
uint32_t    get_micros(void);
void        delay_millis(uint32_t ms);
void        delay_micros(uint32_t us);

void        rng_init(void);
void        rng_get_bytes(uint8_t *dst, uint32_t len);

void        usbhid_init(void);
uint32_t    usbhid_tx(uint8_t *tx, uint32_t tx_len);
uint32_t    usbhid_rx(uint8_t *rx, uint32_t rx_len);

void        button_init(void);
bool        button_pushed(void);

void        led_init(void);
void        led_brightness(LED led, uint8_t percent);

uint32_t    flash_write(uint32_t offset, uint8_t *data, uint32_t len);
uint32_t    flash_read(uint32_t offset, uint8_t *data, uint32_t len);
void        flash_erase_block(int8_t block_no);
uint32_t    flash_get_device_address(uint32_t offset);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __GLUE_H__ */

/* end of file ****************************************************************************************************** */
