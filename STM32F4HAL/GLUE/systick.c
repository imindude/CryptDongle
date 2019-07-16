/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include <stdint.h>
#include "stm32f4xx.h"

/* ****************************************************************************************************************** */

extern RNG_HandleTypeDef    hrng;
extern TIM_HandleTypeDef    htim4;
extern PCD_HandleTypeDef    hpcd_USB_OTG_FS;

extern uint32_t get_micros_tick(void);

/* ****************************************************************************************************************** */

uint32_t get_millis(void)
{
    return HAL_GetTick();
}

uint32_t get_micros(void)
{
    volatile uint32_t   now_ticks = SysTick->VAL;   // down count
    return HAL_GetTick() * 1000 + (1000 - (now_ticks / get_micros_tick()));
}

void delay_millis(uint32_t ms)
{
    HAL_Delay(ms);
}

void delay_micros(uint32_t us)
{
    volatile uint32_t   target_us = get_micros() + us;

    while (get_micros() < target_us)
        __asm("nop");
}

/* end of file ****************************************************************************************************** */
