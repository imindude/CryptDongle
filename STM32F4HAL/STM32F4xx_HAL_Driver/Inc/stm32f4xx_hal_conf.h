/**
 * *********************************************************************************************************************
 * @author      wuyong.yi@sisoul.co.kr
 * @copyright   Copyright 2018 SISOUL. All rights reserved.
 * *********************************************************************************************************************
 */

#ifndef __STM32F4XX_HAL_CONF_H__
#define __STM32F4XX_HAL_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#if !defined  (HSE_VALUE)
#   define HSE_VALUE                ((uint32_t)8000000U)
#endif

#if !defined  (HSE_STARTUP_TIMEOUT)
#   define HSE_STARTUP_TIMEOUT      ((uint32_t)100U)
#endif

#if !defined  (HSI_VALUE)
#   define HSI_VALUE                ((uint32_t)16000000U)
#endif

#if !defined  (LSI_VALUE)
#   define LSI_VALUE                ((uint32_t)32000U)
#endif

#if !defined  (LSE_VALUE)
#   define LSE_VALUE                ((uint32_t)32768U)
#endif

#if !defined  (LSE_STARTUP_TIMEOUT)
#   define LSE_STARTUP_TIMEOUT      ((uint32_t)5000U)
#endif

#if !defined  (EXTERNAL_CLOCK_VALUE)
#   define EXTERNAL_CLOCK_VALUE     ((uint32_t)12288000U)
#endif

#define VDD_VALUE                   ((uint32_t)3300U)
#define TICK_INT_PRIORITY           ((uint32_t)0U)
#define USE_RTOS                    0U
#define PREFETCH_ENABLE             1U
#define INSTRUCTION_CACHE_ENABLE    1U
#define DATA_CACHE_ENABLE           1U

#define USE_SPI_CRC                 0U

/* ****************************************************************************************************************** */

#define HAL_MODULE_ENABLED

#define HAL_RCC_MODULE_ENABLED
#ifdef HAL_RCC_MODULE_ENABLED
#   include "stm32f4xx_hal_rcc.h"
#endif

#ifdef HAL_EXTI_MODULE_ENABLED
#   include "stm32f4xx_hal_exti.h"
#endif

#define HAL_GPIO_MODULE_ENABLED
#ifdef HAL_GPIO_MODULE_ENABLED
#   include "stm32f4xx_hal_gpio.h"
#endif

#define HAL_DMA_MODULE_ENABLED
#ifdef HAL_DMA_MODULE_ENABLED
#   include "stm32f4xx_hal_dma.h"
#endif

#define HAL_CORTEX_MODULE_ENABLED
#ifdef HAL_CORTEX_MODULE_ENABLED
#   include "stm32f4xx_hal_cortex.h"
#endif

#ifdef HAL_ADC_MODULE_ENABLED
#   include "stm32f4xx_hal_adc.h"
#endif

#ifdef HAL_CAN_MODULE_ENABLED
#   include "stm32f4xx_hal_can.h"
#endif

#ifdef HAL_CRC_MODULE_ENABLED
#   include "stm32f4xx_hal_crc.h"
#endif

#ifdef HAL_CRYP_MODULE_ENABLED
#   include "stm32f4xx_hal_cryp.h"
#endif

#ifdef HAL_DMA2D_MODULE_ENABLED
#   include "stm32f4xx_hal_dma2d.h"
#endif

#ifdef HAL_DAC_MODULE_ENABLED
#   include "stm32f4xx_hal_dac.h"
#endif

#ifdef HAL_DCMI_MODULE_ENABLED
#   include "stm32f4xx_hal_dcmi.h"
#endif

#ifdef HAL_ETH_MODULE_ENABLED
#   include "stm32f4xx_hal_eth.h"
#endif

#define HAL_FLASH_MODULE_ENABLED
#ifdef HAL_FLASH_MODULE_ENABLED
#   include "stm32f4xx_hal_flash.h"
#endif

#ifdef HAL_SRAM_MODULE_ENABLED
#   include "stm32f4xx_hal_sram.h"
#endif

#ifdef HAL_NOR_MODULE_ENABLED
#   include "stm32f4xx_hal_nor.h"
#endif

#ifdef HAL_NAND_MODULE_ENABLED
#   include "stm32f4xx_hal_nand.h"
#endif

#ifdef HAL_PCCARD_MODULE_ENABLED
#   include "stm32f4xx_hal_pccard.h"
#endif

#ifdef HAL_SDRAM_MODULE_ENABLED
#   include "stm32f4xx_hal_sdram.h"
#endif

#ifdef HAL_HASH_MODULE_ENABLED
#   include "stm32f4xx_hal_hash.h"
#endif

#ifdef HAL_I2C_MODULE_ENABLED
#   include "stm32f4xx_hal_i2c.h"
#endif

#ifdef HAL_I2S_MODULE_ENABLED
#   include "stm32f4xx_hal_i2s.h"
#endif

#ifdef HAL_IWDG_MODULE_ENABLED
#   include "stm32f4xx_hal_iwdg.h"
#endif

#ifdef HAL_LTDC_MODULE_ENABLED
#   include "stm32f4xx_hal_ltdc.h"
#endif

#define HAL_PWR_MODULE_ENABLED
#ifdef HAL_PWR_MODULE_ENABLED
#   include "stm32f4xx_hal_pwr.h"
#endif

#define HAL_RNG_MODULE_ENABLED
#ifdef HAL_RNG_MODULE_ENABLED
#   include "stm32f4xx_hal_rng.h"
#endif

#ifdef HAL_RTC_MODULE_ENABLED
#   include "stm32f4xx_hal_rtc.h"
#endif

#ifdef HAL_SAI_MODULE_ENABLED
#   include "stm32f4xx_hal_sai.h"
#endif

#ifdef HAL_SD_MODULE_ENABLED
#   include "stm32f4xx_hal_sd.h"
#endif

#ifdef HAL_MMC_MODULE_ENABLED
#   include "stm32f4xx_hal_mmc.h"
#endif

#ifdef HAL_SPI_MODULE_ENABLED
#   include "stm32f4xx_hal_spi.h"
#endif

#define HAL_TIM_MODULE_ENABLED
#ifdef HAL_TIM_MODULE_ENABLED
#   include "stm32f4xx_hal_tim.h"
#endif

#ifdef HAL_UART_MODULE_ENABLED
#   include "stm32f4xx_hal_uart.h"
#endif

#ifdef HAL_USART_MODULE_ENABLED
#   include "stm32f4xx_hal_usart.h"
#endif

#ifdef HAL_IRDA_MODULE_ENABLED
#   include "stm32f4xx_hal_irda.h"
#endif

#ifdef HAL_SMARTCARD_MODULE_ENABLED
#   include "stm32f4xx_hal_smartcard.h"
#endif

#ifdef HAL_WWDG_MODULE_ENABLED
#   include "stm32f4xx_hal_wwdg.h"
#endif

#define HAL_PCD_MODULE_ENABLED
#ifdef HAL_PCD_MODULE_ENABLED
#   include "stm32f4xx_hal_pcd.h"
#endif

#ifdef HAL_HCD_MODULE_ENABLED
#   include "stm32f4xx_hal_hcd.h"
#endif

#ifdef HAL_DSI_MODULE_ENABLED
#   include "stm32f4xx_hal_dsi.h"
#endif

#ifdef HAL_QSPI_MODULE_ENABLED
#   include "stm32f4xx_hal_qspi.h"
#endif

#ifdef HAL_CEC_MODULE_ENABLED
#   include "stm32f4xx_hal_cec.h"
#endif

#ifdef HAL_FMPI2C_MODULE_ENABLED
#   include "stm32f4xx_hal_fmpi2c.h"
#endif

#ifdef HAL_SPDIFRX_MODULE_ENABLED
#   include "stm32f4xx_hal_spdifrx.h"
#endif

#ifdef HAL_DFSDM_MODULE_ENABLED
#   include "stm32f4xx_hal_dfsdm.h"
#endif

#ifdef HAL_LPTIM_MODULE_ENABLED
#   include "stm32f4xx_hal_lptim.h"
#endif

/* ****************************************************************************************************************** */

#define assert_param(expr)      ((void)0U)

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* __STM32F4XX_HAL_CONF_H__ */

/* end of file ****************************************************************************************************** */
