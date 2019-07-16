/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"

/* ****************************************************************************************************************** */

RNG_HandleTypeDef   hrng =
{
        .Instance = RNG
};
TIM_HandleTypeDef   htim4 =
{
        .Instance = TIM4,
        .Init.Prescaler     = 0,
        .Init.CounterMode   = TIM_COUNTERMODE_UP,
        .Init.Period        = 0,
        .Init.ClockDivision = TIM_CLOCKDIVISION_DIV1
};
PCD_HandleTypeDef   hpcd_USB_OTG_FS;

/* ****************************************************************************************************************** */

static uint32_t micros_tick = 0;

/* ****************************************************************************************************************** */

static void system_clock_config(void)
{
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

    RCC_OscInitTypeDef  osc_init =
    {
            .OscillatorType = RCC_OSCILLATORTYPE_HSE,
            .HSEState       = RCC_HSE_ON,
            .PLL.PLLState   = RCC_PLL_ON,
            .PLL.PLLSource  = RCC_PLLSOURCE_HSE,
            .PLL.PLLM       = 4,
            .PLL.PLLN       = 168,
            .PLL.PLLP       = RCC_PLLP_DIV2,
            .PLL.PLLQ       = 7
    };
    HAL_RCC_OscConfig(&osc_init);

    RCC_ClkInitTypeDef  clk_init =
    {
            .ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2,
            .SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK,
            .AHBCLKDivider  = RCC_SYSCLK_DIV1,
            .APB1CLKDivider = RCC_HCLK_DIV4,
            .APB2CLKDivider = RCC_HCLK_DIV2
    };
    HAL_RCC_ClockConfig(&clk_init, FLASH_LATENCY_5);

    HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq() / 1000);
    HAL_SYSTICK_CLKSourceConfig(SYSTICK_CLKSOURCE_HCLK);
    micros_tick = HAL_RCC_GetSysClockFreq() / 1000000;
}

uint32_t get_micros_tick(void)
{
    return micros_tick;
}

void HAL_MspInit(void)
{
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    __HAL_RCC_PWR_CLK_ENABLE();

    system_clock_config();
}

void HAL_RNG_MspInit(RNG_HandleTypeDef* hrng)
{
    if (hrng->Instance == RNG)
    {
        __HAL_RCC_RNG_CLK_ENABLE();
    }
}

void HAL_TIM_OC_MspInit(TIM_HandleTypeDef* htim_oc)
{
    if (htim_oc->Instance == TIM4)
    {
        __HAL_RCC_TIM4_CLK_ENABLE();
        __HAL_RCC_GPIOD_CLK_ENABLE();

        /**
         * TIM4 GPIO Configuration
         * PD14     ------> TIM4_CH3
         * PD15     ------> TIM4_CH4
         */

        GPIO_InitTypeDef init =
        {
                .Pin        = GPIO_PIN_14 | GPIO_PIN_15,
                .Mode       = GPIO_MODE_AF_PP,
                .Pull       = GPIO_NOPULL,
                .Speed      = GPIO_SPEED_FREQ_LOW,
                .Alternate  = GPIO_AF2_TIM4
        };
        HAL_GPIO_Init(GPIOD, &init);
    }
}

void HAL_PCD_MspInit(PCD_HandleTypeDef* hpcd)
{
    if (hpcd->Instance == USB_OTG_FS)
    {
        __HAL_RCC_GPIOA_CLK_ENABLE();

        /**
         * USB_OTG_FS GPIO Configuration
         * PA9      ------> USB_OTG_FS_VBUS
         * PA11     ------> USB_OTG_FS_DM
         * PA12     ------> USB_OTG_FS_DP
         */

        GPIO_InitTypeDef init =
        {
                .Pin        = GPIO_PIN_12,
                .Mode       = GPIO_MODE_OUTPUT_OD,
                .Pull       = GPIO_NOPULL,
                .Speed      = GPIO_SPEED_FREQ_VERY_HIGH,
                .Alternate  = 0
        };
        HAL_GPIO_Init(GPIOA, &init);

        /**
         * USB reset
         */
        HAL_GPIO_WritePin(GPIOA, init.Pin, GPIO_PIN_RESET);
        HAL_Delay(100);
        HAL_GPIO_WritePin(GPIOA, init.Pin, GPIO_PIN_SET);
        HAL_Delay(100);
        HAL_GPIO_DeInit(GPIOA, init.Pin);

        /**
         * USB Init.
         */

        init.Pin        = GPIO_PIN_9;
        init.Mode       = GPIO_MODE_INPUT;
        init.Pull       = GPIO_NOPULL;
        init.Speed      = GPIO_SPEED_FREQ_VERY_HIGH;
        init.Alternate  = 0;
        HAL_GPIO_Init(GPIOA, &init);

        init.Pin        = GPIO_PIN_11 | GPIO_PIN_12;
        init.Mode       = GPIO_MODE_AF_PP;
        init.Pull       = GPIO_NOPULL;
        init.Speed      = GPIO_SPEED_FREQ_VERY_HIGH;
        init.Alternate  = GPIO_AF10_OTG_FS;
        HAL_GPIO_Init(GPIOA, &init);

        __HAL_RCC_USB_OTG_FS_CLK_ENABLE();

        HAL_NVIC_SetPriority(OTG_FS_IRQn, 0, 0);
        HAL_NVIC_EnableIRQ(OTG_FS_IRQn);
    }
}


/* end of file ****************************************************************************************************** */
