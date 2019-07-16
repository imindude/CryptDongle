/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "glue.h"

/* ****************************************************************************************************************** */

extern TIM_HandleTypeDef    htim4;

/* ****************************************************************************************************************** */

void led_init(void)
{
    uint32_t    freq_hz = 100;
    uint32_t    clock_hz = HAL_RCC_GetPCLK1Freq() * 2;
    uint32_t    prescalar = 1;

    while (1)
    {
        if (((clock_hz / prescalar) / freq_hz) <= 0xFFFF)
            break;

        prescalar++;
    }

    clock_hz /= prescalar;

    htim4.Init.Prescaler = prescalar - 1;
    htim4.Init.Period    = (clock_hz / freq_hz) - 1;

    HAL_TIM_OC_Init(&htim4);

    TIM_MasterConfigTypeDef master_config =
    {
            .MasterOutputTrigger    = TIM_TRGO_RESET,
            .MasterSlaveMode        = TIM_MASTERSLAVEMODE_DISABLE
    };
    HAL_TIMEx_MasterConfigSynchronization(&htim4, &master_config);

    TIM_OC_InitTypeDef  oc_init =
    {
            .OCMode     = TIM_OCMODE_PWM1,
            .Pulse      = 0,
            .OCPolarity = TIM_OCPOLARITY_HIGH,
            .OCFastMode = TIM_OCFAST_ENABLE
    };
    HAL_TIM_OC_ConfigChannel(&htim4, &oc_init, TIM_CHANNEL_3);
    HAL_TIM_OC_ConfigChannel(&htim4, &oc_init, TIM_CHANNEL_4);

    HAL_TIM_OC_Start(&htim4, TIM_CHANNEL_3);
    HAL_TIM_OC_Start(&htim4, TIM_CHANNEL_4);
}

void led_brightness(LED led, uint8_t percent)
{
    uint32_t    channel = (led == _LED_BLUE) ? TIM_CHANNEL_4 : TIM_CHANNEL_3;
    uint32_t    period = (uint32_t)((float)(htim4.Init.Period + 1) * ((float)percent / 100.0f));

    __HAL_TIM_SET_COMPARE(&htim4, channel, period);
}

/* end of file ****************************************************************************************************** */
