/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include <stdbool.h>
#include "stm32f4xx.h"
#include "glue.h"

/* ****************************************************************************************************************** */

void button_init(void)
{
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitTypeDef    init =
    {
            .Pin    = GPIO_PIN_0,
            .Mode   = GPIO_MODE_INPUT,
            .Pull   = GPIO_NOPULL
    };
    HAL_GPIO_Init(GPIOA, &init);
}

bool button_pushed(void)
{
    return (HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_SET) ? true : false;
}

/* end of file ****************************************************************************************************** */
