/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include <stdint.h>
#include "stm32f4xx.h"

/* ****************************************************************************************************************** */

extern RNG_HandleTypeDef    hrng;

/* ****************************************************************************************************************** */

void rng_init(void)
{
    HAL_RNG_Init(&hrng);
}

void rng_get_bytes(uint8_t *dst, uint32_t len)
{
    union
    {
        uint32_t    word_;
        uint8_t     byte_[4];
    }
    digit;
    uint32_t    i;

    for (i = 0; i < (len / 4); i++)
    {
        HAL_RNG_GenerateRandomNumber(&hrng, &digit.word_);
        *(uint32_t*)(&dst[4 * i]) = digit.word_;
    }

    if (len % 4)
    {
        HAL_RNG_GenerateRandomNumber(&hrng, &digit.word_);
        for (uint8_t j = 0; j < (len % 4); j++)
            dst[4 * i + j] = digit.byte_[j];
    }
}

/* end of file ****************************************************************************************************** */
