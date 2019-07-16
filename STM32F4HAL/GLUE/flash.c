/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 * @note        FLASH memory map
 *
 *              Sector  0 : 0x08000000 : 16KB
 *              Sector  1 : 0x08004000 : 16KB
 *              Sector  2 : 0x08008000 : 16KB
 *              Sector  3 : 0x0800C000 : 16KB
 *              Sector  4 : 0x08010000 : 64KB
 *              Sector  5 : 0x08020000 : 128KB
 *              Sector  6 : 0x08040000 : 128KB
 *              Sector  7 : 0x08060000 : 128KB
 *              Sector  8 : 0x08080000 : 128KB
 *              Sector  9 : 0x080A0000 : 128KB
 *              Sector 10 : 0x080C0000 : 128KB
 *              Sector 11 : 0x080E0000 : 128KB
 *
 */

#include <stdint.h>
#include <string.h>
#include "stm32f4xx.h"
#include "glue.h"

/* ****************************************************************************************************************** */

#define FLASH_USER_SECTOR           FLASH_SECTOR_10
#define FLASH_USER_ADDRESS          0x080C0000
#define FLASH_USER_BLOCKS           2
#define FLASH_USER_SIZE             (128 * 1024 * FLASH_USER_BLOCKS)

/* ****************************************************************************************************************** */

static inline bool check_offset(uint32_t offset, uint32_t len)
{
    return ((offset + len) < FLASH_USER_SIZE) ? true : false;
}

uint32_t flash_write(uint32_t offset, uint8_t *data, uint32_t len)
{
    if (check_offset(offset, len))
    {
        uint16_t    n = 0;
        uint32_t    addr = FLASH_USER_ADDRESS + offset;

        HAL_FLASH_Unlock();

        for (n = 0; n < len; n++)
        {
            if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, addr + n, data[n]) != HAL_OK)
            {
                len = 0;
                break;
            }
        }

        HAL_FLASH_Lock();
    }
    else
    {
        len = 0;
    }

    return len;
}

uint32_t flash_read(uint32_t offset, uint8_t *data, uint32_t len)
{
    if (check_offset(offset, len))
    {
        uint32_t    addr = FLASH_USER_ADDRESS + offset;

        memcpy(data, (uint8_t*)addr, len);

        return len;
    }

    return 0;
}

void flash_erase_block(int8_t block_no)
{
    FLASH_EraseInitTypeDef  erase =
    {
            .TypeErase      = FLASH_TYPEERASE_SECTORS,
            .Banks          = 0,
            .Sector         = FLASH_USER_SECTOR + block_no,
            .NbSectors      = 1,
            .VoltageRange   = FLASH_VOLTAGE_RANGE_3
    };
    uint32_t            error_sector;

    HAL_FLASH_Unlock();
    HAL_FLASHEx_Erase(&erase, &error_sector);
    HAL_FLASH_Lock();
}

uint32_t flash_get_device_address(uint32_t offset)
{
    if (check_offset(offset, 0))
        return FLASH_USER_ADDRESS + offset;

    return 0;
}

/* end of file ****************************************************************************************************** */
