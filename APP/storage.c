/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "storage.h"
#include "glue.h"
#include "misc.h"

/* ****************************************************************************************************************** */

#define STORAGE_BLOCK_SIZE      (128 * 1024)
#define INVALID_OFFSET          STORAGE_BLOCK_SIZE

#define STORAGE_DEV_BLOCK       0
#define STORAGE_KEY_BLOCK       1
#define STORAGE_DEV_OFFSET      (STORAGE_DEV_BLOCK * STORAGE_BLOCK_SIZE)
#define STORAGE_KEY_OFFSET      (STORAGE_KEY_BLOCK * STORAGE_BLOCK_SIZE)

#define STORAGE_MAGIC_WORD      0xDEAD
#define FILE_FLAG_EMPTY         0xFFFFFFFF
#define FILE_FLAG_ERASED        0x00000000

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

struct StorageDev
{
    uint32_t    count_;
    uint8_t     uid_[DEV_UID_LEN];
    uint8_t     pin_[DEV_PIN_LEN];
    uint16_t    crc16_;
};
typedef struct StorageDev       StorageDev;

struct StorageKey
{
    uint16_t    key_len_;
    uint16_t    crc16_;
};
typedef struct StorageKey       StorageKey;

#pragma pack(pop)

/* ****************************************************************************************************************** */

static uint32_t find_dev_offset(void)
{
    uint8_t     count;

    for (uint32_t offset = STORAGE_DEV_OFFSET; offset < STORAGE_BLOCK_SIZE; offset += sizeof(StorageDev))
    {
        if (flash_read(offset, &count, 4) > 0)
        {
            if (count == FILE_FLAG_EMPTY)
                break;
            else if (count != FILE_FLAG_ERASED)
                return offset;
        }
    }

    return INVALID_OFFSET;
}

void storage_dev_reset(void)
{
    flash_erase_block(STORAGE_DEV_BLOCK);
}

bool storage_dev_read(uint8_t *uid, uint8_t *pin)
{
    StorageDev  sdev;
    uint32_t    offset = find_dev_offset();

    if ((offset != INVALID_OFFSET) && (flash_read(offset, (uint8_t*)&sdev, sizeof(StorageDev)) > 0))
    {
        if (sdev.crc16_ == get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)&sdev, sizeof(StorageDev) - 2))
        {
            if (uid)
                memcpy(uid, sdev.uid_, DEV_UID_LEN);
            if (pin)
                memcpy(pin, sdev.pin_, DEV_PIN_LEN);

            return true;
        }
    }

    return false;
}

bool storage_dev_write(uint8_t *uid, uint8_t *pin)
{
    StorageDev  sdev;
    uint32_t    offset = find_dev_offset();
    uint32_t    count = 1;

    if ((offset != INVALID_OFFSET) && (flash_read(offset, (uint8_t*)&sdev, sizeof(StorageDev)) > 0))
    {
        count = sdev.count_;

        sdev.count_ = FILE_FLAG_ERASED;
        flash_write(offset, (uint8_t*)&sdev, sizeof(StorageDev));

        offset += sizeof(StorageDev);

        if (offset > (STORAGE_BLOCK_SIZE - sizeof(StorageDev)))
        {
            flash_erase_block(STORAGE_DEV_BLOCK);
            offset = STORAGE_DEV_OFFSET;
        }

        if (uid)
        {
            memset(sdev.uid_, 0, DEV_UID_LEN);
            memcpy(sdev.uid_, uid, DEV_UID_LEN);
        }

        if (pin)
        {
            memset(sdev.pin_, 0, DEV_PIN_LEN);
            memcpy(sdev.pin_, pin, DEV_PIN_LEN);
        }

        sdev.count_ = count;
        sdev.crc16_ = get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)&sdev, sizeof(StorageDev) - 2);

        if (flash_write(offset, (uint8_t*)&sdev, sizeof(StorageDev)) > 0)
            return true;
    }

    return false;
}

uint32_t storage_dev_count(void)
{
    StorageDev  sdev;
    uint32_t    offset = find_dev_offset();
    uint32_t    count = 0;

    if ((offset != INVALID_OFFSET) && (flash_read(offset, (uint8_t*)&sdev, sizeof(StorageDev)) > 0))
    {
        if (sdev.crc16_ == get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)&sdev, sizeof(StorageDev) - 2))
        {
            count = sdev.count_ + 1;

            sdev.count_ = FILE_FLAG_ERASED;
            flash_write(offset, (uint8_t*)&sdev, sizeof(StorageDev));

            offset += sizeof(StorageDev);

            if (offset > (STORAGE_BLOCK_SIZE - sizeof(StorageDev)))
            {
                flash_erase_block(STORAGE_DEV_BLOCK);
                offset = STORAGE_DEV_OFFSET;
            }

            sdev.count_ = count;
            sdev.crc16_ = get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)&sdev, sizeof(StorageDev) - 2);

            if (flash_write(offset, (uint8_t*)&sdev, sizeof(StorageDev)) == 0)
                count = 0;
        }
    }

    return count;
}

bool storage_key_read(uint8_t *key, uint16_t *key_len)
{
    StorageKey  skey;

    if (flash_read(STORAGE_KEY_OFFSET, (uint8_t*)&skey, sizeof(StorageKey)) > 0)
    {
        uint32_t    offset = STORAGE_KEY_OFFSET + sizeof(StorageKey);
        uint32_t    device_address = flash_get_device_address(offset);

        if (get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)device_address, skey.key_len_) == skey.crc16_)
        {
            flash_read(offset, key, skey.key_len_);
            *key_len = skey.key_len_;

            return true;
        }
    }

    return false;
}

bool storage_key_write(uint8_t *key, uint16_t key_len)
{
    StorageKey  skey;

    skey.key_len_ = key_len;
    skey.crc16_ = get_crc16_ccitt(STORAGE_MAGIC_WORD, key, key_len);

    flash_erase_block(STORAGE_KEY_BLOCK);

    if (flash_write(STORAGE_KEY_OFFSET, (uint8_t*)&skey, sizeof(StorageKey)) > 0)
    {
        uint32_t    offset = STORAGE_KEY_OFFSET + sizeof(StorageKey);
        uint32_t    device_address = flash_get_device_address(offset);

        flash_write(offset, key, key_len);

        if (flash_read(STORAGE_KEY_OFFSET, (uint8_t*)&skey, sizeof(StorageKey)) > 0)
        {
            if (get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)device_address, skey.key_len_) == skey.crc16_)
                return true;
        }
    }

    return false;
}

uint16_t storage_key_size(void)
{
    StorageKey  skey;

    if (flash_read(STORAGE_KEY_OFFSET, (uint8_t*)&skey, sizeof(StorageKey)) > 0)
    {
        uint32_t    device_address = flash_get_device_address(STORAGE_KEY_OFFSET + sizeof(StorageKey));

        if (get_crc16_ccitt(STORAGE_MAGIC_WORD, (uint8_t*)device_address, skey.key_len_) == skey.crc16_)
            return skey.key_len_;
    }

    return 0;
}

/* end of file ****************************************************************************************************** */
