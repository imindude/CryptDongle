/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
#include "buffer.h"
#include "glue.h"

/* ****************************************************************************************************************** */

USBD_HandleTypeDef hUsbDeviceFS;

/* ****************************************************************************************************************** */

void usbhid_init(void)
{
    USBD_Init(&hUsbDeviceFS, &FS_Desc, DEVICE_FS);
    USBD_RegisterClass(&hUsbDeviceFS, &USBD_HID);
    USBD_Start(&hUsbDeviceFS);
}

uint32_t usbhid_tx(uint8_t *tx, uint32_t tx_len)
{
    uint32_t    sent_size = 0;
    uint32_t    actual_len;
    uint8_t     report[HID_PACKET_SIZE];
    uint32_t    timeout_ms;

    while (tx_len > 0)
    {
        actual_len = tx_len;
        if (actual_len > HID_PACKET_SIZE)
            actual_len = HID_PACKET_SIZE;
        memcpy(report, tx + sent_size, actual_len);

        timeout_ms = get_millis() + 300;
        while (USBD_HID_SendReport(&hUsbDeviceFS, report, actual_len) != USBD_OK)
        {
            if (timeout_ms < get_millis())
                return sent_size;
        }

        tx_len -= actual_len;
        sent_size += actual_len;
    }

    return sent_size;
}

uint32_t usbhid_rx(uint8_t *rx, uint32_t rx_len)
{
    uint32_t    read_size = 0;
    uint32_t    actual_len;
    uint8_t     recv[HID_PACKET_SIZE];

    while (rx_len > 0)
    {
        if (bf_usbhid.size() > 0)
        {
            actual_len = rx_len;
            if (actual_len > HID_PACKET_SIZE)
                actual_len = HID_PACKET_SIZE;
            bf_usbhid.take(recv);
            memcpy(rx + read_size, recv, actual_len);
            read_size += actual_len;
            rx_len -= actual_len;
        }
        else
        {
            break;
        }
    }

    return read_size;
}

/* end of file ****************************************************************************************************** */
