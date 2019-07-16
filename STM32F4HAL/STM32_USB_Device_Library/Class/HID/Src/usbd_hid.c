/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "usbd_hid.h"
#include "usbd_desc.h"
#include "usbd_ctlreq.h"
#include "buffer.h"

/* ****************************************************************************************************************** */

/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_CfgDesc[USB_HID_CONFIG_DESC_SIZ] __ALIGN_END =
{
        0x09,                           /* bLength: Configuration Descriptor size */
        USB_DESC_TYPE_CONFIGURATION,    /* bDescriptorType: Configuration */
        USB_HID_CONFIG_DESC_SIZ, 0x00,  /* wTotalLength: Bytes returned */

        0x01,                           /*bNumInterfaces: 1 interface*/
        0x01,                           /*bConfigurationValue: Configuration value*/
        0x00,                           /*iConfiguration: Index of string descriptor describing the configuration*/
        0x80,                           /*bmAttributes: bus powered and Support Remote Wake-up */
        0xFA,                           /*MaxPower 500 mA: this current is used for detecting Vbus*/

        /************** Descriptor of HID interface ****************/
        0x09,                           /*bLength: Interface Descriptor size*/
        USB_DESC_TYPE_INTERFACE,        /*bDescriptorType: Interface descriptor type*/
        0x00,                           /*bInterfaceNumber: Number of Interface*/
        0x00,                           /*bAlternateSetting: Alternate setting*/
        0x02,                           /*bNumEndpoints*/
        0x03,                           /*bInterfaceClass: HID*/
        0x00,                           /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
        0x00,                           /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
        0,                              /*iInterface: Index of string descriptor*/

        /******************** Descriptor of HID ********************/
        0x09,                           /*bLength: HID Descriptor size*/
        HID_DESCRIPTOR_TYPE,            /*bDescriptorType: HID*/
        0x11, 0x01,                     /*bcdHID: HID Class Spec release number*/
        0x00,                           /*bCountryCode: Hardware target country*/
        0x01,                           /*bNumDescriptors: Number of HID class descriptors to follow*/
        0x22,                           /*bDescriptorType*/
        USB_HID_REPORT_DESC_SIZE, 0x00, /*wItemLength: Total length of Report descriptor*/

        /******************** Descriptor of Mouse endpoint ********************/
        0x07,                           /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT,         /*bDescriptorType:*/
        HID_EPIN_ADDR,                  /*bEndpointAddress: Endpoint Address (IN)*/
        0x03,                           /*bmAttributes: Interrupt endpoint*/
        HID_EPIN_SIZE, 0x00,            /*wMaxPacketSize: 4 Byte max */
        HID_FS_BINTERVAL,               /*bInterval: Polling Interval (5 ms)*/

        0x07,                           /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT,         /*bDescriptorType:*/
        HID_EPOUT_ADDR,                 /*bEndpointAddress: Endpoint Address (IN)*/
        0x03,                           /*bmAttributes: Interrupt endpoint*/
        HID_EPOUT_SIZE, 0x00,           /*wMaxPacketSize: 4 Byte max */
        HID_FS_BINTERVAL,               /*bInterval: Polling Interval */
};

/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_Desc[USB_HID_DESC_SIZ] __ALIGN_END =
{
        0x09,                           /*bLength: HID Descriptor size*/
        HID_DESCRIPTOR_TYPE,            /*bDescriptorType: HID*/
        0x11, 0x01,                     /*bcdHID: HID Class Spec release number*/
        0x00,                           /*bCountryCode: Hardware target country*/
        0x01,                           /*bNumDescriptors: Number of HID class descriptors to follow*/
        0x22,                           /*bDescriptorType*/
        USB_HID_REPORT_DESC_SIZE,       /*wItemLength: Total length of Report descriptor*/
        0x00,
};

/* USB Standard Device Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] __ALIGN_END =
{
        USB_LEN_DEV_QUALIFIER_DESC,
        USB_DESC_TYPE_DEVICE_QUALIFIER,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x40,
        0x01,
        0x00,
};

__ALIGN_BEGIN static uint8_t USBD_HID_ReportDesc[USB_HID_REPORT_DESC_SIZE] __ALIGN_END =
{
        0x06, 0xD0, 0xF1,       // USAGE PAGE (FIDO Alliance)
        0x09, 0x01,             // USAGE (U2F Authenticator Device)
        0xA1, 0x01,             // COLLECTION (Application)

        0x09, 0x20,             // USAGE (Input Report Data)
        0x15, 0x00,             // LOGICAL_MININUM (0)
        0x26, 0xFF, 0x00,       // LOGICAL_MAXIMUM (255)
        0x75, 0x08,             // REPORT SIZE (8)
        0x95, HID_PACKET_SIZE,  // REPORT COUNT (64)
        0x81, 0x02,             // INPUT (Data, Var, Abs)

        0x09, 0x21,             // USAGE (Output Report Data)
        0x15, 0x00,             // LOGICAL_MININUM (0)
        0x26, 0xFF, 0x00,       // LOGICAL_MAXIMUM (255)
        0x75, 0x08,             // REPORT SIZE (8)
        0x95, HID_PACKET_SIZE,  // REPORT COUNT (64)
        0x91, 0x02,             // OUTPUT (Data, Ver, Abs)

        0xC0,                   // END COLLECTION
};

static uint8_t  usbhid_recv[HID_PACKET_SIZE];

/* ****************************************************************************************************************** */

static uint8_t USBD_HID_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    uint8_t ret = USBD_OK;

    /* Open EP IN */
    USBD_LL_OpenEP(pdev, HID_EPIN_ADDR, USBD_EP_TYPE_INTR, HID_EPIN_SIZE);
    USBD_LL_OpenEP(pdev, HID_EPOUT_ADDR, USBD_EP_TYPE_INTR, HID_EPOUT_SIZE);

    pdev->pClassData = USBD_malloc(sizeof(USBD_HID_HandleTypeDef));

    if (pdev->pClassData == NULL)
    {
        ret = USBD_FAIL;
    }
    else
    {
        ((USBD_HID_HandleTypeDef *) pdev->pClassData)->state = HID_IDLE;
        USBD_LL_PrepareReceive(pdev, HID_EPOUT_ADDR, usbhid_recv, HID_PACKET_SIZE);
    }
    return ret;
}

/**
 * @brief  USBD_HID_Init
 *         DeInitialize the HID layer
 * @param  pdev: device instance
 * @param  cfgidx: Configuration index
 * @retval status
 */
static uint8_t USBD_HID_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    /* Close HID EPs */
    USBD_LL_CloseEP(pdev, HID_EPIN_ADDR);
    USBD_LL_CloseEP(pdev, HID_EPOUT_ADDR);

    /* FRee allocated memory */
    if (pdev->pClassData != NULL)
    {
        USBD_free(pdev->pClassData);
        pdev->pClassData = NULL;
    }

    return USBD_OK;
}

/**
 * @brief  USBD_HID_Setup
 *         Handle the HID specific requests
 * @param  pdev: instance
 * @param  req: usb requests
 * @retval status
 */
static uint8_t USBD_HID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
    uint16_t len = 0;
    uint8_t *pbuf = NULL;
    uint16_t status = 0;
    USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef*) pdev->pClassData;

    switch (req->bmRequest & USB_REQ_TYPE_MASK)
    {
    case USB_REQ_TYPE_CLASS:

        switch (req->bRequest)
        {
        case HID_REQ_SET_PROTOCOL:
            hhid->Protocol = (uint8_t) (req->wValue);
            break;

        case HID_REQ_GET_PROTOCOL:
            USBD_CtlSendData(pdev, (uint8_t *) &hhid->Protocol, 1);
            break;

        case HID_REQ_SET_IDLE:
            hhid->IdleState = (uint8_t) (req->wValue >> 8);
            break;

        case HID_REQ_GET_IDLE:
            USBD_CtlSendData(pdev, (uint8_t *) &hhid->IdleState, 1);
            break;

        default:
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    case USB_REQ_TYPE_STANDARD:

        switch (req->bRequest)
        {
        case USB_REQ_GET_STATUS:

            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                USBD_CtlSendData(pdev, (uint8_t*)&status, 2);
            }
            else
            {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }

            break;

        case USB_REQ_GET_DESCRIPTOR:
            if (req->wValue >> 8 == HID_REPORT_DESC)
            {
                len = MIN(USB_HID_REPORT_DESC_SIZE, req->wLength);
                pbuf = USBD_HID_ReportDesc;
            }
            else if (req->wValue >> 8 == HID_DESCRIPTOR_TYPE)
            {
                pbuf = USBD_HID_Desc;
                len = MIN(USB_HID_DESC_SIZ, req->wLength);
            }
            else
            {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }

            USBD_CtlSendData(pdev, pbuf, len);

            break;

        case USB_REQ_GET_INTERFACE:
            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                USBD_CtlSendData(pdev, (uint8_t *) &hhid->AltSetting, 1);
            }
            else
            {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }

            break;

        case USB_REQ_SET_INTERFACE:
            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                hhid->AltSetting = (uint8_t) (req->wValue);
            }
            else
            {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
            break;

        default:

            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    default:

        USBD_CtlError(pdev, req);
        return USBD_FAIL;
    }
    return USBD_OK;
}

/**
 * @brief  USBD_HID_GetCfgDesc
 *         return configuration descriptor
 * @param  speed : current device speed
 * @param  length : pointer data length
 * @retval pointer to descriptor buffer
 */
static uint8_t *USBD_HID_GetCfgDesc(uint16_t *length)
{
    *length = sizeof(USBD_HID_CfgDesc);
    return USBD_HID_CfgDesc;
}

/**
 * @brief  USBD_HID_DataIn
 *         handle data IN Stage
 * @param  pdev: device instance
 * @param  epnum: endpoint index
 * @retval status
 */
static uint8_t USBD_HID_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    /* Ensure that the FIFO is empty before a new transfer, this condition could
     be caused by  a new transfer before the end of the previous transfer */
    ((USBD_HID_HandleTypeDef *) pdev->pClassData)->state = HID_IDLE;
    return USBD_OK;
}

static uint8_t USBD_HID_DataOut(USBD_HandleTypeDef *pdev, uint8_t epenum)
{
    /* Ensure that the FIFO is empty before a new transfer, this condition could
     be caused by  a new transfer before the end of the previous transfer */
    ((USBD_HID_HandleTypeDef *) pdev->pClassData)->state = HID_IDLE;
    return USBD_OK;
}

/**
 * @brief  DeviceQualifierDescriptor
 *         return Device Qualifier descriptor
 * @param  length : pointer data length
 * @retval pointer to descriptor buffer
 */
static uint8_t *USBD_HID_GetDeviceQualifierDesc(uint16_t *length)
{
    *length = sizeof(USBD_HID_DeviceQualifierDesc);
    return USBD_HID_DeviceQualifierDesc;
}

/**
 * @brief  USBD_HID_SendReport
 *         Send HID Report
 * @param  pdev: device instance
 * @param  buff: pointer to report
 * @retval status
 */
uint8_t USBD_HID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)
{
    USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef*) pdev->pClassData;

    if (pdev->dev_state == USBD_STATE_CONFIGURED)
    {
        if (hhid->state == HID_IDLE)
        {
            hhid->state = HID_BUSY;
            return USBD_LL_Transmit(pdev, HID_EPIN_ADDR, report, len);
        }
    }
    return USBD_BUSY;
}

/**
 * @brief  USBD_HID_GetPollingInterval
 *         return polling interval from endpoint descriptor
 * @param  pdev: device instance
 * @retval polling interval
 */
uint32_t USBD_HID_GetPollingInterval(USBD_HandleTypeDef *pdev)
{
    uint32_t polling_interval = 0;

    /* HIGH-speed endpoints */
    if (pdev->dev_speed == USBD_SPEED_HIGH)
    {
        /* Sets the data transfer polling interval for high speed transfers.
         Values between 1..16 are allowed. Values correspond to interval
         of 2 ^ (bInterval-1). This option (8 ms, corresponds to HID_HS_BINTERVAL */
        polling_interval = (((1 << (HID_HS_BINTERVAL - 1))) / 8);
    }
    else /* LOW and FULL-speed endpoints */
    {
        /* Sets the data transfer polling interval for low and full
         speed transfers */
        polling_interval = HID_FS_BINTERVAL;
    }

    return ((uint32_t) (polling_interval));
}

void USBD_HID_RecvCallback(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    // send to buffer
    bf_usbhid.add(usbhid_recv);
    memset(usbhid_recv, 0, HID_PACKET_SIZE);
    USBD_LL_PrepareReceive(pdev, HID_EPOUT_ADDR, usbhid_recv, HID_PACKET_SIZE);
}

/* ****************************************************************************************************************** */

USBD_ClassTypeDef USBD_HID =
{
        USBD_HID_Init,
        USBD_HID_DeInit,
        USBD_HID_Setup,
        NULL,               /*EP0_TxSent*/
        NULL,               /*EP0_RxReady*/
        USBD_HID_DataIn,    /*DataIn*/
        USBD_HID_DataOut,   /*DataOut*/
        NULL,               /*SOF */
        NULL,
        NULL,
        USBD_HID_GetCfgDesc,
        USBD_HID_GetCfgDesc,
        USBD_HID_GetCfgDesc,
        USBD_HID_GetDeviceQualifierDesc,
};

/* end of file ****************************************************************************************************** */
