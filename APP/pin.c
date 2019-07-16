/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "customdef.h"
#include "pin.h"
#include "glue.h"
#include "buffer.h"
#include "storage.h"

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

struct PIN_Request
{
    uint8_t     cla_;
    uint8_t     ins_;
    uint8_t     p1_;
    uint8_t     p2_;
    uint8_t     dat_[1];
};
typedef struct PIN_Request      PIN_Request;

#pragma pack(pop)

/* ****************************************************************************************************************** */

struct PIN_Keepalive
{
    enum
    {
        _KA_None,
        _KA_GetPin,
        _KA_SetPin_Check,
        _KA_SetPin_Update
    }
    type_;

    enum
    {
        _STA_Idle,
        _STA_Push,
        _STA_Pull
    }
    state_;

    uint8_t     pin_[DEV_PIN_LEN];
    uint8_t     idx_;
    uint32_t    last_ms_;
};
typedef struct PIN_Keepalive    PIN_Keepalive;

/* ****************************************************************************************************************** */

static PIN_Keepalive    keepalive_data;

/* ****************************************************************************************************************** */

static void add_sw(uint16_t sw)
{
    ba_hidif.add_byte(sw >> 8 & 0xFF);
    ba_hidif.add_byte(sw & 0xFF);
}

static bool pin_getter(PIN_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_None)
        memset(&keepalive_data, 0, sizeof(PIN_Keepalive));

    uint8_t     pin[DEV_PIN_LEN];

    if (storage_dev_read(NULL, pin))
    {
        if ((pin[0] == PIN_NONE) || (pin[0] != PIN_BEEP) || (pin[0] != PIN_BEEEEP))
        {
            add_sw(PIN_SW_NOT_SATISFIED);
            return false;
        }

        keepalive_data.type_  = _KA_GetPin;
        keepalive_data.state_ = _STA_Idle;

        return true;
    }

    add_sw(PIN_SW_ERR_OTHER);

    return false;
}

static uint16_t process_pin_check(uint32_t now_ms)
{
    uint16_t    sw = 0;
    uint32_t    dt = now_ms - keepalive_data.last_ms_;
    bool        pushed = button_pushed();

    switch (keepalive_data.state_)
    {
    case _STA_Idle:

        if (pushed)
        {
            keepalive_data.state_   = _STA_Push;
            keepalive_data.last_ms_ = now_ms;
        }

        break;

    case _STA_Push:

        if (pushed)
        {
            if (dt > PIN_BEEEEP_MS)
                sw = PIN_SW_TIMEOUT;
        }
        else
        {
            if (dt > PIN_BEEP_MS)
                keepalive_data.pin_[keepalive_data.idx_++] = PIN_BEEEEP;
            else
                keepalive_data.pin_[keepalive_data.idx_++] = PIN_BEEP;

            keepalive_data.state_   = _STA_Pull;
            keepalive_data.last_ms_ = now_ms;
        }

        break;

    case _STA_Pull:

        if (pushed)
        {
            keepalive_data.state_   = _STA_Pull;
            keepalive_data.last_ms_ = now_ms;
        }
        else
        {
            if (dt > PIN_BEEEEP_MS)
            {
                if (keepalive_data.idx_ < PIN_MIN_LEN)
                    sw = PIN_SW_TIMEOUT;
                else
                    sw = PIN_SW_NO_ERROR;
            }
        }

        break;
    }

    return sw;
}

static bool lease_pin_getter(uint32_t now_ms)
{
    uint16_t    sw = process_pin_check(now_ms);

    if (sw == PIN_SW_NO_ERROR)
    {
        uint8_t     pin[DEV_PIN_LEN];

        if (storage_dev_read(NULL, pin) && (memcmp(keepalive_data.pin_, pin, DEV_PIN_LEN) == 0))
            add_sw(PIN_SW_CONFIRM);
        else
            add_sw(PIN_SW_VERIFY_FAILED);

        return false;
    }
    else if (sw != 0)
    {
        add_sw(sw);

        return false;
    }

    return true;
}

static bool pin_setter(PIN_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_None)
        memset(&keepalive_data, 0, sizeof(PIN_Keepalive));

    uint8_t     pin[DEV_PIN_LEN];

    if (storage_dev_read(NULL, pin))
    {
        if ((pin[0] == PIN_NONE) || (pin[0] != PIN_BEEP) || (pin[0] != PIN_BEEEEP))
            keepalive_data.type_  = _KA_SetPin_Update;
        else
            keepalive_data.type_  = _KA_SetPin_Check;
        keepalive_data.state_ = _STA_Idle;

        return true;
    }

    add_sw(PIN_SW_ERR_OTHER);

    return false;
}

static bool lease_pin_setter(uint32_t now_ms)
{
    bool        keepalive = true;
    uint16_t    sw = process_pin_check(now_ms);

    switch (keepalive_data.type_)
    {
    case _KA_SetPin_Check:

        if (sw == PIN_SW_NO_ERROR)
        {
            uint8_t     pin[DEV_PIN_LEN];

            if (storage_dev_read(NULL, pin) && (memcmp(keepalive_data.pin_, pin, DEV_PIN_LEN) == 0))
            {
                memset(&keepalive_data, 0, sizeof(PIN_Keepalive));

                keepalive_data.type_  = _KA_SetPin_Update;
                keepalive_data.state_ = _STA_Idle;

                add_sw(PIN_SW_CONFIRM);
            }
            else
            {
                memset(&keepalive_data, 0, sizeof(PIN_Keepalive));
                add_sw(PIN_SW_VERIFY_FAILED);
                keepalive = false;
            }
        }
        else if (sw != 0)
        {
            add_sw(sw);
            keepalive = false;
        }

        break;

    case _KA_SetPin_Update:

        if (sw == PIN_SW_NO_ERROR)
        {
            if (storage_dev_write(NULL, keepalive_data.pin_))
                add_sw(PIN_SW_NO_ERROR);
            else
                add_sw(PIN_SW_ERR_OTHER);

            memset(&keepalive_data, 0, sizeof(PIN_Keepalive));
            keepalive = false;
        }
        else if (sw != 0)
        {
            add_sw(sw);
            keepalive = false;
        }

        break;

    default:

        add_sw(PIN_SW_ERR_OTHER);
        keepalive = false;

        break;
    }

    return keepalive;
}

bool pin_request(uint8_t *msg, uint16_t len, uint32_t now_ms)
{
    bool        keepalive = false;
    PIN_Request *req = (PIN_Request*)msg;

    if (req->cla_ == PIN_CLASS)
    {
        switch (req->ins_)
        {
        case PIN_GETTER:
            keepalive = pin_getter(req, len, now_ms);
            break;
        case PIN_SETTER:
            keepalive = pin_setter(req, len, now_ms);
            break;
        default:
            add_sw(CIPHER_SW_INVALID_INS);
            break;
        }
    }
    else
    {
        add_sw(CIPHER_SW_INVALID_CLA);
    }

    return keepalive;
}

bool pin_keepalive(uint32_t now_ms)
{
    bool    keepalive = false;

    switch (keepalive_data.type_)
    {
    case _KA_GetPin:
        keepalive = lease_pin_getter(now_ms);
        break;
    case _KA_SetPin_Check:
    case _KA_SetPin_Update:
        keepalive = lease_pin_setter(now_ms);
        break;
    default:
       break;
    }

    return keepalive;
}

/* end of file ****************************************************************************************************** */
