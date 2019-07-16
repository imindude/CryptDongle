/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "globaldef.h"
#include "fidodef.h"
#include "glue.h"
#include "hidif.h"
#include "buffer.h"
#include "u2f.h"
#include "pin.h"
#include "cpr.h"

/* ****************************************************************************************************************** */

#define HIDIF_PACKET_SIZE           64
#define HIDIF_INIT_PAYLOAD_SIZE     (HIDIF_PACKET_SIZE - 7)     // channel_id + command + length
#define HIDIF_CONT_PAYLOAD_SIZE     (HIDIF_PACKET_SIZE - 5)     // channel_id + sequence

#define IS_INIT_PACKET(c)           (((c) & 0x80) == 0x80)
#define IS_CONT_PACKET(c)           (((c) & 0x80) == 0x00)
#define GET_CMD(c)                  ((c) & 0x7F)
#define SET_CMD(c)                  ((c) | 0x80)

#define HIDIF_BUFFER_SIZE           (HIDIF_INIT_PAYLOAD_SIZE + 128 * HIDIF_CONT_PAYLOAD_SIZE)   // 7609
#define HIDIF_MAX_CHANNELS          1

#define KEEPALIVE_INTERVAL_MS       100
#define KEEPALIVE_TIMEOUT_MS        (20 * 1000)
#define WINK_TIMEOUT_MS             (10 * 1000)

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

struct HIDIF_InitPacket
{
    uint8_t     cmd_;
    uint8_t     bcnth_;
    uint8_t     bcntl_;
    uint8_t     payload_[HIDIF_INIT_PAYLOAD_SIZE];
};
typedef struct HIDIF_InitPacket     HIDIF_InitPacket;

struct HIDIF_ContPacket
{
    uint8_t     seq_;
    uint8_t     payload_[HIDIF_CONT_PAYLOAD_SIZE];
};
typedef struct HIDIF_ContPacket     HIDIF_ContPacket;

struct HIDIF_Packet
{
    uint32_t    cid_;
    union
    {
        HIDIF_InitPacket    init_;
        HIDIF_ContPacket    cont_;
    };
};
typedef struct HIDIF_Packet         HIDIF_Packet;

#pragma pack(pop)

struct HIDIF_Channel
{
    uint32_t    cid_;
    uint32_t    used_ms_;
    uint32_t    tout_ms_;
    uint32_t    wink_ms_;
    uint32_t    lock_ms_;

    uint8_t     rxcmd_;
    uint8_t     rxseq_;
    uint16_t    rxlen_;
    uint16_t    rxpos_;

    uint8_t     buffer_[HIDIF_BUFFER_SIZE];
};
typedef struct HIDIF_Channel        HIDIF_Channel;

/* ****************************************************************************************************************** */

static HIDIF_Channel    hidif_channels[HIDIF_MAX_CHANNELS];

/* ****************************************************************************************************************** */

static int8_t find_cid(uint32_t cid)
{
    for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
    {
        if ((hidif_channels[i].cid_ != 0) && (hidif_channels[i].cid_ == cid))
            return i;
    }

    return -1;
}

static int8_t add_cid(uint32_t cid, uint32_t now_ms)
{
    for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
    {
        if (hidif_channels[i].cid_ == 0)
        {
            memset(&hidif_channels[i], 0, sizeof(HIDIF_Channel));
            hidif_channels[i].cid_     = cid;
            hidif_channels[i].used_ms_ = now_ms;

            return i;
        }
    }

    return -1;
}

static int8_t del_cid(uint32_t cid, uint32_t now_ms)
{
    do
    {
        if (cid == 0)
        {
            HIDIF_Channel   *ch = NULL;

            for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
            {
                if (hidif_channels[i].cid_ != 0)
                {
                    if ((ch == NULL) || ((hidif_channels[i].used_ms_ < ch->used_ms_) && (hidif_channels[i].lock_ms_ < now_ms)))
                        ch = &hidif_channels[i];
                }
            }

            if (ch == NULL)
                break;

            cid = ch->cid_;
        }

        for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
        {
            if (hidif_channels[i].cid_ == cid)
            {
                memset(&hidif_channels[i], 0, sizeof(HIDIF_Channel));
                return i;
            }
        }
    }
    while (0);

    return -1;
}

static int8_t ren_cid(uint32_t old_cid, uint32_t new_cid, uint32_t now_ms)
{
    for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
    {
        if (hidif_channels[i].cid_ == old_cid)
        {
            memset(&hidif_channels[i], 0, sizeof(HIDIF_Channel));
            hidif_channels[i].cid_     = new_cid;
            hidif_channels[i].used_ms_ = now_ms;

            return i;
        }
    }

    return -1;
}

static void touch_cid(uint32_t cid, uint32_t now_ms)
{
    for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
    {
        if (hidif_channels[i].cid_ == cid)
        {
            hidif_channels[i].used_ms_ = now_ms;
            break;
        }
    }
}

static void hidif_write(uint32_t cid, uint8_t cmd, uint8_t *dat, uint16_t len)
{
    HIDIF_Packet        packet;
    HIDIF_InitPacket    *init_packet = &packet.init_;
    uint16_t            pos = 0;

    packet.cid_ = cid;

    init_packet->cmd_ = SET_CMD(cmd);
    init_packet->bcnth_ = len >> 8 & 0xFF;
    init_packet->bcntl_ = len & 0xFF;

    for (int8_t i = 0; i < HIDIF_INIT_PAYLOAD_SIZE; i++)
    {
        if (pos < len)
            init_packet->payload_[i] = dat[pos];
        else
            init_packet->payload_[i] = 0;
        pos++;
    }

    usbhid_tx((uint8_t*)&packet, HIDIF_PACKET_SIZE);

    if (pos < len)
    {
        HIDIF_ContPacket    *cont_packet = &packet.cont_;
        uint8_t             seq = 0;

        while (pos < len)
        {
            cont_packet->seq_ = seq++;

            for (int8_t i = 0; i < HIDIF_CONT_PAYLOAD_SIZE; i++)
            {
                if (pos < len)
                    cont_packet->payload_[i] = dat[pos];
                else
                    cont_packet->payload_[i] = 0;
                pos++;
            }

            usbhid_tx((uint8_t*)&packet, HIDIF_PACKET_SIZE);
        }
    }

    ba_hidif.flush();
}

static void process_error(uint32_t cid, uint8_t err_code)
{
    hidif_write(cid, HIDIF_ERROR, &err_code, 1);
}

static void process_ping(HIDIF_Channel *channel, uint32_t now_ms)
{
    ba_hidif.add_bytes(channel->buffer_, channel->rxlen_);
    hidif_write(channel->cid_, HIDIF_PING, ba_hidif.head(), ba_hidif.size());
}

static bool process_msg(HIDIF_Channel *channel, uint32_t now_ms)
{
    bool    keepalive = u2f_request(channel->buffer_, channel->rxlen_, now_ms);

    if (ba_hidif.size() > 0)
        hidif_write(channel->cid_, HIDIF_MSG, ba_hidif.head(), ba_hidif.size());

    return keepalive;
}

static void process_lock(HIDIF_Channel *channel, uint32_t now_ms)
{
    channel->lock_ms_ = now_ms + channel->buffer_[0] * 1000;
    hidif_write(channel->cid_, HIDIF_LOCK, NULL, 0);
}

static void process_init(HIDIF_Channel *channel, uint32_t now_ms)
{
    uint32_t    cid = channel->cid_;

    if (channel->cid_ == HIDIF_BROADCAST_CID)
        rng_get_bytes((uint8_t*)&cid, 4);

    ba_hidif.add_bytes(channel->buffer_, 8);
    ba_hidif.add_bytes((uint8_t*)&cid, 4);
    ba_hidif.add_byte(HIDIF_PROTOCOL_VERSION);
    ba_hidif.add_byte(device_ver.major_);
    ba_hidif.add_byte(device_ver.minor_);
    ba_hidif.add_byte(device_ver.build_ & 0xFF);
    ba_hidif.add_byte(FIDO_CAPABILITIES);

    hidif_write(channel->cid_, HIDIF_INIT, ba_hidif.head(), ba_hidif.size());
    ren_cid(channel->cid_, cid, now_ms);
}

static void process_wink(HIDIF_Channel *channel, uint32_t now_ms)
{
    channel->wink_ms_ = now_ms + WINK_TIMEOUT_MS;
    hidif_write(channel->cid_, HIDIF_WINK, NULL, 0);
}

static bool process_cbor(HIDIF_Channel *channel, uint32_t now_ms)
{
    process_error(channel->cid_, FIDO_ERR_UNSUPPORTED_OPTION);

    return false;
}

static void process_cancel(HIDIF_Channel *channel, uint32_t now_ms)
{
    channel->used_ms_ = now_ms;
    channel->tout_ms_ = 0;
    channel->wink_ms_ = 0;
    channel->lock_ms_ = 0;
}

static bool process_pin(HIDIF_Channel *channel, uint32_t now_ms)
{
    bool    keepalive = pin_request(channel->buffer_, channel->rxlen_, now_ms);

    if (ba_hidif.size() > 0)
        hidif_write(channel->cid_, HIDIF_PIN, ba_hidif.head(), ba_hidif.size());

    return keepalive;
}

static bool process_cipher(HIDIF_Channel *channel, uint32_t now_ms)
{
    bool    keepalive = cpr_request(channel->buffer_, channel->rxlen_, now_ms);

    if (ba_hidif.size() > 0)
        hidif_write(channel->cid_, HIDIF_CIPHER, ba_hidif.head(), ba_hidif.size());

    return keepalive;
}

static bool message_process(HIDIF_Channel *channel, uint32_t now_ms)
{
    bool    keepalive = false;

    switch (channel->rxcmd_)
    {
    case HIDIF_PING:
        process_ping(channel, now_ms);
        break;
    case HIDIF_MSG:
        keepalive = process_msg(channel, now_ms);
        break;
    case HIDIF_LOCK:
        process_lock(channel, now_ms);
        break;
    case HIDIF_INIT:
        process_init(channel, now_ms);
        break;
    case HIDIF_WINK:
        process_wink(channel, now_ms);
        break;
    case HIDIF_CBOR:
        keepalive = process_cbor(channel, now_ms);
        break;
    case HIDIF_CANCEL:
        process_cancel(channel, now_ms);
        break;
    case HIDIF_PIN:
        keepalive = process_pin(channel, now_ms);
        break;
    case HIDIF_CIPHER:
        keepalive = process_cipher(channel, now_ms);
        break;
    default:
        process_error(channel->cid_, FIDO_ERR_INVALID_COMMAND);
        break;
    }

    return keepalive;
}

static bool wink_process(HIDIF_Channel *channel, uint32_t now_ms)
{
    if (channel->wink_ms_ > now_ms)
        return true;

    channel->wink_ms_ = 0;
    return false;
}

static bool keepalive_process(HIDIF_Channel *channel, uint32_t now_ms)
{
    bool    need_keepalive = true;

    if ((now_ms - channel->used_ms_) >= KEEPALIVE_INTERVAL_MS)
    {
        channel->used_ms_ = now_ms;
        if (now_ms >= channel->tout_ms_)
        {
            process_error(channel->cid_, FIDO_ERR_TIMEOUT);
            del_cid(channel->cid_, now_ms);

            need_keepalive = false;
        }
        else
        {
            switch (channel->rxcmd_)
            {
            case HIDIF_MSG:

                if (u2f_keepalive(now_ms))
                {
                    if (ba_hidif.size() > 0)
                        hidif_write(channel->cid_, HIDIF_MSG, ba_hidif.head(), ba_hidif.size());
                    channel->tout_ms_ = 0;

                    need_keepalive = false;
                }
                else
                {
                    ba_hidif.add_byte(KEEPALIVE_TUP_NEEDED);
                    hidif_write(channel->cid_, HIDIF_KEEPALIVE, ba_hidif.head(), ba_hidif.size());
                }

                break;

            case HIDIF_CBOR:

                break;

            case HIDIF_PIN:

                break;

            case HIDIF_CIPHER:

                break;

            default:

                break;
            }
        }
    }

    return need_keepalive;
}

DeviceState hidif_process(uint32_t now_ms)
{
    HIDIF_Packet    packet;
    DeviceState     device_state = _DeviceState_Idle;
    bool            message_ready = false;
    HIDIF_Channel   *channel = NULL;

    do
    {
        if (usbhid_rx((uint8_t*)&packet, HIDIF_PACKET_SIZE) > 0)
        {
            if (packet.cid_ == 0)
                break;

            int8_t  id = find_cid(packet.cid_);

            if (id == -1)
            {
                if ((id = add_cid(packet.cid_, now_ms)) == -1)
                {
                    if ((del_cid(0, now_ms) == -1) || ((id = add_cid(packet.cid_, now_ms)) == -1))
                    {
                        process_error(packet.cid_, FIDO_ERR_OTHER);
                        break;
                    }
                }
            }

            channel = &hidif_channels[id];

            if (channel->rxpos_ == 0)
            {
                if (IS_INIT_PACKET(packet.init_.cmd_))
                {
                    HIDIF_InitPacket    *init_packet = &packet.init_;
                    uint16_t            len = init_packet->bcnth_ << 8 | init_packet->bcntl_;

                    channel->rxcmd_ = GET_CMD(init_packet->cmd_);
                    channel->rxseq_ = 0;
                    channel->rxlen_ = len;

                    if (len > HIDIF_INIT_PAYLOAD_SIZE)
                        len = HIDIF_INIT_PAYLOAD_SIZE;
                    memcpy(channel->buffer_, init_packet->payload_, HIDIF_INIT_PAYLOAD_SIZE);
                    channel->rxpos_ = len;

                    if (channel->rxpos_ == channel->rxlen_)
                    {
                        message_ready = true;
                        break;
                    }
                }
                else
                {
                    process_error(channel->cid_, FIDO_ERR_INVALID_PARAMETER);
                    break;
                }
            }
            else
            {
                if (IS_CONT_PACKET(packet.cont_.seq_))
                {
                    HIDIF_ContPacket    *cont_packet = &packet.cont_;
                    uint16_t            len = channel->rxpos_ + HIDIF_CONT_PAYLOAD_SIZE;

                    if (cont_packet->seq_ != channel->rxseq_)
                    {
                        process_error(channel->cid_, FIDO_ERR_INVALID_SEQ);
                        break;
                    }

                    if (len > channel->rxlen_)
                        len = channel->rxlen_;
                    memcpy(channel->buffer_ + channel->rxpos_, cont_packet->payload_, HIDIF_CONT_PAYLOAD_SIZE);
                    channel->rxpos_ = len;

                    if (channel->rxpos_ == channel->rxlen_)
                    {
                        message_ready = true;
                        break;
                    }

                    touch_cid(channel->cid_, now_ms);
                    channel->rxseq_++;
                }
                else
                {
                    process_error(channel->cid_, FIDO_ERR_INVALID_PARAMETER);
                    break;
                }
            }
        }
    }
    while (0);

    if (message_ready)
    {
        if (message_process(channel, now_ms))
            channel->tout_ms_ = now_ms + KEEPALIVE_TIMEOUT_MS;
        else
            channel->tout_ms_ = 0;

        channel->rxpos_ = 0;
    }

    for (int8_t i = 0; i < HIDIF_MAX_CHANNELS; i++)
    {
        channel = &hidif_channels[i];

        if (channel->cid_ != 0)
        {
            if ((channel->wink_ms_ != now_ms) && wink_process(channel, now_ms))
                device_state = _DeviceState_Wink;

            if ((channel->tout_ms_ != 0) && keepalive_process(channel, now_ms))
                device_state = _DeviceState_Busy;
        }
    }

    return device_state;
}

/* end of file ****************************************************************************************************** */
