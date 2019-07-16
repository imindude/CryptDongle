/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "globaldef.h"
#include "fidodef.h"
#include "u2f.h"
#include "buffer.h"
#include "glue.h"
#include "storage.h"
#include "misc.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"

/* ****************************************************************************************************************** */

#define CHAL_PARAM_LEN      32
#define APPL_PARAM_LEN      32

#define U2F_KEY_LEN         32
#define U2F_TAG_LEN         32

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

struct U2F_Request
{
    uint8_t     cla_;
    uint8_t     ins_;
    uint8_t     p1_;
    uint8_t     p2_;
    uint8_t     dat_[1];
};
typedef struct U2F_Request      U2F_Request;

#pragma pack(pop)

/* ****************************************************************************************************************** */

struct U2F_Key
{
    uint8_t     key_[U2F_KEY_LEN];
    uint8_t     tag_[U2F_TAG_LEN];
};
typedef struct U2F_Key          U2F_Key;

struct U2F_Keepalive
{
    enum
    {
        _KA_None,
        _KA_Registration,
        _KA_Authentication
    }
    type_;

    uint8_t     chal_param_[CHAL_PARAM_LEN];
    uint8_t     appl_param_[APPL_PARAM_LEN];
    U2F_Key     key_handle_;
};
typedef struct U2F_Keepalive    U2F_Keepalive;

/* ****************************************************************************************************************** */

static U2F_Keepalive    keepalive_data;

/* ****************************************************************************************************************** */

static void add_sw(uint16_t sw)
{
    ba_hidif.add_byte(sw >> 8 & 0xFF);
    ba_hidif.add_byte(sw & 0xFF);
}

static void make_u2f_key_tag(uint8_t *appl_param, U2F_Key *u2f_key)
{
    mbedtls_md_context_t    md_ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, appl_param, APPL_PARAM_LEN);
    mbedtls_md_hmac_update(&md_ctx, device_uid, DEV_UID_LEN);
    mbedtls_md_hmac_update(&md_ctx, u2f_key->key_, U2F_KEY_LEN);
    mbedtls_md_hmac_finish(&md_ctx, u2f_key->tag_);
    mbedtls_md_free(&md_ctx);
}

static void make_key_pair(uint8_t *appl_param, U2F_Key *u2f_key, uint8_t *pri_key, uint8_t *pub_key)
{
    union
    {
        uint8_t     pub_key_[ECC_PUB_KEY_SIZE];
        uint8_t     pri_key_[ECC_PRI_KEY_SIZE];
        uint8_t     sha_hash_[MBEDTLS_MD_MAX_SIZE];
    } hash;
    mbedtls_md_context_t        md_ctx;
    const mbedtls_md_info_t     *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, device_uid, DEV_UID_LEN);
    mbedtls_md_hmac_update(&md_ctx, u2f_key->key_, U2F_KEY_LEN);
    mbedtls_md_hmac_update(&md_ctx, u2f_key->tag_, U2F_KEY_LEN);
    mbedtls_md_hmac_update(&md_ctx, appl_param, APPL_PARAM_LEN);
    mbedtls_md_hmac_finish(&md_ctx, hash.sha_hash_);
    mbedtls_md_free(&md_ctx);

    if (pri_key)
        memcpy(pri_key, hash.pri_key_, ECC_PRI_KEY_SIZE);

    if (pub_key)
    {
        mbedtls_ecdsa_context       ecdsa_ctx;
        size_t                      len;

        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
        mbedtls_mpi_read_binary(&ecdsa_ctx.d, hash.pri_key_, ECC_PRI_KEY_SIZE);
        mbedtls_ecp_mul(&ecdsa_ctx.grp, &ecdsa_ctx.Q, &ecdsa_ctx.d, &ecdsa_ctx.grp.G, mbedtls_if_rng, NULL);
        mbedtls_ecp_point_write_binary(&ecdsa_ctx.grp, &ecdsa_ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, hash.pub_key_, ECC_PUB_KEY_SIZE);
        mbedtls_ecdsa_free(&ecdsa_ctx);

        memcpy(pub_key, hash.pub_key_, ECC_PUB_KEY_SIZE);
    }
}

static bool param_parser(uint8_t *dat, uint8_t *chal_param, uint8_t *appl_param, U2F_Key *u2f_key)
{
    uint16_t    pos;
    uint16_t    len;

    if (dat[0] > 0)     // short encoding
    {
        pos = 1;
        len = dat[0];
    }
    else                // extended length encoding (0|MSB|LSB)
    {
        pos = 3;
        len = dat[1] << 8 | dat[2];
    }

    if (len >= (CHAL_PARAM_LEN + APPL_PARAM_LEN))
    {
        memcpy(chal_param, &dat[pos], CHAL_PARAM_LEN);
        pos += CHAL_PARAM_LEN;
        memcpy(appl_param, &dat[pos], APPL_PARAM_LEN);
        pos += APPL_PARAM_LEN;

        if (u2f_key && (len > pos) && (dat[pos] == (CHAL_PARAM_LEN + APPL_PARAM_LEN)))
        {
            pos++;
            memcpy(u2f_key->key_, &dat[pos], U2F_KEY_LEN);
            pos += U2F_KEY_LEN;
            memcpy(u2f_key->tag_, &dat[pos], U2F_TAG_LEN);
            pos += U2F_TAG_LEN;
        }
    }
    else
    {
        pos = 0;
    }

    return pos > 0 ? true : false;
}

static bool registration(uint8_t *dat)
{
    if (param_parser(dat, keepalive_data.chal_param_, keepalive_data.appl_param_, NULL))
    {
        keepalive_data.type_ = _KA_Registration;
        return true;
    }

    memset(&keepalive_data, 0, sizeof(U2F_Keepalive));
    add_sw(SW_WRONG_DATA);
    return false;
}

static void lease_registration(uint32_t now_ms)
{
    U2F_Key     u2f_key;
    uint8_t     pub_key[ECC_PUB_KEY_SIZE];
    uint8_t     byte;

    memset(&u2f_key, 0, sizeof(U2F_Key));
    memset(pub_key, 0, ECC_PUB_KEY_SIZE);

    /**
     * U2F key & key pair
     */

    rng_get_bytes(u2f_key.key_, U2F_KEY_LEN);
    make_u2f_key_tag(keepalive_data.appl_param_, &u2f_key);
    make_key_pair(keepalive_data.appl_param_, &u2f_key, NULL, pub_key);

    /**
     * HASH
     */

    mbedtls_md_context_t    md_ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t     hash[HASH_SIZE];

    memset(hash, 0, HASH_SIZE);

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    byte = 0;       // reserved
    mbedtls_md_update(&md_ctx, &byte, 1);
    mbedtls_md_update(&md_ctx, keepalive_data.appl_param_, APPL_PARAM_LEN);
    mbedtls_md_update(&md_ctx, keepalive_data.chal_param_, CHAL_PARAM_LEN);
    mbedtls_md_update(&md_ctx, u2f_key.key_, U2F_KEY_LEN);
    mbedtls_md_update(&md_ctx, u2f_key.tag_, U2F_TAG_LEN);
    mbedtls_md_update(&md_ctx, pub_key, ECC_PUB_KEY_SIZE);  // ECC public key of uncompressed form (RFC5480 section-2.2)

    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    /**
     * Attestation
     */

    mbedtls_pk_context  pk_ctx;
    uint8_t     sign[SIGN_DER_MAX_SIZE];
    size_t      len;

    memset(sign, 0, SIGN_DER_MAX_SIZE);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, fido_private_key, fido_private_key_size, NULL, 0);
    mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, hash, HASH_SIZE, sign, &len, mbedtls_if_rng, NULL);
    mbedtls_pk_free(&pk_ctx);

    /**
     * Make response
     */

    ba_hidif.add_byte(0x05);                        // reserved
    ba_hidif.add_bytes(pub_key, ECC_PUB_KEY_SIZE);  // ECC public key of uncompressed form (RFC5480 section-2.2)
    ba_hidif.add_byte(sizeof(U2F_Key));
    ba_hidif.add_bytes(u2f_key.key_, U2F_KEY_LEN);
    ba_hidif.add_bytes(u2f_key.tag_, U2F_TAG_LEN);
    ba_hidif.add_bytes((uint8_t*)fido_certificate, fido_certificate_size);
    ba_hidif.add_bytes(sign, len);
    add_sw(SW_NO_ERROR);
}

static bool authentication(uint8_t *dat)
{
    if (param_parser(dat, keepalive_data.chal_param_, keepalive_data.appl_param_, &keepalive_data.key_handle_))
    {
        U2F_Key     u2f_key;

        memset(&u2f_key, 0, sizeof(U2F_Key));
        memcpy(u2f_key.key_, keepalive_data.key_handle_.key_, U2F_KEY_LEN);
        make_u2f_key_tag(keepalive_data.appl_param_, &u2f_key);

        if (memcmp(keepalive_data.key_handle_.tag_, u2f_key.tag_, U2F_TAG_LEN) == 0)
        {
            keepalive_data.type_ = _KA_Authentication;
            return true;
        }
    }

    add_sw(SW_WRONG_DATA);

    return false;
}

static void lease_authentication(uint32_t now_ms)
{
    uint8_t     pri_key[ECC_PRI_KEY_SIZE];
    uint32_t    count = storage_dev_count();    // authentication count
    uint8_t     count_array[4];
    uint8_t     user_present = 1;               // user present value (always 1 -> my condition)

    memset(pri_key, 0, ECC_PRI_KEY_SIZE);

    count_array[0] = count >> 24 & 0xFF;
    count_array[1] = count >> 16 & 0xFF;
    count_array[2] = count >>  8 & 0xFF;
    count_array[3] = count >>  0 & 0xFF;

    /**
     * HASH
     */

    mbedtls_md_context_t    md_ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t     hash[HASH_SIZE];

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    mbedtls_md_update(&md_ctx, keepalive_data.appl_param_, APPL_PARAM_LEN);
    mbedtls_md_update(&md_ctx, &user_present, 1);
    mbedtls_md_update(&md_ctx, count_array, 4);
    mbedtls_md_update(&md_ctx, keepalive_data.chal_param_, CHAL_PARAM_LEN);

    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    /**
     * Key generation
     */

    make_key_pair(keepalive_data.appl_param_, &keepalive_data.key_handle_, pri_key, NULL);

    /**
     * Sign
     */

    mbedtls_ecdsa_context   ecdsa_ctx;
    uint8_t     sign[SIGN_DER_MAX_SIZE];
    size_t      len;

    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecdsa_ctx.d, pri_key, ECC_PRI_KEY_SIZE);
    mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256, hash, mbedtls_md_get_size(md_info), sign, &len,
            mbedtls_if_rng, NULL);
    mbedtls_ecdsa_free(&ecdsa_ctx);

    ba_hidif.add_byte(user_present);
    ba_hidif.add_bytes(count_array, 4);
    ba_hidif.add_bytes(sign, len);
    add_sw(SW_NO_ERROR);
}

static uint16_t check_registration(uint8_t *dat)
{
    uint8_t     chal_param[CHAL_PARAM_LEN];
    uint8_t     appl_param[APPL_PARAM_LEN];
    U2F_Key     u2f_key;
    uint16_t    sw = SW_WRONG_DATA;

    if (param_parser(dat, chal_param, appl_param, &u2f_key))
    {
        U2F_Key     u2f_tmp;

        memset(&u2f_tmp, 0, sizeof(U2F_Key));
        memcpy(u2f_tmp.key_, u2f_key.key_, U2F_KEY_LEN);
        make_u2f_key_tag(appl_param, &u2f_tmp);

        if (memcmp(u2f_key.tag_, u2f_tmp.tag_, U2F_TAG_LEN) == 0)
            sw = SW_CONDITINOS_NOT_SATISFIED;
    }

    return sw;
}

static bool u2f_register(U2F_Request *req, uint16_t len, uint32_t now_ms)
{
    bool    keepalive = false;

    switch (req->p1_)
    {
    case 0:
    case ENFORCE_USER_PRESENCE_AND_SIGN:
    case DONT_ENFORCE_USER_PRESENCE_AND_SIGN:
        keepalive = registration(req->dat_);
        break;
    default:
        add_sw(SW_WRONG_DATA);
        break;
    }

    return keepalive;
}

static bool u2f_authenticate(U2F_Request *req, uint16_t len, uint32_t now_ms)
{
    bool    keepalive = false;

    switch (req->p1_)
    {
    case CHECK_ONLY:
        add_sw(check_registration(req->dat_));
        break;
    case ENFORCE_USER_PRESENCE_AND_SIGN:
    case DONT_ENFORCE_USER_PRESENCE_AND_SIGN:
        keepalive = authentication(req->dat_);
        break;
    default:
        add_sw(SW_WRONG_DATA);
        break;
    }

    return keepalive;
}

static void u2f_version(U2F_Request *req, uint16_t len, uint32_t now_ms)
{
    if ((req->p1_ == 0) && (req->p2_ == 0))
    {
        ba_hidif.add_bytes((uint8_t*)U2F_VERSION_STR, strlen(U2F_VERSION_STR));
        add_sw(SW_NO_ERROR);
    }
    else
    {
        add_sw(SW_WRONG_DATA);
    }
}

bool u2f_request(uint8_t *msg, uint16_t len, uint32_t now_ms)
{
    bool        keepalive = false;
    U2F_Request *req = (U2F_Request*)msg;

    if (req->cla_ == 0)
    {
        switch (req->ins_)
        {
        case U2F_REGISTER:
            keepalive = u2f_register(req, len, now_ms);
            break;
        case U2F_AUTHENTICATE:
            keepalive = u2f_authenticate(req, len, now_ms);
            break;
        case U2F_VERSION:
            u2f_version(req, len, now_ms);
            break;
        default:
            add_sw(SW_INS_NOT_SUPPORTED);
            break;
        }
    }
    else
    {
        add_sw(SW_CLA_NOT_SUPPORTED);
    }

    return keepalive;
}

bool u2f_keepalive(uint32_t now_ms)
{
    if (button_pushed())
    {
        if (keepalive_data.type_ == _KA_Registration)
            lease_registration(now_ms);
        else if (keepalive_data.type_ == _KA_Authentication)
            lease_authentication(now_ms);

        memset(&keepalive_data, 0, sizeof(U2F_Keepalive));
        return true;
    }

    return false;
}

/* end of file ****************************************************************************************************** */
