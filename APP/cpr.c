/**
 * *********************************************************************************************************************
 * @author      imindude@gmail.com
 * *********************************************************************************************************************
 */

#include "globaldef.h"
#include "customdef.h"
#include "cpr.h"
#include "buffer.h"
#include "glue.h"
#include "storage.h"
#include "misc.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/cipher.h"

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

struct CPR_Request
{
    uint8_t     cla_;
    uint8_t     ins_;
    uint8_t     p1_;
    uint8_t     p2_;
    uint8_t     dat_[1];
};
typedef struct CPR_Request      CPR_Request;

#pragma pack(pop)

/* ****************************************************************************************************************** */

#define BLOB_SIZE       2048

struct CPR_Encryption
{
    mbedtls_md_context_t        md_ctx_;
    mbedtls_cipher_context_t    cr_ctx_;
    uint8_t     seed_[CIPHER_SEED_SIZE];
    uint8_t     md_[CIPHER_MD_SIZE];
};
typedef struct CPR_Encryption   CPR_Encryption;

struct CPR_Keepalive
{
    enum
    {
        _KA_None,
        _KA_EncryptionSet,
        _KA_EncryptionGet
    }
    type_;

    CPR_Encryption  encryption_;
};
typedef struct CPR_Keepalive    CPR_Keepalive;

/* ****************************************************************************************************************** */

static CPR_Keepalive    keepalive_data;

/* ****************************************************************************************************************** */

static void add_sw(uint16_t sw)
{
    ba_hidif.add_byte(sw >> 8 & 0xFF);
    ba_hidif.add_byte(sw & 0xFF);
}

static bool check_checksum(uint16_t checksum, uint8_t *dat, uint16_t dat_len)
{
    return (get_crc16_ccitt(CIPHER_MAGIC_WORD & 0xFFFF, dat, dat_len) == checksum) ? true : false;
}

static uint16_t make_checksum(uint8_t *dat, uint16_t dat_len)
{
    return get_crc16_ccitt(CIPHER_MAGIC_WORD & 0xFFFF, dat, dat_len);
}

static uint16_t load_public_key(uint8_t *pub_key, uint16_t pub_len)
{
    mbedtls_pk_context      pk_ctx;
    uint8_t     key_buf[storage_key_size() + 1];
    uint16_t    key_len = 0;

    mbedtls_pk_init(&pk_ctx);

    do
    {
        if (storage_key_read(key_buf, &key_len) == false)
            break;

        if (mbedtls_pk_parse_key(&pk_ctx, key_buf, key_len, NULL, 0) != 0)
            break;
        if (mbedtls_pk_write_pubkey_pem(&pk_ctx, pub_key, pub_len) != 0)
            break;

        key_len = strlen((char*)pub_key);
        pub_key[key_len++] = '\0';
    }
    while (0);

    mbedtls_pk_free(&pk_ctx);

    return key_len;
}

static bool make_block_key(uint8_t *seed, uint8_t *iv, uint8_t *key, bool new_seed)
{
    mbedtls_md_context_t    md_ctx;
    bool        res = false;
    uint8_t     buffer[BLOB_SIZE];
    uint16_t    length;

    mbedtls_md_init(&md_ctx);

    do
    {
        if ((length = load_public_key(buffer, BLOB_SIZE)) == 0)
            break;

        /**
         * seed / iv / key
         */

        if (new_seed)
            rng_get_bytes(seed, CIPHER_SEED_SIZE);

        uint16_t    crc = CIPHER_MAGIC_WORD >> 16 & 0xFFFF;

        crc = get_crc16_ccitt(crc, seed, CIPHER_SEED_SIZE);
        crc = get_crc16_ccitt(crc, buffer, length);

        for (int8_t i = 0; i < CIPHER_BLOCK_IV_SIZE; i++)
        {
            int8_t  xor_len = CIPHER_SEED_SIZE / CIPHER_BLOCK_IV_SIZE;

            iv[i] = (i & 1) ? (crc >> 8 & 0xFF) : (crc & 0xFF);

            for (int8_t k = 0; k < xor_len; k++)
                iv[i] ^= seed[i * xor_len + k];
        }

        if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0)
            break;
        if (mbedtls_md_hmac_starts(&md_ctx, seed, CIPHER_SEED_SIZE) != 0)
            break;
        if (mbedtls_md_hmac_update(&md_ctx, buffer, length) != 0)
            break;

        buffer[0] = 0x55;
        buffer[1] = length >> 8 & 0xFF;
        buffer[2] = length >> 0 & 0xFF;
        buffer[3] = CIPHER_MAGIC_WORD >> 8 & 0xFF;
        buffer[4] = CIPHER_MAGIC_WORD >> 0 & 0xFF;
        buffer[5] = 0xAA;
        buffer[6] = crc >> 8 & 0xFF;
        buffer[7] = crc >> 0 & 0xFF;

        if (mbedtls_md_hmac_update(&md_ctx, buffer, 8) != 0)
            break;
        if (mbedtls_md_hmac_update(&md_ctx, iv, CIPHER_BLOCK_IV_SIZE) != 0)
            break;
        if (mbedtls_md_hmac_finish(&md_ctx, key) != 0)
            break;

        res = true;
    }
    while (0);

    mbedtls_md_free(&md_ctx);

    return res;
}

static void reset_keepalive(void)
{
    switch (keepalive_data.type_)
    {
    case _KA_EncryptionSet:
    case _KA_EncryptionGet:
        mbedtls_md_free(&keepalive_data.encryption_.md_ctx_);
        mbedtls_cipher_free(&keepalive_data.encryption_.cr_ctx_);
        break;
    default:
        break;
    }

    keepalive_data.type_ = _KA_None;
}

static void cpr_version(CPR_Request *req, uint16_t len)
{
    uint8_t     magic_word[4];

    magic_word[0] = CIPHER_MAGIC_WORD >> 24 & 0xFF;
    magic_word[1] = CIPHER_MAGIC_WORD >> 16 & 0xFF;
    magic_word[2] = CIPHER_MAGIC_WORD >>  8 & 0xFF;
    magic_word[3] = CIPHER_MAGIC_WORD >>  0 & 0xFF;

    ba_hidif.add_bytes(magic_word, 4);
    ba_hidif.add_byte(device_ver.major_);
    ba_hidif.add_byte(device_ver.minor_);
    ba_hidif.add_byte(device_ver.build_ >> 24 & 0xFF);
    ba_hidif.add_byte(device_ver.build_ >> 16 & 0xFF);
    ba_hidif.add_byte(device_ver.build_ >>  8 & 0xFF);
    ba_hidif.add_byte(device_ver.build_ >>  0 & 0xFF);
    add_sw(CIPHER_SW_NO_ERROR);
}

static void cpr_key_set(CPR_Request *req, uint16_t len)
{
    /**
     * Always extended length encoding (0|MSB|LSB)
     */
    uint16_t    key_len = req->dat_[1] << 8 | req->dat_[2];
    uint16_t    key_crc = req->dat_[3] << 8 | req->dat_[4];
    uint8_t     *key_buf = &req->dat_[5];

    if ((req->dat_[0] != 0) || (check_checksum(key_crc, key_buf, key_len) == false))
    {
        add_sw(CIPHER_SW_WRONG_DATA);
        return;
    }

    mbedtls_pk_context  pk_ctx;
    uint8_t     buffer[BLOB_SIZE];
    bool        res = false;

    mbedtls_pk_init(&pk_ctx);

    do
    {
        key_buf[key_len++] = '\0';

        if (mbedtls_pk_parse_key(&pk_ctx, key_buf, key_len, NULL, 0) != 0)
            break;

        if (mbedtls_pk_write_key_pem(&pk_ctx, buffer, BLOB_SIZE) != 0)
            break;
        if (mbedtls_pk_write_pubkey_pem(&pk_ctx, buffer, BLOB_SIZE) != 0)
            break;

        if (storage_key_write(key_buf, key_len) == false)
            break;

        add_sw(CIPHER_SW_NO_ERROR);

        res = true;
    }
    while (0);

    if (res == false)
        add_sw(CIPHER_SW_ERR_OTHER);

    mbedtls_pk_free(&pk_ctx);
}

static void cpr_key_get(CPR_Request *req, uint16_t len)
{
    uint8_t     pub_key[BLOB_SIZE];
    uint16_t    pub_len;

    if ((pub_len = load_public_key(pub_key, BLOB_SIZE)) > 0)
    {
        uint16_t    key_crc = make_checksum(pub_key, pub_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */
        ba_hidif.add_byte(0);
        ba_hidif.add_byte(pub_len >> 8 & 0xFF);
        ba_hidif.add_byte(pub_len >> 0 & 0xFF);
        ba_hidif.add_byte(key_crc >> 8 & 0xFF);
        ba_hidif.add_byte(key_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(pub_key, pub_len);
        add_sw(CIPHER_SW_NO_ERROR);
    }
    else
    {
        add_sw(CIPHER_SW_ERR_OTHER);
    }
}

static bool cpr_encryption_init(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (storage_key_size() == 0)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    if (keepalive_data.type_ != _KA_None)
        reset_keepalive();

    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;
    uint8_t     *seed = keepalive_data.encryption_.seed_;
    uint8_t     iv[CIPHER_BLOCK_IV_SIZE];
    uint8_t     key[CIPHER_BLOCK_KEY_SIZE];

    mbedtls_md_init(md_ctx);
    mbedtls_cipher_init(cr_ctx);

    do
    {
        if (make_block_key(seed, iv, key, true) == false)
            break;

        if (mbedtls_md_setup(md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0)
            break;
        if (mbedtls_md_hmac_starts(md_ctx, key, CIPHER_BLOCK_KEY_SIZE) != 0)
            break;

        if (mbedtls_cipher_setup(cr_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)) != 0)
            break;
        if (mbedtls_cipher_setkey(cr_ctx, key, CIPHER_BLOCK_KEY_SIZE * 8, MBEDTLS_ENCRYPT) != 0)
            break;
        if (mbedtls_cipher_set_iv(cr_ctx, iv, CIPHER_BLOCK_IV_SIZE) != 0)
            break;
        if (mbedtls_cipher_reset(cr_ctx) != 0)
            break;

        keepalive_data.type_ = _KA_EncryptionSet;

        add_sw(CIPHER_SW_NO_ERROR);

        return true;
    }
    while (0);

    add_sw(CIPHER_SW_ERR_OTHER);
    reset_keepalive();

    return false;
}

static bool cpr_encryption_do(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_EncryptionSet)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    /**
     * Always extended length encoding (0|MSB|LSB)
     */
    uint16_t    block_len = req->dat_[1] << 8 | req->dat_[2];
    uint16_t    block_crc = req->dat_[3] << 8 | req->dat_[4];
    uint8_t     *block_buf = &req->dat_[5];

    if ((req->dat_[0] != 0) || (check_checksum(block_crc, block_buf, block_len) == false))
    {
        add_sw(CIPHER_SW_WRONG_DATA);
        return true;
    }

    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;

    do
    {
        size_t  enc_len;
        uint8_t enc_buf[CIPHER_BLOCK_SIZE];

        if (mbedtls_md_hmac_update(md_ctx, block_buf, block_len) != 0)
            break;

        if (mbedtls_cipher_update(cr_ctx, block_buf, block_len, enc_buf, &enc_len) != 0)
            break;

        uint16_t    enc_crc = make_checksum(enc_buf, enc_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */
        ba_hidif.add_byte(0);
        ba_hidif.add_byte(enc_len >> 8 & 0xFF);
        ba_hidif.add_byte(enc_len >> 0 & 0xFF);
        ba_hidif.add_byte(enc_crc >> 8 & 0xFF);
        ba_hidif.add_byte(enc_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(enc_buf, enc_len);
        add_sw(CIPHER_SW_NO_ERROR);

        return true;
    }
    while (0);

    add_sw(CIPHER_SW_ERR_OTHER);
    reset_keepalive();

    return false;
}

static bool cpr_encryption_done(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_EncryptionSet)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;
    uint8_t     *md = keepalive_data.encryption_.md_;

    do
    {
        size_t  fin_len;
        uint8_t fin_buf[CIPHER_BLOCK_SIZE];

        if (mbedtls_md_hmac_finish(md_ctx, md) != 0)
            break;

        if (mbedtls_cipher_finish(cr_ctx, fin_buf, &fin_len) != 0)
            break;

        uint16_t    fin_crc = make_checksum(fin_buf, fin_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */
        ba_hidif.add_byte(0);
        ba_hidif.add_byte(fin_len >> 8 & 0xFF);
        ba_hidif.add_byte(fin_len >> 0 & 0xFF);
        ba_hidif.add_byte(fin_crc >> 8 & 0xFF);
        ba_hidif.add_byte(fin_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(fin_buf, fin_len);
        add_sw(CIPHER_SW_NO_ERROR);

        mbedtls_md_free(md_ctx);
        mbedtls_cipher_free(cr_ctx);

        return true;
    }
    while (0);

    add_sw(CIPHER_SW_ERR_OTHER);
    reset_keepalive();

    return false;
}

static bool cpr_encryption_sign(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_EncryptionSet)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    /**
     * Always extended length encoding (0|MSB|LSB)
     */
    uint16_t    pub_len = req->dat_[1] << 8 | req->dat_[2];
    uint16_t    pub_crc = req->dat_[3] << 8 | req->dat_[4];
    uint8_t     *pub_buf = &req->dat_[5];

    if (check_checksum(pub_crc, pub_buf, pub_len) == false)
    {
        add_sw(CIPHER_SW_WRONG_DATA);
        return true;
    }

    mbedtls_pk_context      pk_ctx;
    mbedtls_md_context_t    md_ctx;

    mbedtls_pk_init(&pk_ctx);
    mbedtls_md_init(&md_ctx);

    do
    {
        while (*pub_buf == '\n')
        {
            pub_buf++;
            pub_len--;
        }

        if (pub_buf[pub_len - 1] != '\0')
            pub_buf[pub_len++] = '\0';

        /**
         * Create PUBLIC KEY hash -> Unique ID
         */

        uint8_t     md_pub[CIPHER_MD_SIZE];

        if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_starts(&md_ctx) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_update(&md_ctx, pub_buf, pub_len) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_finish(&md_ctx, md_pub) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        /**
         * Encryp the cipher information in use of given PUBLIC KEY
         */

        if (mbedtls_pk_parse_public_key(&pk_ctx, pub_buf, pub_len) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        uint8_t     *seed = keepalive_data.encryption_.seed_;
        uint8_t     *md = keepalive_data.encryption_.md_;
        uint8_t     n = 0;
        size_t      enc_len;
        uint8_t     plain_text[(CIPHER_TAG_LEN_SIZE + CIPHER_SEED_SIZE) + (CIPHER_TAG_LEN_SIZE + CIPHER_MD_SIZE)];
        uint8_t     cipher_text[BLOB_SIZE];

        plain_text[n++] = CIPHER_SIGN_TAG_SEED;
        plain_text[n++] = CIPHER_SEED_SIZE >> 8 & 0xFF;
        plain_text[n++] = CIPHER_SEED_SIZE >> 0 & 0xFF;
        memcpy(&plain_text[n], seed, CIPHER_SEED_SIZE);
        n += CIPHER_SEED_SIZE;

        plain_text[n++] = CIPHER_SIGN_TAG_MD;
        plain_text[n++] = CIPHER_MD_SIZE >> 8 & 0xFF;
        plain_text[n++] = CIPHER_MD_SIZE >> 0 & 0xFF;
        memcpy(&plain_text[n], md, CIPHER_MD_SIZE);
        n += CIPHER_MD_SIZE;

        if (mbedtls_pk_encrypt(&pk_ctx, plain_text, n, cipher_text, &enc_len, BLOB_SIZE, mbedtls_if_rng, NULL) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        uint16_t    payload_len = CIPHER_MD_SIZE + enc_len;
        uint16_t    payload_crc = make_checksum(md_pub, CIPHER_MD_SIZE);

        payload_crc = get_crc16_ccitt(payload_crc, cipher_text, enc_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */

        ba_hidif.add_byte(0);
        ba_hidif.add_byte(payload_len >> 8 & 0xFF);
        ba_hidif.add_byte(payload_len >> 0 & 0xFF);
        ba_hidif.add_byte(payload_crc >> 8 & 0xFF);
        ba_hidif.add_byte(payload_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(md_pub, CIPHER_MD_SIZE);
        ba_hidif.add_bytes(cipher_text, enc_len);
        add_sw(CIPHER_SW_NO_ERROR);
    }
    while (0);

    mbedtls_pk_free(&pk_ctx);
    mbedtls_md_free(&md_ctx);

    return true;
}

static void cpr_encryption_term(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ == _KA_EncryptionSet)
    {
        add_sw(CIPHER_SW_NO_ERROR);
        reset_keepalive();
    }
    else
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
    }
}

static bool cpr_decryption_init(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    uint8_t     buffer[BLOB_SIZE];
    uint16_t    length = load_public_key(buffer, BLOB_SIZE);

    if (length == 0)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    if (keepalive_data.type_ != _KA_None)
        reset_keepalive();

    uint16_t    meta_len = req->dat_[1] << 8 | req->dat_[2];
    uint16_t    meta_crc = req->dat_[3] << 8 | req->dat_[4];
    uint8_t     *meta_buf = &req->dat_[5];

    if ((req->dat_[0] != 0) && (check_checksum(meta_crc, meta_buf, meta_len) == false))
    {
        add_sw(CIPHER_SW_WRONG_DATA);
        return false;
    }

    mbedtls_pk_context          pk_ctx;
    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;

    mbedtls_pk_init(&pk_ctx);
    mbedtls_md_init(md_ctx);
    mbedtls_cipher_init(cr_ctx);

    do
    {
        /**
         * Create PUBLIC KEY hash -> Unique ID
         */

        uint8_t     md_pub[CIPHER_MD_SIZE];

        if (mbedtls_md_setup(md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_starts(md_ctx) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_update(md_ctx, buffer, length) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_finish(md_ctx, md_pub) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (memcmp(md_pub, meta_buf, CIPHER_MD_SIZE) != 0)
        {
            add_sw(CIPHER_SW_WRONG_KEY);
            break;
        }

        /**
         * Decrypt the metadata
         */

        if (storage_key_read(buffer, &length) == false)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_pk_parse_key(&pk_ctx, buffer, length, NULL, 0) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        meta_buf += CIPHER_MD_SIZE;
        meta_len -= CIPHER_MD_SIZE;

        size_t  dec_len;

        if (mbedtls_pk_decrypt(&pk_ctx, meta_buf, meta_len, buffer, &dec_len, length, mbedtls_if_rng, NULL) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        /**
         * Check metadata
         */

        uint8_t     *seed = keepalive_data.encryption_.seed_;
        uint8_t     *md = keepalive_data.encryption_.md_;
        int16_t     n = 0;

        if (buffer[n++] != CIPHER_SIGN_TAG_SEED)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        length  = buffer[n++] << 8;
        length |= buffer[n++] << 0;

        if (length != CIPHER_SEED_SIZE)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        memcpy(seed, &buffer[n], length);
        n += length;

        if (buffer[n++] != CIPHER_SIGN_TAG_MD)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        length  = buffer[n++] << 8;
        length |= buffer[n++] << 0;

        if (length != CIPHER_MD_SIZE)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        memcpy(md, &buffer[n], length);

        /**
         * Get block cipher key
         */

        uint8_t     iv[CIPHER_BLOCK_IV_SIZE];
        uint8_t     key[CIPHER_BLOCK_KEY_SIZE];

        if (make_block_key(seed, iv, key, false) == false)
            break;

        mbedtls_md_free(md_ctx);
        mbedtls_md_init(md_ctx);

        if (mbedtls_md_setup(md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0)
            break;
        if (mbedtls_md_hmac_starts(md_ctx, key, CIPHER_BLOCK_KEY_SIZE) != 0)
            break;

        if (mbedtls_cipher_setup(cr_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)) != 0)
            break;
        if (mbedtls_cipher_setkey(cr_ctx, key, CIPHER_BLOCK_KEY_SIZE * 8, MBEDTLS_DECRYPT) != 0)
            break;
        if (mbedtls_cipher_set_iv(cr_ctx, iv, CIPHER_BLOCK_IV_SIZE) != 0)
            break;
        if (mbedtls_cipher_reset(cr_ctx) != 0)
            break;

        keepalive_data.type_ = _KA_EncryptionGet;

        add_sw(CIPHER_SW_NO_ERROR);

        return true;
    }
    while (0);

    add_sw(CIPHER_SW_ERR_OTHER);

    mbedtls_pk_free(&pk_ctx);
    mbedtls_md_free(md_ctx);
    mbedtls_cipher_free(cr_ctx);
    memset(&keepalive_data, 0, sizeof(CPR_Keepalive));

    return false;
}

static bool cpr_decryption_do(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_EncryptionGet)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    /**
     * Always extended length encoding (0|MSB|LSB)
     */
    uint16_t    block_len = req->dat_[1] << 8 | req->dat_[2];
    uint16_t    block_crc = req->dat_[3] << 8 | req->dat_[4];
    uint8_t     *block_buf = &req->dat_[5];

    if ((req->dat_[0] != 0) || (check_checksum(block_crc, block_buf, block_len) == false))
    {
        add_sw(CIPHER_SW_WRONG_DATA);
        return true;
    }

    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;

    do
    {
        size_t  dec_len;
        uint8_t dec_buf[CIPHER_BLOCK_SIZE];

        if (mbedtls_cipher_update(cr_ctx, block_buf, block_len, dec_buf, &dec_len) != 0)
            break;

        if (mbedtls_md_hmac_update(md_ctx, dec_buf, dec_len) != 0)
            break;

        uint16_t    dec_crc = make_checksum(dec_buf, dec_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */
        ba_hidif.add_byte(0);
        ba_hidif.add_byte(dec_len >> 8 & 0xFF);
        ba_hidif.add_byte(dec_len >> 0 & 0xFF);
        ba_hidif.add_byte(dec_crc >> 8 & 0xFF);
        ba_hidif.add_byte(dec_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(dec_buf, dec_len);
        add_sw(CIPHER_SW_NO_ERROR);

        return true;
    }
    while (0);

    add_sw(CIPHER_SW_ERR_OTHER);
    reset_keepalive();

    return false;
}

static bool cpr_decryption_done(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ != _KA_EncryptionGet)
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
        return false;
    }

    mbedtls_md_context_t        *md_ctx = &keepalive_data.encryption_.md_ctx_;
    mbedtls_cipher_context_t    *cr_ctx = &keepalive_data.encryption_.cr_ctx_;
    uint8_t     *md = keepalive_data.encryption_.md_;

    do
    {
        uint8_t     md_plain[CIPHER_MD_SIZE];
        uint8_t     fin_buf[CIPHER_BLOCK_SIZE];
        size_t      fin_len;

        if (mbedtls_cipher_finish(cr_ctx, fin_buf, &fin_len) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_hmac_update(md_ctx, fin_buf, fin_len) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (mbedtls_md_hmac_finish(md_ctx, md_plain) != 0)
        {
            add_sw(CIPHER_SW_ERR_OTHER);
            break;
        }

        if (memcmp(md, md_plain, CIPHER_MD_SIZE) != 0)
        {
            add_sw(CIPHER_SW_WRONG_KEY);
            break;
        }

        uint16_t    fin_crc = make_checksum(fin_buf, fin_len);

        /**
         * Always extended length encoding (0|MSB|LSB)
         */
        ba_hidif.add_byte(0);
        ba_hidif.add_byte(fin_len >> 8 & 0xFF);
        ba_hidif.add_byte(fin_len >> 0 & 0xFF);
        ba_hidif.add_byte(fin_crc >> 8 & 0xFF);
        ba_hidif.add_byte(fin_crc >> 0 & 0xFF);
        ba_hidif.add_bytes(fin_buf, fin_len);
        add_sw(CIPHER_SW_NO_ERROR);

        mbedtls_md_free(md_ctx);
        mbedtls_cipher_free(cr_ctx);

        return true;
    }
    while (0);

    reset_keepalive();

    return false;
}

static bool cpr_decryption_sign(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ == _KA_EncryptionGet)
    {
        add_sw(CIPHER_SW_NO_ERROR);
        return true;
    }

    add_sw(CIPHER_SW_NOT_SATISFIED);
    return false;
}

static void cpr_decryption_term(CPR_Request *req, uint16_t len, uint32_t now_ms)
{
    if (keepalive_data.type_ == _KA_EncryptionGet)
    {
        add_sw(CIPHER_SW_NO_ERROR);
        reset_keepalive();
    }
    else
    {
        add_sw(CIPHER_SW_NOT_SATISFIED);
    }
}

bool cpr_request(uint8_t *msg, uint16_t len, uint32_t now_ms)
{
    bool        keepalive = false;
    CPR_Request *req = (CPR_Request*)msg;

    if (req->cla_ == CIPHER_CLASS)
    {
        switch (req->ins_)
        {
        case CIPHER_VERSION:

            cpr_version(req, len);
            break;

        case CIPHER_KEY:

            if (req->p1_ == CIPHER_PARAM_SET)
                cpr_key_set(req, len);
            else if (req->p1_ == CIPHER_PARAM_GET)
                cpr_key_get(req, len);
            else
                add_sw(CIPHER_SW_INVALID_PARAM);
            break;

        case CIPHER_ENCRYPTION:

            if (req->p1_ == CIPHER_PARAM_SET)
            {
                switch (req->p2_)
                {
                case CIPHER_PARAM_INIT:
                    keepalive = cpr_encryption_init(req, len, now_ms);
                    break;
                case CIPHER_PARAM_DO:
                    keepalive = cpr_encryption_do(req, len, now_ms);
                    break;
                case CIPHER_PARAM_DONE:
                    keepalive = cpr_encryption_done(req, len, now_ms);
                    break;
                case CIPHER_PARAM_SIGN:
                    keepalive = cpr_encryption_sign(req, len, now_ms);
                    break;
                case CIPHER_PARAM_TERM:
                    cpr_encryption_term(req, len, now_ms);
                    break;
                default:
                    add_sw(CIPHER_SW_INVALID_PARAM);
                    break;
                }
            }
            else if (req->p1_ == CIPHER_PARAM_GET)
            {
                switch (req->p2_)
                {
                case CIPHER_PARAM_INIT:
                    keepalive = cpr_decryption_init(req, len, now_ms);
                    break;
                case CIPHER_PARAM_DO:
                    keepalive = cpr_decryption_do(req, len, now_ms);
                    break;
                case CIPHER_PARAM_DONE:
                    keepalive = cpr_decryption_done(req, len, now_ms);
                    break;
                case CIPHER_PARAM_SIGN:
                    keepalive = cpr_decryption_sign(req, len, now_ms);
                    break;
                case CIPHER_PARAM_TERM:
                    cpr_decryption_term(req, len, now_ms);
                    break;
                default:
                    add_sw(CIPHER_SW_INVALID_PARAM);
                    break;
                }
            }
            else
            {
                add_sw(CIPHER_SW_INVALID_PARAM);
            }
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

bool cpr_keepalive(uint32_t now_ms)
{
    if (button_pushed())
    {
        return true;
    }

    return false;
}

/* end of file ****************************************************************************************************** */

