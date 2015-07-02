/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2015   Dennis A. Bush, Jr.   bush@tcnj.edu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, the copyright holder
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#ifdef WINDOWS

#include <winsock2.h>

#endif

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "uftp_common.h"
#include "encryption.h"

/**
 * Prints OpenSSL errors to log
 */
static void log_ssl_err(const char *mes)
{
    unsigned long err, found;
    char errstr[1000];

    found = 0;
    while ((err = ERR_get_error())) {
        ERR_error_string(err, errstr);
        log0(0, 0, 0, "%s: %s", mes, errstr);
        found = 1;
    }
    if (!found) {
        log0(0, 0, 0, "%s", mes);
    }
}

static int init_done;

/**
 * Performs all necessary steps to initialize the crypto library
 */
void crypto_init(int set_sys_key)
{
    // TODO: include calls to RAND_add and the like?
    OpenSSL_add_all_algorithms();
#ifdef EVP_CIPH_CCM_MODE
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_256_ccm());
#endif
    ERR_load_crypto_strings();
    init_done = 1;
}

/**
 * Performs all necessary steps to clean up the crypto library
 */
void crypto_cleanup(void)
{
    if (init_done) {
        ERR_free_strings();
        EVP_cleanup();
    }
}

#ifndef NO_EC
/**
 * Gets the EC curve type associated with a given curve NID
 */
static uint8_t get_ec_curve_type(int curve)
{
    switch (curve) {
    case NID_sect163k1:
        return CURVE_sect163k1;
    case NID_sect163r1:
        return CURVE_sect163r1;
    case NID_sect163r2:
        return CURVE_sect163r2;
    case NID_sect193r1:
        return CURVE_sect193r1;
    case NID_sect193r2:
        return CURVE_sect193r2;
    case NID_sect233k1:
        return CURVE_sect233k1;
    case NID_sect233r1:
        return CURVE_sect233r1;
    case NID_sect239k1:
        return CURVE_sect239k1;
    case NID_sect283k1:
        return CURVE_sect283k1;
    case NID_sect283r1:
        return CURVE_sect283r1;
    case NID_sect409k1:
        return CURVE_sect409k1;
    case NID_sect409r1:
        return CURVE_sect409r1;
    case NID_sect571k1:
        return CURVE_sect571k1;
    case NID_sect571r1:
        return CURVE_sect571r1;
    case NID_secp160k1:
        return CURVE_secp160k1;
    case NID_secp160r1:
        return CURVE_secp160r1;
    case NID_secp160r2:
        return CURVE_secp160r2;
    case NID_secp192k1:
        return CURVE_secp192k1;
    case NID_X9_62_prime192v1:
        return CURVE_secp192r1;
    case NID_secp224k1:
        return CURVE_secp224k1;
    case NID_secp224r1:
        return CURVE_secp224r1;
    case NID_secp256k1:
        return CURVE_secp256k1;
    case NID_X9_62_prime256v1:
        return CURVE_secp256r1;
    case NID_secp384r1:
        return CURVE_secp384r1;
    case NID_secp521r1:
        return CURVE_secp521r1;
    default:
        return 0;
    }
}

/**
 * Gets the EC curve NID associated with a given curve
 */
static int get_ec_curve_nid(uint8_t curve)
{
    switch (curve) {
    case CURVE_sect163k1:
        return NID_sect163k1;
    case CURVE_sect163r1:
        return NID_sect163r1;
    case CURVE_sect163r2:
        return NID_sect163r2;
    case CURVE_sect193r1:
        return NID_sect193r1;
    case CURVE_sect193r2:
        return NID_sect193r2;
    case CURVE_sect233k1:
        return NID_sect233k1;
    case CURVE_sect233r1:
        return NID_sect233r1;
    case CURVE_sect239k1:
        return NID_sect239k1;
    case CURVE_sect283k1:
        return NID_sect283k1;
    case CURVE_sect283r1:
        return NID_sect283r1;
    case CURVE_sect409k1:
        return NID_sect409k1;
    case CURVE_sect409r1:
        return NID_sect409r1;
    case CURVE_sect571k1:
        return NID_sect571k1;
    case CURVE_sect571r1:
        return NID_sect571r1;
    case CURVE_secp160k1:
        return NID_secp160k1;
    case CURVE_secp160r1:
        return NID_secp160r1;
    case CURVE_secp160r2:
        return NID_secp160r2;
    case CURVE_secp192k1:
        return NID_secp192k1;
    case CURVE_secp192r1:
        return NID_X9_62_prime192v1;
    case CURVE_secp224k1:
        return NID_secp224k1;
    case CURVE_secp224r1:
        return NID_secp224r1;
    case CURVE_secp256k1:
        return NID_secp256k1;
    case CURVE_secp256r1:
        return NID_X9_62_prime256v1;
    case CURVE_secp384r1:
        return NID_secp384r1;
    case CURVE_secp521r1:
        return NID_secp521r1;
    default:
        return 0;
    }
}
#endif

/**
 * Gets the EVP_CIPHER associated with a given keytype
 */
static const EVP_CIPHER *get_cipher(int keytype)
{
    switch (keytype) {
    case KEY_DES:
        return EVP_get_cipherbyname("DES-CBC");
    case KEY_DES_EDE3:
        return EVP_get_cipherbyname("DES-EDE3-CBC");
    case KEY_AES128_CBC:
        return EVP_get_cipherbyname("AES-128-CBC");
    case KEY_AES256_CBC:
        return EVP_get_cipherbyname("AES-256-CBC");
    case KEY_AES128_GCM:
        return EVP_get_cipherbyname("id-aes128-GCM");
    case KEY_AES256_GCM:
        return EVP_get_cipherbyname("id-aes256-GCM");
    case KEY_AES128_CCM:
        return EVP_get_cipherbyname("id-aes128-CCM");
    case KEY_AES256_CCM:
        return EVP_get_cipherbyname("id-aes256-CCM");
    default:
        log0(0, 0, 0, "Unknown keytype: %d", keytype);
        return NULL;
    }
}

/**
 * Gets the EVP_MD associated with a given hashtype
 */
static const EVP_MD *get_hash(int hashtype)
{
    switch (hashtype) {
    case HASH_SHA512:
        return EVP_get_digestbyname("SHA512");
    case HASH_SHA384:
        return EVP_get_digestbyname("SHA384");
    case HASH_SHA256:
        return EVP_get_digestbyname("SHA256");
    case HASH_SHA1:
        return EVP_get_digestbyname("SHA1");
    case HASH_MD5:
        return EVP_get_digestbyname("MD5");
    default:
        log0(0, 0, 0, "Unknown hashtype: %d", hashtype);
        return NULL;
    }
}

/**
 * Returns whether a particular cipher is supported
 */
int cipher_supported(int keytype)
{
    return (get_cipher(keytype) != NULL);
}

/**
 * Returns whether a particular hash is supported
 */
int hash_supported(int hashtype)
{
    return (get_hash(hashtype) != NULL);
}

/**
 * Gets the key length and IV/block length of a given key
 */
void get_key_info(int keytype, int *keylen, int *ivlen)
{
    const EVP_CIPHER *cipher = get_cipher(keytype);
    int mode;

    if (cipher == NULL) {
        *keylen = 0;
        *ivlen = 0;
    } else {
        mode = EVP_CIPHER_mode(cipher);
        *keylen = EVP_CIPHER_key_length(cipher);
#ifdef EVP_CIPH_GCM_MODE
        if (mode == EVP_CIPH_GCM_MODE) {
            *ivlen = GCM_IV_LEN;
        } else if (mode == EVP_CIPH_CCM_MODE) {
            *ivlen = CCM_IV_LEN;
        } else {
            *ivlen = EVP_CIPHER_iv_length(cipher);
        }
#else
        *ivlen = EVP_CIPHER_iv_length(cipher);
#endif
    }
}

/**
 * Gets the length of the given hash
 */
int get_hash_len(int hashtype)
{
    const EVP_MD *hashptr = get_hash(hashtype);

    if (hashptr == NULL) {
        return 0;
    } else {
        return EVP_MD_size(hashptr);
    }
}

/**
 * Gets num cryptographically random bytes
 */
int get_random_bytes(unsigned char *buf, int num)
{
    int rval;

    if (!(rval = RAND_bytes(buf, num))) {
        log_ssl_err("Error getting random bytes");
    }
    return rval;
}

/**
 * Takes a block of data and encrypts it with a symmetric cypher.
 * For authenticated cipher modes, also takes additional authentication data.
 * The output buffer must be at least the size of source data + block size.
 */
int encrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = get_cipher(keytype);
    int mode, len;

    if (cipher == NULL) {
        log0(0, 0, 0, "Invalid keytype");
        return 0;
    }
    mode = EVP_CIPHER_mode(cipher);
    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_EncryptInit_ex(&ctx, cipher, NULL, NULL, NULL)) {
        log_ssl_err("EncryptInit for cipher failed");
        return 0;
    }
#ifdef EVP_CIPH_GCM_MODE
    if (mode == EVP_CIPH_GCM_MODE) {
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, 0)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for IVLEN failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    } else if (mode == EVP_CIPH_CCM_MODE) {
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, CCM_IV_LEN, 0)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for IVLEN failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN, 0)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for tag len failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    }
#endif
    if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, IV)) {
        log_ssl_err("EncryptInit for key/IV failed");
        return 0;
    }
    len = 0;
#ifdef EVP_CIPH_GCM_MODE
    if ((mode == EVP_CIPH_GCM_MODE) || (mode == EVP_CIPH_CCM_MODE)) {
        if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_EncryptUpdate(&ctx, NULL, &len, NULL, srclen)) {
                log_ssl_err("EncryptUpdate for datalen failed");
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
        if ((aad != NULL) && (aadlen > 0)) {
            if (!EVP_EncryptUpdate(&ctx, NULL, &len, aad, aadlen)) {
                log_ssl_err("EncryptUpdate for authdata failed");
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
    }
#endif
    if (!EVP_EncryptUpdate(&ctx, dest, &len, src, srclen)) {
        log_ssl_err("EncryptUpdate for data failed");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
    *destlen = len;
    if (!EVP_EncryptFinal_ex(&ctx, dest + *destlen, &len)) {
        log_ssl_err("EncryptFinal failed");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
#ifdef EVP_CIPH_GCM_MODE
    if (mode == EVP_CIPH_GCM_MODE) {
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                                 dest + *destlen)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for get tag failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        len += GCM_TAG_LEN;
    } else if (mode == EVP_CIPH_CCM_MODE) {
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, CCM_TAG_LEN,
                                 dest + *destlen)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for get tag failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        len += CCM_TAG_LEN;
    }
#endif
    *destlen += len;
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

/**
 * Takes a block of data encrypted with a symmetric cypher and decrypts it.
 * For authenticated cipher modes, also takes additional authentication data.
 * The output buffer must be at least the size of source data.
 */
int decrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = get_cipher(keytype);
    int mode, len, l_srclen;

    if (cipher == NULL) {
        log0(0, 0, 0, "Invalid keytype");
        return 0;
    }
    mode = EVP_CIPHER_mode(cipher);
    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL)) {
        log_ssl_err("DecryptInit for cipher failed");
        return 0;
    }
#ifdef EVP_CIPH_GCM_MODE
    if (mode == EVP_CIPH_GCM_MODE) {
        l_srclen = srclen - GCM_TAG_LEN;
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, 0)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for IVLEN failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                 (void *)(src + l_srclen))) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for set tag failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    } else if (mode == EVP_CIPH_CCM_MODE) {
        l_srclen = srclen - CCM_TAG_LEN;
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, CCM_IV_LEN, 0)) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for IVLEN failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, CCM_TAG_LEN,
                                 (void *)(src + l_srclen))) {
            log_ssl_err("EVP_CIPHER_CTX_ctrl for set tag failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    } else {
        l_srclen = srclen;
    }
#else
    l_srclen = srclen;
#endif
    if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, IV)) {
        log_ssl_err("DecryptInit for key/IV failed");
        return 0;
    }
    len = 0;
#ifdef EVP_CIPH_GCM_MODE
    if ((mode == EVP_CIPH_GCM_MODE) || (mode == EVP_CIPH_CCM_MODE)) {
        if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_DecryptUpdate(&ctx, NULL, &len, NULL, l_srclen)) {
                log_ssl_err("DecryptUpdate for datalen failed");
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
        if ((aad != NULL) && (aadlen > 0)) {
            if (!EVP_DecryptUpdate(&ctx, NULL, &len, aad, aadlen)) {
                log_ssl_err("DecryptUpdate for authdata failed");
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
    }
#endif
    if (!EVP_DecryptUpdate(&ctx, dest, &len, src, l_srclen)) {
        log_ssl_err("DecryptUpdate for data failed");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
    *destlen = len;
#ifdef EVP_CIPH_CCM_MODE
    if (mode != EVP_CIPH_CCM_MODE) {
#endif
        if (!EVP_DecryptFinal_ex(&ctx, dest + *destlen, &len)) {
            log_ssl_err("DecryptFinal failed");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        *destlen += len;
#ifdef EVP_CIPH_CCM_MODE
    }
#endif
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

/**
 * Calculates the HMAC of the given message, hashtype, and hashkey.
 * dest must be at least the hash length.
 */
int create_hmac(int hashtype, const unsigned char *key, unsigned int keylen,
                const unsigned char *src, unsigned int srclen,
                unsigned char *dest, unsigned int *destlen)
{
    const EVP_MD *hashptr = get_hash(hashtype);

    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }
    return (HMAC(hashptr, key, keylen, src, srclen, dest, destlen) != NULL);
}

/**
 * Calculates the hash of the given message and hashtype
 */
int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen)
{
    EVP_MD_CTX hashctx;
    const EVP_MD *hashptr = get_hash(hashtype);

    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }
    EVP_MD_CTX_init(&hashctx);
    if (!EVP_DigestInit_ex(&hashctx, hashptr, NULL)) {
        log_ssl_err("DigestInit failed");
        EVP_MD_CTX_cleanup(&hashctx);
        return 0;
    }
    if (!EVP_DigestUpdate(&hashctx, src, srclen)) {
        log_ssl_err("DigestUpdate failed");
        EVP_MD_CTX_cleanup(&hashctx);
        return 0;
    }
    if (!EVP_DigestFinal_ex(&hashctx, dest, (unsigned int *)destlen)) {
        log_ssl_err("DigestUpdate failed");
        EVP_MD_CTX_cleanup(&hashctx);
        return 0;
    }
    EVP_MD_CTX_cleanup(&hashctx);

    return 1;
}

/**
 * Returns the length in bytes of the modulus for the given RSA key
 */
int RSA_keylen(const RSA_key_t rsa)
{
    return RSA_size(rsa);
}

/**
 * Returns the length of an exported EC public key
 * An exported key is built as follows:
 *   uint8_t xpoint[ceil(curve_bitlen/8)]
 *   uint8_t ypoint[ceil(curve_bitlen/8)]
 *   uint8_t padding[]
 */
int EC_keylen(const EC_key_t ec)
{
#ifndef NO_EC
    int keylen, padding; 

    if ((keylen = i2o_ECPublicKey(ec, NULL)) == 0) {
        log0(0, 0, 0, "error getting size of EC key");
        return 0;
    }
    // Don't count leading "4"
    keylen--;
    if ((keylen % 4) == 0) {
        padding = 0;
    } else {
        padding = 4 - (keylen % 4);
    }
    
    return keylen + padding;
#else
    return 0;
#endif
}

/**
 * Returns the length in bytes of a signature created by the given ECDSA key
 * ECDSA signatures consist of:
 *   uint16_t rlen
 *   uint16_t slen
 *   uint8_t rsig[ceil(curve_bitlen/8)]
 *   uint8_t ssig[ceil(curve_bitlen/8)]
 *   uint8_t padding[]
 */
int ECDSA_siglen(const EC_key_t ec)
{
#ifndef NO_EC
    return sizeof(uint16_t) + sizeof(uint16_t) + EC_keylen(ec);
#else
    return 0;
#endif
}

/**
 * Encrypts a small block of data with an RSA public key.
 * Output buffer must be at least the key size.
 */
int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    int padding;

    if (RSA_size(rsa) * 8 < 768) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    if ((*tolen = RSA_public_encrypt(fromlen, from, to, rsa, padding)) == -1) {
        log_ssl_err("RSA_public_encrypt failed");
        return 0;
    }

    return 1;
}

/**
 * Decrypts a small block of data with an RSA private key.
 */
int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    int padding;

    if (RSA_size(rsa) * 8 < 768) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    if ((*tolen = RSA_private_decrypt(fromlen, from, to, rsa, padding)) == -1) {
        log_ssl_err("RSA_private_decrypt failed");
        return 0;
    }

    return 1;
}

/**
 * Hashes a block of data and signs it with an RSA private key.
 * Output buffer must be at least the key size.
 */
int create_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int *siglen)
{
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }
    if (!RSA_sign(EVP_MD_type(hashptr), meshash, meshashlen,
                  sig, siglen, rsa)) {
        log_ssl_err("RSA_sign failed");
        return 0;
    } else {
        return 1;
    }
}

/**
 * Hashes a block of data and verifies it against an RSA signature.
 */
int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen)
{
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }
    if (!RSA_verify(EVP_MD_type(hashptr), meshash, meshashlen,
                    sig, siglen, rsa)) {
        log_ssl_err("RSA_verify failed");
        return 0;
    } else {
        return 1;
    }
}

/**
 * Hashes a block of data and signs it with a ECDSA private key.
 * Output buffer must be at least ECDSA_siglen bytes
 */
int create_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     unsigned char *sig, unsigned int *siglen)
{
#ifndef NO_EC
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;
    ECDSA_SIG *_sig;
    uint16_t *rlen, *slen;
    unsigned char *rval, *sval;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }
    if ((_sig = ECDSA_do_sign(meshash, meshashlen, ec)) == NULL) {
        log_ssl_err("ECDSA_do_sign failed");
        return 0;
    }

    rlen = (uint16_t *)sig;
    slen = (uint16_t *)(sig + sizeof(uint16_t));
    rval = (unsigned char *)slen + sizeof(uint16_t);
    sval = rval + BN_num_bytes(_sig->r);

    *siglen = ECDSA_siglen(ec);
    memset(sig, 0, *siglen);
    *rlen = htons(BN_num_bytes(_sig->r));
    *slen = htons(BN_num_bytes(_sig->s));
    BN_bn2bin(_sig->r, rval);
    BN_bn2bin(_sig->s, sval);
    ECDSA_SIG_free(_sig);
    return 1;
#else
    log0(0, 0, 0, "ECDSA not supported");
    return 0;
#endif
}

/**
 * Hashes a block of data and verifies it against a ECDSA signature.
 */
int verify_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     const unsigned char *sig, unsigned int siglen)
{
#ifndef NO_EC
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    const EVP_MD *hashptr;
    ECDSA_SIG *_sig;
    const uint16_t *rlen, *slen;
    const unsigned char *rval, *sval;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    hashptr = get_hash(hashtype);
    if (hashptr == NULL) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }

    rlen = (const uint16_t *)sig;
    slen = (const uint16_t *)(sig + sizeof(uint16_t));
    rval = (const unsigned char *)slen + sizeof(uint16_t);
    sval = rval + ntohs(*rlen);
    if (ntohs(*rlen) + ntohs(*slen) > siglen) {
        log0(0, 0, 0, "Invalid signature length");
        return 0;
    }

    _sig = ECDSA_SIG_new();
    if (BN_bin2bn(rval, ntohs(*rlen), _sig->r) == NULL) {
        log_ssl_err("BN_bn2bin failed for r");
        ECDSA_SIG_free(_sig);
        return 0;
    }
    if (BN_bin2bn(sval, ntohs(*slen), _sig->s) == NULL) {
        log_ssl_err("BN_bn2bin failed for r");
        ECDSA_SIG_free(_sig);
        return 0;
    }

    if (!ECDSA_do_verify(meshash, meshashlen, _sig, ec)) {
        log_ssl_err("ECDSA_do_verify failed");
        ECDSA_SIG_free(_sig);
        return 0;
    } else {
        ECDSA_SIG_free(_sig);
        return 1;
    }
#else
    log0(0, 0, 0, "ECDSA not supported");
    return 0;
#endif
}

#ifndef NO_EC
/**
 * Key derivation function for ECDH.
 * Takes the raw key and returns the SHA-1 hash of the key
 */
static void *KDF(const void *in, size_t inlen, void *out, size_t *outlen)
{
    unsigned int outlen_i;
    if (!hash(HASH_SHA1, in, inlen, out, &outlen_i)) {
        *outlen = outlen_i;
        return NULL;
    } else {
        *outlen = outlen_i;
        return out;
    }
}
#endif

/**
 * Creates an ECDH key based on two EC keys, one public and one private
 */
int get_ECDH_key(EC_key_t pubkey, EC_key_t privkey, unsigned char *key,
                 unsigned int *keylen)
{
#ifndef NO_EC
    if (!ECDH_compute_key(key, 0, EC_KEY_get0_public_key(pubkey),
            privkey, KDF)) {
        log_ssl_err("couldn't compute shared key");
        return 0;
    }
    *keylen = get_hash_len(HASH_SHA1);
    return 1;
#else
    log0(0, 0, 0, "ECDH not supported");
    return 0;
#endif
}

/**
 * Creates an RSA public key with the given modulus and public exponent
 */
int import_RSA_key(RSA_key_t *rsa, const unsigned char *keyblob,
                   uint16_t bloblen)
{
    const struct rsa_blob_t *rsablob;
    const unsigned char *modulus;

    rsablob = (const struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);

    if (sizeof(struct rsa_blob_t) + ntohs(rsablob->modlen) != bloblen) {
        log0(0, 0, 0, "Error importing RSA key: invalid length");
        return 0;
    } 

    *rsa = RSA_new();

    if (((*rsa)->e = BN_bin2bn((const unsigned char *)&rsablob->exponent,
                               4, NULL)) == NULL) {
        log_ssl_err("BN_bin2bn failed for e");
        return 0;
    }
    if (((*rsa)->n = BN_bin2bn(modulus, ntohs(rsablob->modlen),NULL)) == NULL) {
        log_ssl_err("BN_bin2bn failed for n");
        return 0;
    }

    return 1;
}

/**
 * Extracts the modulus and public exponent from an RSA public key
 */
int export_RSA_key(const RSA_key_t rsa, unsigned char *keyblob,
                   uint16_t *bloblen)
{
    struct rsa_blob_t *rsablob;
    unsigned char *modulus;
    unsigned char bin_exponent[4];
    uint32_t exponent;
    int explen, modlen, i;

    rsablob = (struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);

    if (BN_num_bytes(rsa->e) > sizeof(bin_exponent)) {
        log0(0, 0, 0, "exponent too big for export");
        return 0;
    }
    if ((explen = BN_bn2bin(rsa->e, bin_exponent)) <= 0) {
        log_ssl_err("BN_bn2bin failed for e");
        return 0;
    }
    if (explen > 4) {
        log0(0, 0, 0, "exponent too big, size %d", explen);
        return 0;
    }
    exponent = 0;
    for (i = 0; i < explen; i++) {
        exponent |= bin_exponent[i] << (8 * (explen - i - 1));
    }

    if ((modlen = BN_bn2bin(rsa->n, modulus)) <= 0) {
        log_ssl_err("BN_bn2bin failed for n");
        return 0;
    }
    rsablob->blobtype = KEYBLOB_RSA;
    rsablob->reserved = 0;
    rsablob->modlen = htons(modlen);
    rsablob->exponent = htonl(exponent);
    *bloblen = sizeof(struct rsa_blob_t) + modlen;

    return 1;
}

/**
 * Creates an EC public key with the curve and key value
 */
int import_EC_key(EC_key_t *ec, const unsigned char *keyblob, uint16_t bloblen,
                  int isdh)
{
#ifndef NO_EC
    const struct ec_blob_t *ecblob;
    const unsigned char *keyval, *tmp;
    unsigned char *buf;

    ecblob = (const struct ec_blob_t *)keyblob;
    keyval = keyblob + sizeof(struct ec_blob_t);

    if (sizeof(struct ec_blob_t) + ntohs(ecblob->keylen) > bloblen) {
        log0(0, 0, 0, "Error importing EC key: invalid length");
        return 0;
    } 

    if ((*ec = EC_KEY_new_by_curve_name(
                    get_ec_curve_nid(ecblob->curve))) == NULL) {
        log_ssl_err("EC_KEY_new_by_curve_name failed");
        return 0;
    }
    buf = safe_malloc(ntohs(ecblob->keylen) + 1);
    buf[0] = 4;
    memcpy(&buf[1], keyval, ntohs(ecblob->keylen));
    tmp = buf;
    if (!o2i_ECPublicKey(ec, &tmp, ntohs(ecblob->keylen) + 1)) {
        log_ssl_err("o2i_ECPublicKey failed");
        EC_KEY_free(*ec);
        free(buf);
        return 0;
    }
    free(buf);
    return 1;
#else
    log0(0, 0, 0, "EC keys not supported");
    return 0;
#endif
}

/**
 * Extracts the key value from an EC public key
 */
int export_EC_key(const EC_key_t ec, unsigned char *keyblob, uint16_t *bloblen)
{
#ifndef NO_EC
    struct ec_blob_t *ecblob;
    unsigned char *keyval, *buf, *tmp;
    int keylen;

    ecblob = (struct ec_blob_t *)keyblob;
    keyval = keyblob + sizeof(struct ec_blob_t);

    if ((keylen = i2o_ECPublicKey(ec, NULL)) == 0) {
        log0(0, 0, 0, "error getting size of EC key");
        return 0;
    }
    buf = safe_malloc(keylen);
    tmp = buf;
    // After this call, tmp points to (buf + keylen),
    // but the exported key lives at buf
    if (!i2o_ECPublicKey(ec, &tmp)) {
        log_ssl_err("i2o_ECPublicKey failed");
        free(buf);
        return 0;
    }
    // Keyblob may contain trailing padding; ensure it's zero'ed out
    *bloblen = sizeof(struct ec_blob_t) + EC_keylen(ec);
    memset(keyblob, 0, *bloblen);
    ecblob->blobtype = KEYBLOB_EC;
    ecblob->curve = get_EC_curve(ec);
    // Don't copy the leading "4"
    keylen--;
    memcpy(keyval, &buf[1], keylen);
    ecblob->keylen = htons(keylen);
    free(buf);
    return 1;
#else
    log0(0, 0, 0, "EC keys not supported");
    return 0;
#endif
}

/**
 * Generates an RSA private key with the given exponent and number of bits
 * and writes it to the given file (if specified).
 */
RSA_key_t gen_RSA_key(int bits, int exponent, const char *filename)
{
    RSA_key_t rsa;
    FILE *f;

    if ((rsa = RSA_generate_key(bits ? bits : DEF_RSA_LEN,
                                exponent, NULL, NULL)) == NULL) {
        log_ssl_err("couldn't generate rsa key");
        return NULL;
    }

    if (filename && strcmp(filename, "")) {
        if ((f = fopen(filename, "rb")) != NULL) {
            log0(0, 0, 0, "Private key file already exists, won't overwrite");
            fclose(f);
            return NULL;
        }
        if ((f = fopen(filename, "wb")) == NULL) {
            syserror(0, 0, 0, "failed to open key file");
            return NULL;
        }
        if (!PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL)) {
            log_ssl_err("couldn't write rsa private key");
            fclose(f);
            return NULL;
        }
        fclose(f);
    }

    return rsa;
}

/**
 * Reads an RSA private key from the specified file
 */
RSA_key_t read_RSA_key(const char *filename)
{
    RSA_key_t rsa;
    FILE *f;

    if ((f = fopen(filename, "rb")) == NULL) {
        syserror(0, 0, 0, "failed to open key file");
        return NULL;
    }
    if ((rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)) == NULL) {
        log_ssl_err("couldn't read rsa private key");
        return NULL;
    }
    fclose(f);

    return rsa;
}

/**
 * Generates an EC private key with the given curve
 * and writes it to the given file (if specified).
 */
EC_key_t gen_EC_key(uint8_t curve, int isdh, const char *filename)
{
#ifndef NO_EC
    EC_key_t ec;
    FILE *f;

    if (curve == 0) {
        curve = DEF_CURVE;
    }
    if ((ec = EC_KEY_new_by_curve_name(get_ec_curve_nid(curve))) == NULL) {
        log_ssl_err("EC_KEY_new_by_curve_name failed");
        return NULL;
    }
    if (!EC_KEY_generate_key(ec)) {
        log_ssl_err("EC_KEY_generate_key failed");
        return NULL;
    }
    // Needed to write the PEM with a named curve
    EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);

    if (filename && strcmp(filename, "")) {
        if ((f = fopen(filename, "rb")) != NULL) {
            log0(0, 0, 0, "Private key file already exists, won't overwrite");
            fclose(f);
            return NULL;
        }
        if ((f = fopen(filename, "wb")) == NULL) {
            syserror(0, 0, 0, "failed to open key file");
            return NULL;
        }
        if (!PEM_write_ECPrivateKey(f, ec, NULL, NULL, 0, NULL, NULL)) {
            log_ssl_err("couldn't write EC private key");
            fclose(f);
            return NULL;
        }
        fclose(f);
    }

    return ec;
#else
    log0(0, 0, 0, "EC keys not supported");
    return NULL;
#endif
}

/**
 * Reads an EC private key from the specified file
 */
EC_key_t read_EC_key(const char *filename)
{
#ifndef NO_EC
    EC_key_t ec;
    FILE *f;

    if ((f = fopen(filename, "rb")) == NULL) {
        syserror(0, 0, 0, "failed to open key file");
        return NULL;
    }
    if ((ec = PEM_read_ECPrivateKey(f, NULL, NULL, NULL)) == NULL) {
        log_ssl_err("couldn't read EC private key");
        return NULL;
    }
    fclose(f);

    return ec;
#else
    log0(0, 0, 0, "EC keys not supported");
    return NULL;
#endif
}

/**
 * Reads a private key of unknown type
 */
union key_t read_private_key(const char *filename, int *keytype)
{
    union key_t key;
    FILE *f;

    key.key = 0;
    if ((f = fopen(filename, "rb")) == NULL) {
        syserror(0, 0, 0, "failed to open key file");
        *keytype = 0;
        return key;
    }
    if ((key.rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)) != NULL) {
        fclose(f);
        *keytype = KEYBLOB_RSA;
        return key;
    }
    fclose(f);

#ifndef NO_EC
    key.key = 0;
    if ((f = fopen(filename, "rb")) == NULL) {
        syserror(0, 0, 0, "failed to open key file");
        *keytype = 0;
        return key;
    }
    if ((key.ec = PEM_read_ECPrivateKey(f, NULL, NULL, NULL)) != NULL) {
        *keytype = KEYBLOB_EC;
    } else {
        log0(0, 0, 0, "Failed to read key");
        *keytype = 0;
    }
    fclose(f);
    return key;
#else
    log0(0, 0, 0, "Failed to read key");
    key.key = 0;
    *keytype = 0;
    return key;
#endif
}

/**
 * Returns the EC curve type of the specified EC key
 */
uint8_t get_EC_curve(const EC_key_t ec)
{
#ifndef NO_EC
    int nid;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
    return get_ec_curve_type(nid);
#else
    log0(0, 0, 0, "EC keys not supported");
    return 0;
#endif
}

void free_RSA_key(RSA_key_t rsa)
{
    RSA_free(rsa);
}

void free_EC_key(EC_key_t ec)
{
#ifndef NO_EC
    EC_KEY_free(ec);
#endif
}

const char *get_next_container()
{
    return NULL;
}

void delete_container(const char *name)
{
}

void set_sys_keys(int set)
{
}
