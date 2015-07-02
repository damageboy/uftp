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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uftp_common.h"
#include "encryption.h"

#define MAXLIST 100
#define BLOBLEN 1000

struct private_key_list_t {
    HCRYPTPROV provider;
    HCRYPTKEY key;
};

struct key_list_t {
    char keystr[MAXKEY];
    int keylen;
    HCRYPTKEY mskey;
};


static const struct keyinfo_t {
    ALG_ID alg;
    int keysize;
    int blocksize;
} keyinfo[] = {
    { CALG_DES, 8, 8 },
    { CALG_3DES, 24, 8 },
#ifdef CALG_AES_128
    { CALG_AES_128, 16, 16 },
#endif
#ifdef CALG_AES_256
    { CALG_AES_256, 32, 16}
#endif
};

static const struct hashinfo_t {
    ALG_ID alg;
    int hashsize;
} hashinfo[] = {
    { CALG_MD5, 16 },
    { CALG_SHA1, 20 },
#ifdef CALG_SHA_256
    { CALG_SHA_256, 32 }
#endif
};

// The CSP used for all non-signing operations
static HCRYPTPROV base_prov;

// The provider type of the best available CSP
static DWORD prov_type;

// Since using an RSA key for signing must be done via the provider and
// not directly with the key, each is in its own key container with its
// own separate provider.  The user passes in the key to sign with, and this
// list matches the key with the provider that has access to it for signing.
static struct private_key_list_t private_key_list[MAXLIST];

// Since symmetric keys and hmac keys get an HCRYPTKEY associated with them,
// the first time the user wants to use a key a HCRYPTKEY is created.  Then
// on subsequent uses the associated HCRYPTKEY is looked up so it doesn't
// have to be created and destroyed every time it's used.
static struct key_list_t symmetric_keys[MAXLIST], hmac_keys[MAXLIST];

static int machine_keyset = 0;

/**
 * Prints Microsoft specific error messages to log
 */
static void mserror(const char *str)
{
    char errbuf[300];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                  0, errbuf, sizeof(errbuf), NULL);
    clog0(0, 0, 0, "%s: (0x%08X) %s", str, GetLastError(), errbuf);
}

static int init_done = 0;

/**
 * Performs all necessary steps to initialize the crypto library
 */
void crypto_init(int set_sys_key)
{
    DWORD tmp_prov_type, name_len;
    int cnt, found_aes, i;

    // First see if we have an AES capable provider.
    // If so, use that, otherwise use one without.
#ifdef PROV_RSA_AES
    found_aes = 0;
    cnt = 0;
    name_len = 0;
    while (CryptEnumProviderTypes(cnt, 0, 0, &tmp_prov_type, NULL, &name_len) &&
           (!found_aes)) {
        if (tmp_prov_type == PROV_RSA_AES) {
            found_aes = 1;
        }
        cnt++;
        name_len = 0;
    }
    if ((!found_aes) && (GetLastError() != ERROR_NO_MORE_ITEMS)) {
        mserror("CryptEnumProviderTypes failed");
        exit(ERR_CRYPTO);
    }
    prov_type = (found_aes ? PROV_RSA_AES : PROV_RSA_FULL);
#else
    prov_type = PROV_RSA_FULL;
#endif

    if (set_sys_key) {
        machine_keyset = CRYPT_MACHINE_KEYSET;
    } else {
        machine_keyset = 0;
    }
    if (!CryptAcquireContext(&base_prov, NULL, NULL, prov_type,
            CRYPT_VERIFYCONTEXT | machine_keyset)) {
        mserror("CryptAcquireContext failed");
        exit(ERR_CRYPTO);
    }

    for (i = 0; i < MAXLIST; i++) {
        memset(&private_key_list[i], 0, sizeof(private_key_list[i]));
        memset(&symmetric_keys[i], 0, sizeof(symmetric_keys[i]));
        memset(&hmac_keys[i], 0, sizeof(hmac_keys[i]));
    }
    init_done = 1;
}

/**
 * Performs all necessary steps to clean up the crypto library
 */
void crypto_cleanup(void)
{
    int i;

    if (!init_done) {
        return;
    }
    for (i = 0; i < MAXLIST; i++) {
        if (private_key_list[i].provider != 0) {
            // Cleanup of private (and public) keys should be done by caller,
            // since they have a handle to the key under CryptoAPI and OpenSSL
            if (!CryptReleaseContext(private_key_list[i].provider, 0)) {
                mserror("CryptReleaseContext failed");
            }
        }
        if (symmetric_keys[i].keylen != 0) {
            if (!CryptDestroyKey(symmetric_keys[i].mskey)) {
                mserror("CryptDestroyKey failed");
            }
        }
        if (hmac_keys[i].keylen != 0) {
            if (!CryptDestroyKey(hmac_keys[i].mskey)) {
                mserror("CryptDestroyKey failed");
            }
        }
    }
    if (!CryptReleaseContext(base_prov, 0)) {
        mserror("CryptReleaseContext failed");
    }
}

/**
 * Returns the next key container for the current user
 */
const char *get_next_container(void)
{
    static int flag = CRYPT_FIRST;
    static char *item = NULL;
    static int mlen = 0;
    int rval, len;

    if (flag == CRYPT_FIRST) {
        rval = CryptGetProvParam(base_prov, PP_ENUMCONTAINERS, NULL,
                                 &mlen, CRYPT_FIRST);
        if (!rval) {
            return NULL;
        }
        item = safe_malloc(mlen);
    }
    len = mlen;
    rval = CryptGetProvParam(base_prov, PP_ENUMCONTAINERS, item, &len, flag);
    if (!rval) {
        if (GetLastError() != ERROR_NO_MORE_ITEMS) {
            mserror("CryptGetProvParam failed");
        }
        flag = CRYPT_FIRST;
        free(item);
        item = NULL;
        return NULL;
    }
    flag = CRYPT_NEXT;
    return item;
}

/**
 * Deletes the key container with the given name
 */
void delete_container(const char *name)
{
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, name, NULL, prov_type,
            CRYPT_DELETEKEYSET | machine_keyset)) {
        mserror("CryptAcquireContext for delete failed");
    }
}

/**
 * Returns the ALG_ID associated with a given keytype
 */
static ALG_ID get_cipher(int keytype)
{
    switch (keytype) {
    case KEY_DES:
        return CALG_DES;
    case KEY_DES_EDE3:
        return CALG_3DES;
    case KEY_AES128_CBC:
#ifdef CALG_AES_128
        return CALG_AES_128;
#else
        return 0;
#endif
    case KEY_AES256_CBC:
#ifdef CALG_AES_256
        return CALG_AES_256;
#else
        return 0;
#endif
    case KEY_AES128_GCM:
    case KEY_AES256_GCM:
    case KEY_AES128_CCM:
    case KEY_AES256_CCM:
        // Not supported by CryptoAPI
        return 0;
    default:
        log0(0, 0, 0, "Unknown keytype: %d", keytype);
        return 0;
    }
}

/**
 * Returns the ALG_ID associated with a given hashtype
 */
static ALG_ID get_hash(int hashtype)
{
    switch (hashtype) {
    case HASH_SHA256:
#ifdef CALG_SHA_256
        return CALG_SHA_256;
#else
        return 0;
#endif
    case HASH_SHA1:
        return CALG_SHA1;
    case HASH_MD5:
        return CALG_MD5;
    default:
        log0(0, 0, 0, "Unknown hashtype: %d", hashtype);
        return 0;
    }
}

/**
 * Returns whether a particular ALG_ID is available in the current CSP
 */
static int alg_found(ALG_ID alg)
{
    PROV_ENUMALGS alg_info;
    int alg_info_len, flag, found_alg;

    found_alg = 0;
    alg_info_len = sizeof(alg_info);
    flag = CRYPT_FIRST;
    while (CryptGetProvParam(base_prov, PP_ENUMALGS, (BYTE *)&alg_info,
            &alg_info_len, flag) && (!found_alg)) {
        if (alg_info.aiAlgid == alg) {
            found_alg = 1;
        }
        alg_info_len = sizeof(alg_info);
        flag = CRYPT_NEXT;
    }
    if (!found_alg) {
        if (GetLastError() != ERROR_NO_MORE_ITEMS) {
            mserror("CryptGetProvParam failed");
        }
        return 0;
    } else {
        return 1;
    }
}

/**
 * Returns whether a particular cipher is supported
 */
int cipher_supported(int keytype)
{
    ALG_ID alg;
    if ((alg = get_cipher(keytype)) == 0) {
        return 0;
    }
    return alg_found(alg);
}

/**
 * Returns whether a particular hash is supported
 */
int hash_supported(int hashtype)
{
    ALG_ID alg;
    if ((alg = get_hash(hashtype)) == 0) {
        return 0;
    }
    return alg_found(alg);
}

/**
 * Gets the key length and IV/block length of a given key
 */
void get_key_info(int keytype, int *keylen, int *ivlen)
{
    ALG_ID alg;
    int numkeys, i;

    alg = get_cipher(keytype);
    numkeys = sizeof(keyinfo) / sizeof(struct keyinfo_t);
    for (i = 0; i < numkeys; i++) {
        if (alg == keyinfo[i].alg) {
            *keylen = keyinfo[i].keysize;
            *ivlen = keyinfo[i].blocksize;
            return;
        }
    }
    *keylen = 0;
    *ivlen = 0;
}

/**
 * Gets the length of the given hash
 */
int get_hash_len(int hashtype)
{
    ALG_ID alg;
    int numhash, i;

    alg = get_hash(hashtype);
    numhash = sizeof(hashinfo) / sizeof(struct hashinfo_t);
    for (i = 0; i < numhash; i++) {
        if (alg == hashinfo[i].alg) {
            return hashinfo[i].hashsize;
        }
    }
    return 0;
}

/**
 * Gets num cryptographically random bytes
 */
int get_random_bytes(unsigned char *buf, int num)
{
    int rval;

    if (!(rval = CryptGenRandom(base_prov, num, buf))) {
        mserror("Error getting random bytes");
    }
    return rval;
}

/**
 * Takes a block of data and encrypts it with a symmetric cypher.
 * The output buffer must be at least the size of source data + block size.
 */
int encrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    // TODO: right now we reimport the key each time.  Test to see if this
    // is quick enough or if we need to cache an imported key.
    HCRYPTKEY hckey;
    char keyblob[BLOBLEN];
    BLOBHEADER *bheader;
    DWORD *keysize;
    BYTE *keydata;
    int bloblen, keylen, ivlen, rval;
    ALG_ID alg;
    DWORD mode, _destlen;

    get_key_info(keytype, &keylen, &ivlen);
    alg = get_cipher(keytype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid keytype");
        return 0;
    }

    bheader = (BLOBHEADER *)keyblob;
    keysize = (DWORD *)(keyblob + sizeof(BLOBHEADER));
    keydata = (BYTE *)((char *)keysize + sizeof(DWORD));

    memset(keyblob, 0, sizeof(keyblob));
    bheader->bType = PLAINTEXTKEYBLOB;
    bheader->bVersion = CUR_BLOB_VERSION;
    bheader->aiKeyAlg = alg;
    *keysize = keylen;
    memcpy(keydata, key, keylen);
    bloblen = sizeof(BLOBHEADER) + sizeof(DWORD) + keylen;

    if (!CryptImportKey(base_prov, keyblob, bloblen, 0, 0, &hckey)) {
        mserror("CryptImportKey failed");
        return 0;
    }

    mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hckey, KP_MODE, (BYTE *)&mode, 0)) {
        mserror("CryptSetKeyParam failed on KP_MODE");
        rval = 0;
        goto end;
    }
    if (!CryptSetKeyParam(hckey, KP_IV, IV, 0)) {
        mserror("CryptSetKeyParam failed on KP_IV");
        rval = 0;
        goto end;
    }
    memcpy(dest, src, srclen);
    _destlen = srclen;
    if (!CryptEncrypt(hckey, 0, 1, 0, dest, &_destlen, srclen + ivlen)) {
        mserror("CryptEncrypt failed");
        rval = 0;
        goto end;
    }
    *destlen = _destlen;
    rval = 1;

end:
    if (!CryptDestroyKey(hckey)) {
        mserror("CryptDestroyKey failed");
    }
    return rval;
}

/**
 * Takes a block of data encrypted with a symmetric cypher and decrypts it.
 * The output buffer must be at least the size of source data.
 */
int decrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen)
{
    // TODO: right now we reimport the key each time.  Test to see if this
    // is quick enough or if we need to cache an imported key.
    HCRYPTKEY hckey;
    char keyblob[BLOBLEN];
    BLOBHEADER *bheader;
    DWORD *keysize;
    BYTE *keydata;
    int bloblen, keylen, ivlen, rval;
    ALG_ID alg;
    DWORD mode, _destlen;

    get_key_info(keytype, &keylen, &ivlen);
    alg = get_cipher(keytype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid keytype");
        return 0;
    }

    bheader = (BLOBHEADER *)keyblob;
    keysize = (DWORD *)(keyblob + sizeof(BLOBHEADER));
    keydata = (BYTE *)((char *)keysize + sizeof(DWORD));

    memset(keyblob, 0, sizeof(keyblob));
    bheader->bType = PLAINTEXTKEYBLOB;
    bheader->bVersion = CUR_BLOB_VERSION;
    bheader->aiKeyAlg = alg;
    *keysize = keylen;
    memcpy(keydata, key, keylen);
    bloblen = sizeof(BLOBHEADER) + sizeof(DWORD) + keylen;

    if (!CryptImportKey(base_prov, keyblob, bloblen, 0, 0, &hckey)) {
        mserror("CryptImportKey failed");
        return 0;
    }

    mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hckey, KP_MODE, (BYTE *)&mode, 0)) {
        mserror("CryptSetKeyParam failed on KP_MODE");
        rval = 0;
        goto end;
    }
    if (!CryptSetKeyParam(hckey, KP_IV, IV, 0)) {
        mserror("CryptSetKeyParam failed on KP_IV");
        rval = 0;
        goto end;
    }
    memcpy(dest, src, srclen);
    _destlen = srclen;
    if (!CryptDecrypt(hckey, 0, 1, 0, dest, &_destlen)) {
        mserror("CryptDecrypt failed");
        rval = 0;
        goto end;
    }
    *destlen = _destlen;
    rval = 1;

end:
    if (!CryptDestroyKey(hckey)) {
        mserror("CryptDestroyKey failed");
    }
    return rval;
}

/**
 * Calculates the HMAC of the given message, hashtype, and hashkey.
 * dest must be at least the hash length.
 */
int create_hmac(int hashtype, const unsigned char *key, unsigned int keylen,
                const unsigned char *src, unsigned int srclen,
                unsigned char *dest, unsigned int *destlen)
{
    // TODO: right now we reimport the hmac key each time.  Test to see if this
    // is quick enough or if we need to cache an imported hmac key.
    HCRYPTKEY hmackey;
    HCRYPTHASH hash;
    char keyblob[BLOBLEN];
    BLOBHEADER *bheader;
    DWORD *keysize;
    BYTE *keydata;
    HMAC_INFO info;
    ALG_ID alg;
    int bloblen, hashlen, rval;
    DWORD _destlen;

    hashlen = get_hash_len(hashtype);
    alg = get_hash(hashtype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }

    bheader = (BLOBHEADER *)keyblob;
    keysize = (DWORD *)(keyblob + sizeof(BLOBHEADER));
    keydata = (BYTE *)((char *)keysize + sizeof(DWORD));

    memset(keyblob, 0, sizeof(keyblob));
    bheader->bType = PLAINTEXTKEYBLOB;
    bheader->bVersion = CUR_BLOB_VERSION;
    bheader->aiKeyAlg = CALG_RC2;
    *keysize = keylen;
    memcpy(keydata, key, keylen);
    bloblen = sizeof(BLOBHEADER) + sizeof(DWORD) + hashlen;

    if (!CryptImportKey(base_prov, keyblob, bloblen, 0,
                        CRYPT_IPSEC_HMAC_KEY, &hmackey)) {
        mserror("CryptImportKey failed");
        return 0;
    }

    if (!CryptCreateHash(base_prov, CALG_HMAC, hmackey, 0, &hash)) {
        mserror("CryptCreateHash failed");
        rval = 0;
        goto end1;
    }
    memset(&info, 0, sizeof(info));
    info.HashAlgid = alg;
    if (!CryptSetHashParam(hash, HP_HMAC_INFO, (BYTE *)&info, 0)) {
        mserror("CryptSetHashParam failed");
        rval = 0;
        goto end2;
    }
    if (!CryptHashData(hash, src, srclen, 0)) {
        mserror("CryptHashData failed");
        rval = 0;
        goto end2;
    }
    _destlen = hashlen;
    if (!CryptGetHashParam(hash, HP_HASHVAL, dest, &_destlen, 0)) {
        mserror("CryptGetHashParam failed");
        rval = 0;
        goto end2;
    }
    *destlen = _destlen;
    rval = 1;

end2:
    if (!CryptDestroyHash(hash)) {
        mserror("CryptDestroyHash failed");
    }
end1:
    if (!CryptDestroyKey(hmackey)) {
        mserror("CryptDestroyKey failed");
    }
    return rval;
}

/**
 * Calculates the hash of the given message and hashtype
 */
int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen)
{
    HCRYPTHASH hash;
    ALG_ID alg;
    int hashlen, rval;
    DWORD _destlen;

    hashlen = get_hash_len(hashtype);
    alg = get_hash(hashtype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }

    if (!CryptCreateHash(base_prov, alg, 0, 0, &hash)) {
        mserror("CryptCreateHash failed");
        return 0;
    }
    if (!CryptHashData(hash, src, srclen, 0)) {
        mserror("CryptHashData failed");
        rval = 0;
        goto end;
    }
    _destlen = hashlen;
    if (!CryptGetHashParam(hash, HP_HASHVAL, dest, &_destlen, 0)) {
        mserror("CryptGetHashParam failed");
        rval = 0;
        goto end;
    }
    *destlen = _destlen;
    rval = 1;

end:
    if (!CryptDestroyHash(hash)) {
        mserror("CryptDestroyHash failed");
    }
    return rval;
}

/**
 * Returns the length in bytes of the modulus for the given RSA key
 */
int RSA_keylen(const RSA_key_t rsa)
{
    DWORD keylen, bsize;

    bsize = sizeof(keylen);
    if (!CryptGetKeyParam(rsa, KP_KEYLEN, (BYTE *)&keylen, &bsize, 0)) {
        mserror("CryptGetKeyParam failed");
        return 0;
    }
    return keylen / 8;
}

int EC_keylen(const EC_key_t ec)
{
    log0(0, 0, 0, "EC not supported");
    return 0;
}

int ECDSA_siglen(const EC_key_t ec)
{
    log0(0, 0, 0, "ECDSA not supported");
    return 0;
}

/**
 * Encrypts a small block of data with an RSA public key.
 * Output buffer must be at least the key size.
 */
int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    DWORD _tolen;
    int flags;
    unsigned int i;
    unsigned char *outbuf;

    if (RSA_keylen(rsa) * 8 < 768) {
        flags = 0;
    } else {
        flags = CRYPT_OAEP;
    }

    outbuf = safe_calloc(RSA_keylen(rsa), 1);
    memcpy(outbuf, from, fromlen);
    _tolen = fromlen;
    if (!CryptEncrypt(rsa, 0, 1, flags, outbuf, &_tolen, RSA_keylen(rsa))) {
        mserror("CryptEncrypt failed");
        free(outbuf);
        return 0;
    }
    *tolen = _tolen;

    // CryptoAPI returns ciphertext in little endian, so reverse the bytes
    for (i = 0; i < _tolen; i++) {
        to[i] = outbuf[_tolen - i - 1];
    }

    free(outbuf);
    return 1;
}

/**
 * Decrypts a small block of data with an RSA private key.
 */
int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    DWORD _tolen;
    int flags;
    unsigned int i;

    if (RSA_keylen(rsa) * 8 < 768) {
        flags = 0;
    } else {
        flags = CRYPT_OAEP;
    }

    // CryptoAPI expects ciphertext in little endian, so reverse the bytes
    for (i = 0; i < fromlen; i++) {
        to[i] = from[fromlen - i - 1];
    }
    _tolen = fromlen;
    if (!CryptDecrypt(rsa, 0, 1, flags, to, &_tolen)) {
        mserror("CryptDecrypt failed");
        return 0;
    }
    *tolen = _tolen;

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
    HCRYPTHASH hash;
    DWORD _siglen;
    int idx, found;
    ALG_ID alg;
    int hashlen, rval;
    unsigned int i;
    unsigned char *outsig;

    for (idx = 0, found = 0; (idx < MAXLIST) && (!found); idx++) {
        if (private_key_list[idx].key == rsa) {
            found = 1;
        }
    }
    if (!found) {
        log0(0, 0, 0, "Couldn't find provider for RSA key");
        return 0;
    }
    idx--;

    hashlen = get_hash_len(hashtype);
    alg = get_hash(hashtype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }

    if (!CryptCreateHash(private_key_list[idx].provider, alg, 0, 0, &hash)) {
        mserror("CryptCreateHash failed");
        return 0;
    }
    if (!CryptHashData(hash, mes, meslen, 0)) {
        mserror("CryptHashData failed");
        rval = 0;
        goto end;
    }

    _siglen = RSA_keylen(rsa);
    outsig = safe_calloc(_siglen, 1);
    if (!CryptSignHash(hash, AT_KEYEXCHANGE, NULL, 0, outsig, &_siglen)) {
        mserror("CryptSignHash failed");
        free(outsig);
        rval = 0;
        goto end;
    }
    *siglen = _siglen;
    // CryptoAPI returns signatures in little endian, so reverse the bytes
    for (i = 0; i < _siglen; i++) {
        sig[i] = outsig[_siglen - i - 1];
    }
    free(outsig);

    rval = 1;

end:
    if (!CryptDestroyHash(hash)) {
        mserror("CryptDestroyHash failed");
    }
    return rval;
}

/**
 * Hashes a block of data and verifies it against an RSA signature.
 */
int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen)
{
    HCRYPTHASH hash;
    ALG_ID alg;
    unsigned hashlen, i;
    int rval;
    unsigned char *insig;

    hashlen = get_hash_len(hashtype);
    alg = get_hash(hashtype);
    if (alg == 0) {
        log0(0, 0, 0, "Invalid hashtype");
        return 0;
    }

    if (!CryptCreateHash(base_prov, alg, 0, 0, &hash)) {
        mserror("CryptCreateHash failed");
        return 0;
    }
    if (!CryptHashData(hash, mes, meslen, 0)) {
        mserror("CryptHashData failed");
        rval = 0;
        goto end;
    }
    insig = safe_calloc(siglen, 1);
    // CryptoAPI expects signatures in little endian, so reverse the bytes
    for (i = 0; i < siglen; i++) {
        insig[i] = sig[siglen - i - 1];
    }
    if (!CryptVerifySignature(hash, insig, siglen, rsa, NULL, 0)) {
        mserror("CryptVerifySignature failed");
        free(insig);
        rval = 0;
        goto end;
    }
    free(insig);

    rval = 1;

end:
    if (!CryptDestroyHash(hash)) {
        mserror("CryptDestroyHash failed");
    }
    return rval;
}

int create_ECDSA_sig(EC_key_t rsa, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     unsigned char *sig, unsigned int *siglen)
{
    log0(0, 0, 0, "ECDSA not supported");
    return 0;
}

int verify_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     const unsigned char *sig, unsigned int siglen)
{
    log0(0, 0, 0, "ECDSA not supported");
    return 0;
}

int get_ECDH_key(EC_key_t pubkey, EC_key_t privkey, unsigned char *key,
                 unsigned int *keylen)
{
    log0(0, 0, 0, "ECDH not supported");
    return 0;
}

/**
 * Creates an RSA public key with the given modulus and public exponent
 */
int import_RSA_key(RSA_key_t *rsa, const unsigned char *keyblob,
                   uint16_t bloblen)
{
    struct rsa_blob_t *rsablob;
    const unsigned char *modulus;
    char ms_keyblob[BLOBLEN];
    BLOBHEADER *bheader;
    RSAPUBKEY *pubkeyheader;
    BYTE *ms_blob_modulus;
    int ms_bloblen, modlen, i;

    rsablob = (struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);
    modlen = ntohs(rsablob->modlen);

    if (sizeof(struct rsa_blob_t) + modlen != bloblen) {
        log0(0, 0, 0, "Error importing RSA key: invalid length");
        return 0;
    } 

    bheader = (BLOBHEADER *)ms_keyblob;
    pubkeyheader = (RSAPUBKEY *)(ms_keyblob + sizeof(BLOBHEADER));
    ms_blob_modulus = (BYTE *)pubkeyheader + sizeof(RSAPUBKEY);

    memset(ms_keyblob, 0, sizeof(ms_keyblob));
    bheader->bType = PUBLICKEYBLOB;
    bheader->bVersion = CUR_BLOB_VERSION;
    bheader->aiKeyAlg = CALG_RSA_KEYX;
    pubkeyheader->magic = 0x31415352;
    pubkeyheader->bitlen = modlen * 8;
    pubkeyheader->pubexp = ntohl(rsablob->exponent);
    // CrypoAPI expects the modulus in little endian, so reverse the bytes
    for (i = 0; i < modlen; i++) {
        ms_blob_modulus[i] = modulus[modlen - i - 1];
    }

    ms_bloblen = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + modlen;
    if (!CryptImportKey(base_prov, ms_keyblob, ms_bloblen, 0, 0, rsa)) {
        mserror("CryptImportKey failed");
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
    char ms_keyblob[BLOBLEN];
    BLOBHEADER *bheader;
    RSAPUBKEY *pubkeyheader;
    BYTE *ms_blob_modulus;
    int ms_bloblen, i;
    uint16_t modlen;

    rsablob = (struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);

    ms_bloblen = sizeof(ms_keyblob);
    if (!CryptExportKey(rsa, 0, PUBLICKEYBLOB, 0, ms_keyblob, &ms_bloblen)) {
        mserror("CryptExportKey failed");
        return 0;
    }

    bheader = (BLOBHEADER *)ms_keyblob;
    pubkeyheader = (RSAPUBKEY *)(ms_keyblob + sizeof(BLOBHEADER));
    ms_blob_modulus = (BYTE *)pubkeyheader + sizeof(RSAPUBKEY);

    modlen = (pubkeyheader->bitlen / 8) & 0xFFFF;
    rsablob->blobtype = KEYBLOB_RSA;
    rsablob->reserved = 0;
    rsablob->modlen = htons(modlen);
    rsablob->exponent = htonl(pubkeyheader->pubexp);
    // CrypoAPI exports the modulus in little endian, so reverse the bytes
    for (i = 0; i < modlen; i++) {
        modulus[i] = ms_blob_modulus[modlen - i - 1];
    }
    *bloblen = sizeof(struct rsa_blob_t) + modlen;

    return 1;
}

int import_EC_key(EC_key_t *ec, const unsigned char *keyblob, uint16_t bloblen,
                  int isdh)
{
    log0(0, 0, 0, "EC keys not supported");
    return 0;
}

int export_EC_key(const EC_key_t ec, unsigned char *keyblob, uint16_t *bloblen)
{
    log0(0, 0, 0, "EC keys not supported");
    return 0;
}

/**
 * Generates an RSA private key with the given exponent and number of bits
 * and writes it into the specified key container
 */
RSA_key_t gen_RSA_key(int bits, int exponent, const char *container)
{
    int idx, found, flags;
    const char *_container;

    // First find available private key slot
    for (idx = 0, found = 0; (idx < MAXLIST) && (!found); idx++) {
        if (private_key_list[idx].provider == 0) {
            found = 1;
        }
    }
    if (!found) {
        log0(0, 0, 0, "Couldn't find empty key slot for private key");
        return 0;
    }
    idx--;

    if (!container || !strcmp(container, "")) {
        _container = NULL;
        flags = machine_keyset | CRYPT_VERIFYCONTEXT;
    } else {
        _container = container;
        flags = machine_keyset;
    }
    if (!CryptAcquireContext(&private_key_list[idx].provider, _container,
                             NULL, prov_type, flags)) {
        if (!CryptAcquireContext(&private_key_list[idx].provider, _container,
                    NULL, prov_type, CRYPT_NEWKEYSET | flags)) {
            mserror("CryptAcquireContext failed");
            return 0;
        }
    }

    if (!CryptGenKey(private_key_list[idx].provider, AT_KEYEXCHANGE,
                     ((bits ? bits : DEF_RSA_LEN) << 16) | CRYPT_EXPORTABLE,
                     &private_key_list[idx].key)) {
        mserror("CryptGenKey failed");
        return 0;
    }

    return private_key_list[idx].key;
}

/**
 * Loads an RSA private key from the specified key container
 */
RSA_key_t read_RSA_key(const char *container)
{
    int idx, found;

    // First find available private key slot
    for (idx = 0, found = 0; (idx < MAXLIST) && (!found); idx++) {
        if (private_key_list[idx].provider == 0) {
            found = 1;
        }
    }
    if (!found) {
        log0(0, 0, 0, "Couldn't find empty key slot for private key");
        return 0;
    }
    idx--;

    if (!CryptAcquireContext(&private_key_list[idx].provider, container,
                             NULL, prov_type, machine_keyset)) {
        mserror("CryptAcquireContext failed");
        return 0;
    }

    if (!CryptGetUserKey(private_key_list[idx].provider, AT_KEYEXCHANGE,
                         &private_key_list[idx].key)) {
        mserror("CryptGetUserKey failed");
        return 0;
    }

    return private_key_list[idx].key;
}

EC_key_t gen_EC_key(uint8_t curve, int isdh, const char *filename)
{
    log0(0, 0, 0, "EC keys not supported");
    return NULL;
}


EC_key_t read_EC_key(const char *filename)
{
    log0(0, 0, 0, "EC keys not supported");
    return NULL;
}

union key_t read_private_key(const char *filename, int *keytype)
{
    union key_t key;

    key.rsa = read_RSA_key(filename);
    if (key.rsa == 0) {
        *keytype = 0;
    } else {
        *keytype = KEYBLOB_RSA;
    }
    return key;
}


uint8_t get_EC_curve(const EC_key_t ec)
{
    log0(0, 0, 0, "EC keys not supported");
    return 0;
}

void free_RSA_key(RSA_key_t rsa)
{
    if (!CryptDestroyKey(rsa)) {
        mserror("CryptDestroyKey failed");
    }
}

void free_EC_key(EC_key_t ec)
{
    log0(0, 0, 0, "EC keys not supported");
}

void set_sys_keys(int set_sys_key)
{
    if (set_sys_key) {
        machine_keyset = CRYPT_MACHINE_KEYSET;
    } else {
        machine_keyset = 0;
    }
}
