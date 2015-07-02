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

//#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use this #define to pull in necessary declarations from uftp_common.h
// in encryption.h instead.  We don't include uftp_common.h because it contains
// an include for winsock2.h which is needed pretty much everyplace else.
// Including winsock2.h prevents BCryptEncrypt and BCryptDecrypt from working
// with GCM and CCM mode ciphers.
#define NO_UFTP_COMMON_H
#include "uftp.h"
#include "encryption.h"

#define MAXLIST 100
#define BLOBLEN 1000

static struct providers_t {
    LPCWSTR alg;
    LPCWSTR mode;
    int hmac;
    BCRYPT_ALG_HANDLE handle;
} providers[MAXLIST];

static int provlen;

static const struct keyinfo_t {
    int keytype;
    int keysize;
    int blocksize;
} keyinfo[] = {
    { KEY_DES, 8, 8 },
    { KEY_DES_EDE3, 24, 8 },
    { KEY_AES128_CBC, 16, 16 },
    { KEY_AES128_GCM, 16, 12 },
    { KEY_AES128_CCM, 16, 12 },
    { KEY_AES256_CBC, 32, 16 },
    { KEY_AES256_GCM, 32, 12 },
    { KEY_AES256_CCM, 32, 12 }
};

static int machine_keyset = 0;
static int init_done = 0;

/**
 * Prints Microsoft specific error messages to log
 */
static void mserror(const char *str, int err)
{
    char errbuf[300];
    HMODULE Hand = LoadLibrary("NTDLL.DLL");
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE |
                  FORMAT_MESSAGE_IGNORE_INSERTS, Hand, err,
                  0, errbuf, sizeof(errbuf), NULL);
    clog0(0, 0, 0, "%s: (0x%08X) %s", str, err, errbuf);
    FreeLibrary(Hand);
}

/**
 * Performs all necessary steps to initialize the crypto library
 */
void crypto_init(int set_sys_key)
{
    provlen = 0;
    if (set_sys_key) {
        machine_keyset = NCRYPT_MACHINE_KEY_FLAG;
    } else {
        machine_keyset = 0;
    }
    init_done = 1;
}

/**
 * Performs all necessary steps to clean up the crypto library
 */
void crypto_cleanup(void)
{
    NTSTATUS status;
    int i;

    if (!init_done) {
        return;
    }

    for (i = 0; i < provlen; i++) {
        status = BCryptCloseAlgorithmProvider(providers[i].handle, 0);
        if (!BCRYPT_SUCCESS(status)) {
            mserror("BCryptCloseAlgorithmProvider failed", status);
        }
    }
}

/**
 * Returns the next key for the current user
 */
const char *get_next_container(void)
{
    static NCRYPT_PROV_HANDLE prov = 0;
    static NCryptKeyName *keyitem = NULL;
    static void *ptr = NULL;
    static char name[256];
    SECURITY_STATUS sstatus;

    if (!prov) {
        sstatus = NCryptOpenStorageProvider(&prov, NULL, 0);
        if (!BCRYPT_SUCCESS(sstatus)) {
            mserror("NCryptOpenStorageProvider failed", sstatus);
            return NULL;
        }
    }
    if (keyitem) {
        NCryptFreeBuffer(keyitem);
    }
    sstatus = NCryptEnumKeys(prov, NULL, &keyitem, &ptr,
                             NCRYPT_SILENT_FLAG | machine_keyset);
    if (sstatus == ERROR_SUCCESS) {
        wcstombs(name, keyitem->pszName, sizeof(name));
        return name;
    } else {
        if (sstatus != NTE_NO_MORE_ITEMS) {
            mserror("NCryptEnumKeys failed", sstatus);
        }
        NCryptFreeBuffer(keyitem);
        keyitem = NULL;
        NCryptFreeBuffer(ptr);
        ptr = NULL;
        NCryptFreeObject(prov);
        prov = 0;
        return NULL;
    }
}

/**
 * Deletes the key container with the given name
 */
void delete_container(const char *container)
{
    NCRYPT_PROV_HANDLE prov;
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS sstatus;
    wchar_t wcontainer[256];

    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
    }
    memset(wcontainer, 0, sizeof(wcontainer));
    mbstowcs(wcontainer, container, strlen(container));
    sstatus = NCryptOpenKey(prov, &key, wcontainer, 0,
                            NCRYPT_SILENT_FLAG | machine_keyset);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptOpenKey failed", sstatus);
        NCryptFreeObject(prov);
    }
    if (!BCRYPT_SUCCESS(sstatus = NCryptDeleteKey(key, NCRYPT_SILENT_FLAG))) {
        NCryptFreeObject(prov);
        mserror("NCryptDeleteKey failed", sstatus);
    }
    NCryptFreeObject(prov);
}

/**
 * Gets an algorithm provider handle for the given hash or cipher.
 * Check the provider list to see if it exists.  If so, return it,
 * otherwise get a new one and put it in the list.
 */
static BCRYPT_ALG_HANDLE get_alg_handle(LPCWSTR alg, LPCWSTR mode, int hmac)
{
    BCRYPT_ALG_HANDLE handle;
    NTSTATUS status;
    int i;

    for (i=0; i<provlen; i++) {
        if ((providers[i].alg == alg) && (providers[i].mode == mode) &&
                (providers[i].hmac == hmac)) {
            return providers[i].handle;
        }
    }
    status = BCryptOpenAlgorithmProvider(&handle, alg, NULL,
                hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptOpenAlgorithmProvider failed", status);
        return NULL;
    }
    providers[provlen].alg = alg;
    providers[provlen].mode = mode;
    providers[provlen].hmac = hmac;
    providers[provlen].handle = handle;
    provlen++;
    return handle;
}

/**
 * Returns the cipher name associated with the given keytype
 */
static LPCWSTR get_cipher(int keytype)
{
    switch (keytype) {
    case KEY_DES:
        return BCRYPT_DES_ALGORITHM;
    case KEY_DES_EDE3:
        return BCRYPT_3DES_ALGORITHM;
    case KEY_AES128_CBC:
    case KEY_AES256_CBC:
    case KEY_AES128_GCM:
    case KEY_AES256_GCM:
    case KEY_AES128_CCM:
    case KEY_AES256_CCM:
        return BCRYPT_AES_ALGORITHM;
    default:
        log0(0, 0, 0, "Unknown keytype: %d", keytype);
        return NULL;
    }
}

/**
 * Returns the cipher mode associated with the given keytype
 */
static LPCWSTR get_cipher_mode(int keytype)
{
    switch (keytype) {
    case KEY_DES:
    case KEY_DES_EDE3:
    case KEY_AES128_CBC:
    case KEY_AES256_CBC:
        return BCRYPT_CHAIN_MODE_CBC;
    case KEY_AES128_GCM:
    case KEY_AES256_GCM:
        return BCRYPT_CHAIN_MODE_GCM;
    case KEY_AES128_CCM:
    case KEY_AES256_CCM:
        return BCRYPT_CHAIN_MODE_CCM;
    default:
        return NULL;
    }
}

/**
 * Returns the hash name associated with a given hashtype
 */
static LPCWSTR get_hash(int hashtype)
{
    switch (hashtype) {
    case HASH_SHA512:
        return BCRYPT_SHA512_ALGORITHM;
    case HASH_SHA384:
        return BCRYPT_SHA384_ALGORITHM;
    case HASH_SHA256:
        return BCRYPT_SHA256_ALGORITHM;
    case HASH_SHA1:
        return BCRYPT_SHA1_ALGORITHM;
    case HASH_MD5:
        return BCRYPT_MD5_ALGORITHM;
    default:
        log0(0, 0, 0, "Unknown hashtype: %d", hashtype);
        return NULL;
    }
}

static LPCWSTR get_curve_alg(int curve, int isdh)
{
    if (isdh) {
        switch (curve) {
        case CURVE_prime256v1:
            return BCRYPT_ECDH_P256_ALGORITHM;
        case CURVE_secp384r1:
            return BCRYPT_ECDH_P384_ALGORITHM;
        case CURVE_secp521r1:
            return BCRYPT_ECDH_P521_ALGORITHM;
        default:
            return NULL;
        }
    } else {
        switch (curve) {
        case CURVE_prime256v1:
            return BCRYPT_ECDSA_P256_ALGORITHM;
        case CURVE_secp384r1:
            return BCRYPT_ECDSA_P384_ALGORITHM;
        case CURVE_secp521r1:
            return BCRYPT_ECDSA_P521_ALGORITHM;
        default:
            return NULL;
        }
    }
}

static ULONG get_curve_magic(int curve, int isdh)
{
    if (isdh) {
        switch (curve) {
        case CURVE_prime256v1:
            return BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        case CURVE_secp384r1:
            return BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        case CURVE_secp521r1:
            return BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        default:
            return 0;
        }
    } else {
        switch (curve) {
        case CURVE_prime256v1:
            return BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        case CURVE_secp384r1:
            return BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        case CURVE_secp521r1:
            return BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
        default:
            return 0;
        }
    }
}

/**
 * Returns whether a particular algorithm of a given type is available
 */
static int alg_found(LPCWSTR alg, int type)
{
    NTSTATUS status;
    BCRYPT_ALGORITHM_IDENTIFIER *balglist;
    int count, found, i;

    status = BCryptEnumAlgorithms(type, &count, &balglist, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptEnumAlgorithms failed", status);
        return 0;
    }
    for (found = 0, i = 0; i < count; i++) {
        if (!wcscmp(alg, balglist[i].pszName)) {
            found = 1;
            break;
        }
    }
    BCryptFreeBuffer(balglist);
    return found;
}

/**
 * Returns whether a particular cipher is supported
 */
int cipher_supported(int keytype)
{
    LPCWSTR alg;
    if ((alg = get_cipher(keytype)) == NULL) {
        return 0;
    }
    return alg_found(alg, BCRYPT_CIPHER_OPERATION);
}

/**
 * Returns whether a particular hash is supported
 */
int hash_supported(int hashtype)
{
    LPCWSTR alg;
    if ((alg = get_hash(hashtype)) == NULL) {
        return 0;
    }
    return alg_found(alg, BCRYPT_HASH_OPERATION);
}

/**
 * Gets the key length and IV/block length of a given key
 */
void get_key_info(int keytype, int *keylen, int *ivlen)
{
    int numkeys, i;

    numkeys = sizeof(keyinfo) / sizeof(struct keyinfo_t);
    for (i = 0; i < numkeys; i++) {
        if (keytype == keyinfo[i].keytype) {
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
    BCRYPT_ALG_HANDLE alg;
    NTSTATUS status;
    DWORD hashlen, len;

    alg = get_alg_handle(get_hash(hashtype), NULL, 0);
    if (!alg) {
        return 0;
    }
    status = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashlen,
                               sizeof(DWORD), &len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGetProperty failed", status);
        return 0;
    }
    return hashlen;
}

/**
 * Gets num cryptographically random bytes
 */
int get_random_bytes(unsigned char *buf, int num)
{
    BCRYPT_ALG_HANDLE alg;
    NTSTATUS status;

    alg = get_alg_handle(BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!alg) {
        return 0;
    }
    status = BCryptGenRandom(alg, buf, num, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGenRandom failed", status);
        return 0;
    }
    return 1;
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
    BCRYPT_ALG_HANDLE alghandle = NULL;
    BCRYPT_KEY_HANDLE keyhandle = NULL;
    LPCWSTR alg, mode;
    NTSTATUS status;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo, *pauthinfo;
    unsigned char *l_IV, *p_IV;
    int keylen, ivlen, taglen, flags, l_ivlen;

    alg = get_cipher(keytype);
    get_key_info(keytype, &keylen, &ivlen);
    mode = get_cipher_mode(keytype);

    if ((alghandle = get_alg_handle(alg, mode, 0)) == NULL) {
        log0(0, 0, 0, "get_alg_handle failed\n");
        return 0;
    }
    status = BCryptSetProperty(alghandle, BCRYPT_CHAINING_MODE, (PUCHAR)mode,
                               sizeof(mode), 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptSetProperty failed", status);
        return 0;
    }
    status = BCryptGenerateSymmetricKey(alghandle, &keyhandle, NULL, 0,
                                        (PUCHAR)key, keylen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGenerateSymmetricKey failed", status);
        return 0;
    }
    l_IV = safe_calloc(ivlen, 1);
    memcpy(l_IV, IV, ivlen);

    taglen = is_gcm_mode(keytype) ? GCM_TAG_LEN :
             is_ccm_mode(keytype) ? CCM_TAG_LEN : 0;
    if (is_auth_enc(keytype)) {
        BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
        authinfo.pbNonce = l_IV;
        authinfo.cbNonce = ivlen;
        authinfo.pbAuthData = (unsigned char *)aad;
        authinfo.cbAuthData = aadlen;
        authinfo.pbTag = dest + srclen;
        authinfo.cbTag = taglen;
        authinfo.pbMacContext = NULL;
        authinfo.cbMacContext = 0;
        authinfo.cbAAD = 0;
        authinfo.cbData = 0;
        authinfo.dwFlags = 0;
        pauthinfo = &authinfo;
        flags = 0;
        p_IV = NULL;
        l_ivlen = 0;
    } else {
        pauthinfo = NULL;
        flags = BCRYPT_BLOCK_PADDING;
        p_IV = l_IV;
        l_ivlen = ivlen;
    }

    status = BCryptEncrypt(keyhandle, (PUCHAR)src, srclen, pauthinfo,
                p_IV, l_ivlen, dest, srclen + GCM_TAG_LEN, destlen, flags);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptEncrypt failed", status);
        free(l_IV);
        return 0;
    }
    free(l_IV);
    *destlen += taglen;

    if (!BCRYPT_SUCCESS(status = BCryptDestroyKey(keyhandle))) {
        mserror("BCryptDestroyKey failed", status);
    }
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
    BCRYPT_ALG_HANDLE alghandle = NULL;
    BCRYPT_KEY_HANDLE keyhandle = NULL;
    LPCWSTR alg, mode;
    NTSTATUS status;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo, *pauthinfo;
    unsigned char *l_IV, *p_IV;
    int keylen, ivlen, taglen, flags, l_ivlen;

    alg = get_cipher(keytype);
    get_key_info(keytype, &keylen, &ivlen);
    mode = get_cipher_mode(keytype);

    if ((alghandle = get_alg_handle(alg, mode, 0)) == NULL) {
        log0(0, 0, 0, "get_alg_handle failed\n");
        return 0;
    }
    status = BCryptSetProperty(alghandle, BCRYPT_CHAINING_MODE, (PUCHAR)mode, 
                               sizeof(mode), 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptSetProperty failed", status);
        return 0;
    }
    status = BCryptGenerateSymmetricKey(alghandle, &keyhandle, NULL, 0,
                                        (PUCHAR)key, keylen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGenerateSymmetricKey failed", status);
        return 0;
    }
    l_IV = safe_calloc(ivlen, 1);
    memcpy(l_IV, IV, ivlen);

    taglen = is_gcm_mode(keytype) ? GCM_TAG_LEN :
             is_ccm_mode(keytype) ? CCM_TAG_LEN : 0;
    if (is_auth_enc(keytype)) {
        BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
        authinfo.pbNonce = l_IV;
        authinfo.cbNonce = ivlen;
        authinfo.pbAuthData = (unsigned char *)aad;
        authinfo.cbAuthData = aadlen;
        authinfo.pbTag = (unsigned char *)src + srclen - taglen;
        authinfo.cbTag = taglen;
        authinfo.pbMacContext = NULL;
        authinfo.cbMacContext = 0;
        authinfo.cbAAD = 0;
        authinfo.cbData = 0;
        authinfo.dwFlags = 0;
        pauthinfo = &authinfo;
        flags = 0;
        p_IV = NULL;
        l_ivlen = 0;
    } else {
        pauthinfo = NULL;
        flags = BCRYPT_BLOCK_PADDING;
        p_IV = l_IV;
        l_ivlen = ivlen;
    }
    status = BCryptDecrypt(keyhandle, (PUCHAR)src, srclen - taglen, pauthinfo,
                p_IV, l_ivlen, dest, srclen + GCM_TAG_LEN, destlen, flags);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptDecrypt failed", status);
        free(l_IV);
        return 0;
    }
    free(l_IV);

    if (!BCRYPT_SUCCESS(status = BCryptDestroyKey(keyhandle))) {
        mserror("BCryptDestroyKey failed", status);
    }
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
    BCRYPT_ALG_HANDLE alghandle = NULL;
    BCRYPT_HASH_HANDLE hashhandle = NULL;
    LPCWSTR alg;
    NTSTATUS status;
    DWORD _destlen, rlen;

    alg = get_hash(hashtype);
    if ((alghandle = get_alg_handle(alg, NULL, 1)) == NULL) {
        log0(0, 0, 0, "get_alg_handle failed\n");
        return 0;
    }
    status = BCryptGetProperty(alghandle, BCRYPT_HASH_LENGTH,
                               (char *)&_destlen, sizeof(destlen), &rlen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGetProperty failed", status);
        return 0;
    }
    status = BCryptCreateHash(alghandle, &hashhandle, NULL, 0,
                              (char *)key, keylen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptCreateHash failed", status);
        return 0;
    }
    status = BCryptHashData(hashhandle, (PUCHAR)src, srclen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptHashData failed", status);
        return 0;
    }
    status = BCryptFinishHash(hashhandle, dest, _destlen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptFinishHash failed", status);
        return 0;
    }
    *destlen = _destlen;

    if (!BCRYPT_SUCCESS(status = BCryptDestroyHash(hashhandle))) {
        mserror("BCryptDestroyHash failed", status);
    }
    return 1;
}

/**
 * Calculates the hash of the given message and hashtype
 */
int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen)
{
    BCRYPT_ALG_HANDLE alghandle = NULL;
    BCRYPT_HASH_HANDLE hashhandle = NULL;
    LPCWSTR alg;
    NTSTATUS status;
    DWORD _destlen, rlen;

    alg = get_hash(hashtype);
    if ((alghandle = get_alg_handle(alg, NULL, 0)) == NULL) {
        log0(0, 0, 0, "get_alg_handle failed\n");
        return 0;
    }
    status = BCryptGetProperty(alghandle, BCRYPT_HASH_LENGTH,
                               (char *)&_destlen, sizeof(destlen), &rlen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptGetProperty failed", status);
        return 0;
    }
    status = BCryptCreateHash(alghandle, &hashhandle, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptCreateHash failed", status);
        return 0;
    }
    status = BCryptHashData(hashhandle, (PUCHAR)src, srclen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptHashData failed", status);
        return 0;
    }
    status = BCryptFinishHash(hashhandle, dest, _destlen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        mserror("BCryptFinishHash failed", status);
        return 0;
    }
    *destlen = _destlen;

    if (!BCRYPT_SUCCESS(status = BCryptDestroyHash(hashhandle))) {
        mserror("BCryptDestroyHash failed", status);
    }
    return 1;
}

/**
 * Returns the length in bytes of the modulus for the given RSA key
 */
int RSA_keylen(const RSA_key_t rsa)
{
    int bits, len;
    SECURITY_STATUS sstatus;

    sstatus = NCryptGetProperty(rsa, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits,
                                sizeof(bits), &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptGetProperty failed", sstatus);
        return 0;
    }
    return bits / 8;
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
    SECURITY_STATUS sstatus;
    int len, padding;

    sstatus = NCryptExportKey(ec, (NCRYPT_KEY_HANDLE)NULL,
                BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptExportKey failed", sstatus);
        return 0;
    }

    len -= sizeof(BCRYPT_ECCKEY_BLOB);
    if ((len % 4) == 0) {
        padding = 0;
    } else {
        padding = 4 - (len % 4);
    }
    
    return len + padding;
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
    return sizeof(uint16_t) + sizeof(uint16_t) + EC_keylen(ec);
}

/**
 * Encrypts a small block of data with an RSA public key.
 * Output buffer must be at least the key size.
 */
int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    SECURITY_STATUS sstatus;
    BCRYPT_OAEP_PADDING_INFO pad, *ppad;
    int keylen, _tolen, flags;

    keylen = RSA_keylen(rsa);
    if (keylen * 8 < 768) {
        flags = NCRYPT_PAD_PKCS1_FLAG;
        ppad = NULL;
    } else {
        flags = NCRYPT_PAD_OAEP_FLAG;
        ppad = &pad;
        pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
        pad.pbLabel = NULL;
        pad.cbLabel = 0;
    }

    _tolen = keylen * ((fromlen / keylen) + 1);
    sstatus = NCryptEncrypt(rsa, (PUCHAR)from, fromlen, ppad, to, _tolen,
                            &_tolen, flags);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptEncrypt failed", sstatus);
        return 0;
    }
    *tolen = _tolen;
    return 1;
}

/**
 * Decrypts a small block of data with an RSA private key.
 */
int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen)
{
    SECURITY_STATUS sstatus;
    BCRYPT_OAEP_PADDING_INFO pad, *ppad;
    int _tolen, flags;

    if (RSA_keylen(rsa) * 8 < 768) {
        flags = NCRYPT_PAD_PKCS1_FLAG;
        ppad = NULL;
    } else {
        flags = NCRYPT_PAD_OAEP_FLAG;
        ppad = &pad;
        pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
        pad.pbLabel = NULL;
        pad.cbLabel = 0;
    }

    _tolen = fromlen;
    sstatus = NCryptDecrypt(rsa, (PUCHAR)from, fromlen, ppad, to, _tolen,
                            &_tolen, flags);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptDecrypt failed", sstatus);
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
    SECURITY_STATUS sstatus;
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen, _siglen;
    BCRYPT_PKCS1_PADDING_INFO padding;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    padding.pszAlgId = get_hash(hashtype);
    _siglen = RSA_keylen(rsa);
    sstatus = NCryptSignHash(rsa, &padding, meshash, meshashlen, sig, _siglen,
                             &_siglen, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptSignHash failed", sstatus);
        return 0;
    }
    *siglen = _siglen;
    return 1;
}

/**
 * Hashes a block of data and verifies it against an RSA signature.
 */
int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen)
{
    SECURITY_STATUS sstatus;
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    BCRYPT_PKCS1_PADDING_INFO padding;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    padding.pszAlgId = get_hash(hashtype);
    sstatus = NCryptVerifySignature(rsa, &padding, meshash, meshashlen, sig,
                                    siglen, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptVerifySignature failed", sstatus);
        return 0;
    }
    return 1;
}

/**
 * Hashes a block of data and signs it with an ECDSA private key.
 * Output buffer must be at least ECDSA_siglen bytes.
 */
int create_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     unsigned char *sig, unsigned int *siglen)
{
    SECURITY_STATUS sstatus;
    unsigned char meshash[HMAC_LEN], *buf;
    unsigned int meshashlen, _siglen;
    uint16_t *rlen, *slen;
    unsigned char *rsval;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    sstatus = NCryptSignHash(ec, NULL, meshash, meshashlen, NULL, 0,
                                &_siglen, 0);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptSignHash failed", sstatus);
        return 0;
    }
    buf = safe_malloc(_siglen);
    sstatus = NCryptSignHash(ec, NULL, meshash, meshashlen, buf, _siglen,
                             &_siglen, 0);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptSignHash failed", sstatus);
        free(buf);
        return 0;
    }

    rlen = (uint16_t *)sig;
    slen = (uint16_t *)(sig + sizeof(uint16_t));
    rsval = (unsigned char *)slen + sizeof(uint16_t);

    *siglen = ECDSA_siglen(ec);
    memset(sig, 0, *siglen);
    *rlen = htons((uint16_t)_siglen / 2);
    *slen = htons((uint16_t)_siglen / 2);
    memcpy(rsval, buf, _siglen);
    free(buf);
    return 1;
}

/**
 * Hashes a block of data and verifies it against an ECDSA signature.
 */
int verify_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     const unsigned char *sig, unsigned int siglen)
{
    SECURITY_STATUS sstatus;
    unsigned char meshash[HMAC_LEN];
    unsigned int meshashlen;
    uint16_t *rlen, *slen;
    unsigned char *rsval;

    if (!hash(hashtype, mes, meslen, meshash, &meshashlen)) {
        return 0;
    }

    rlen = (uint16_t *)sig;
    slen = (uint16_t *)(sig + sizeof(uint16_t));
    rsval = (unsigned char *)slen + sizeof(uint16_t);
    if ((unsigned int)ntohs(*rlen) + ntohs(*slen) > siglen) {
        log0(0, 0, 0, "Invalid signature length");
        return 0;
    }

    sstatus = NCryptVerifySignature(ec, NULL, meshash, meshashlen, rsval,
                                    ntohs(*rlen) + ntohs(*slen), 0);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptVerifySignature failed", sstatus);
        return 0;
    }
    return 1;
}

/**
 * Creates an ECDH key based on two EC keys, one public and one private
 */
int get_ECDH_key(EC_key_t pubkey, EC_key_t privkey, unsigned char *key,
                 unsigned int *keylen)
{
    SECURITY_STATUS sstatus;
    NCRYPT_SECRET_HANDLE secret;
    int _len;

    sstatus = NCryptSecretAgreement(privkey, pubkey, &secret, 0);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptSecretAgreement failed", sstatus);
        return 0;
    }
    sstatus = NCryptDeriveKey(secret, BCRYPT_KDF_HASH, NULL, NULL, 0, &_len, 0);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptDeriveKey failed", sstatus);
        return 0;
    }
    sstatus = NCryptDeriveKey(secret, BCRYPT_KDF_HASH, NULL, key, _len,
                              keylen, 0 );
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptDeriveKey failed", sstatus);
        return 0;
    }
    return 1;
}

/**
 * Imports an RSA keyblob into an RSA public key
 */
int import_RSA_key(RSA_key_t *rsa, const unsigned char *keyblob,
                   uint16_t bloblen)
{
    SECURITY_STATUS sstatus;
    NCRYPT_PROV_HANDLE prov;
    BCRYPT_RSAKEY_BLOB *blobheader;
    char *buf, *buf_exp, *buf_mod;
    int buflen;
    const struct rsa_blob_t *rsablob;
    const unsigned char *modulus;

    rsablob = (struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);

    if (sizeof(struct rsa_blob_t) + ntohs(rsablob->modlen) != bloblen) {
        log0(0, 0, 0, "Error importing RSA key: invalid length");
        return 0;
    } 

    buflen = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rsablob->exponent) +
                ntohs(rsablob->modlen);
    buf = safe_calloc(buflen, 1);

    blobheader = (BCRYPT_RSAKEY_BLOB *)buf;
    buf_exp = buf + sizeof(BCRYPT_RSAKEY_BLOB);
    buf_mod = buf_exp + sizeof(rsablob->exponent);
    blobheader->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blobheader->BitLength = ntohs(rsablob->modlen) * 8;
    blobheader->cbPublicExp = sizeof(rsablob->exponent);
    blobheader->cbModulus = ntohs(rsablob->modlen);
    buf_exp[0] = (char)((ntohl(rsablob->exponent) & 0xFF000000) >> 24);
    buf_exp[1] = (char)((ntohl(rsablob->exponent) & 0x00FF0000) >> 16);
    buf_exp[2] = (char)((ntohl(rsablob->exponent) & 0x0000FF00) >> 8);
    buf_exp[3] = (char)(ntohl(rsablob->exponent) & 0x000000FF);
    memcpy(buf_mod, modulus, ntohs(rsablob->modlen));

    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0 ))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
        free(buf);
        return 0;
    }
    sstatus = NCryptImportKey(prov, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, rsa,
                              buf, buflen, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptImportKey failed", sstatus);
        free(buf);
        NCryptFreeObject(prov);
        return 0;
    }
    free(buf);
    NCryptFreeObject(prov);
    return 1;
}

/**
 * Exports an RSA public key into an RSA keyblob
 */
int export_RSA_key(const RSA_key_t rsa, unsigned char *keyblob,
                   uint16_t *bloblen)
{
    SECURITY_STATUS sstatus;
    DWORD len;
    BCRYPT_RSAKEY_BLOB *blobheader;
    char *buf, *buf_exp, *buf_mod;
    struct rsa_blob_t *rsablob;
    unsigned char *modulus;
    uint32_t exponent;
    int i;

    rsablob = (struct rsa_blob_t *)keyblob;
    modulus = keyblob + sizeof(struct rsa_blob_t);

    sstatus = NCryptExportKey(rsa, (NCRYPT_KEY_HANDLE)NULL, 
            BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptExportKey failed", sstatus);
        return 0;
    }
    buf = safe_malloc(len);
    sstatus = NCryptExportKey(rsa, (NCRYPT_KEY_HANDLE)NULL,
            BCRYPT_RSAPUBLIC_BLOB, NULL, buf, len, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptExportKey failed", sstatus);
        free(buf);
        return 0;
    }
    blobheader = (BCRYPT_RSAKEY_BLOB *)buf;
    buf_exp = buf + sizeof(BCRYPT_RSAKEY_BLOB);
    buf_mod = buf_exp + blobheader->cbPublicExp;
    if (blobheader->cbPublicExp > 4) {
        log0(0, 0, 0, "unexpected size %d of public exponent\n",
                blobheader->cbPublicExp);
        free(buf);
        return 0;
    }
    for (exponent = 0, i = blobheader->cbPublicExp - 1; i >= 0; i--) {
        exponent |= buf_exp[i] << (8 * (blobheader->cbPublicExp - 1 - i));
    }

    rsablob->blobtype = KEYBLOB_RSA;
    rsablob->reserved = 0;
    rsablob->modlen = htons((uint16_t)blobheader->cbModulus);
    rsablob->exponent = htonl(exponent);
    memcpy(modulus, buf_mod, blobheader->cbModulus);
    *bloblen = (uint16_t)(sizeof(struct rsa_blob_t) + blobheader->cbModulus);
    free(buf);

    return 1;
}

/**
 * Imports an EC keyblob into an EC public key
 */
int import_EC_key(EC_key_t *ec, const unsigned char *keyblob, uint16_t bloblen,
                  int isdh)
{
    SECURITY_STATUS sstatus;
    NCRYPT_PROV_HANDLE prov;
    BCRYPT_ECCKEY_BLOB *blobheader;
    char *buf, *buf_key;
    int buflen;
    const struct ec_blob_t *ecblob;
    const unsigned char *keyval;

    ecblob = (struct ec_blob_t *)keyblob;
    keyval = keyblob + sizeof(struct ec_blob_t);

    if (sizeof(struct ec_blob_t) + ntohs(ecblob->keylen) > bloblen) {
        log0(0, 0, 0, "Error importing EC key: invalid length");
        return 0;
    } 

    buflen = sizeof(BCRYPT_ECCKEY_BLOB) + ntohs(ecblob->keylen);
    buf = safe_calloc(buflen, 1);

    blobheader = (BCRYPT_ECCKEY_BLOB *)buf;
    buf_key = buf + sizeof(BCRYPT_ECCKEY_BLOB);
    blobheader->dwMagic = get_curve_magic(ecblob->curve, isdh);
    blobheader->cbKey = ntohs(ecblob->keylen) / 2;
    memcpy(buf_key, keyval, ntohs(ecblob->keylen));

    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0 ))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
        free(buf);
        return 0;
    }
    sstatus = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB,
                              NULL, ec, buf, buflen, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptImportKey failed", sstatus);
        free(buf);
        NCryptFreeObject(prov);
        return 0;
    }
    free(buf);
    NCryptFreeObject(prov);
    return 1;
}

/**
 * Exports an EC public key into an EC keyblob
 */
int export_EC_key(const EC_key_t ec, unsigned char *keyblob, uint16_t *bloblen)
{
    SECURITY_STATUS sstatus;
    DWORD len;
    BCRYPT_ECCKEY_BLOB *blobheader;
    char *buf, *buf_key;
    struct ec_blob_t *ecblob;
    unsigned char *keyval;

    ecblob = (struct ec_blob_t *)keyblob;
    keyval = keyblob + sizeof(struct ec_blob_t);

    sstatus = NCryptExportKey(ec, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0,
                              &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptExportKey failed", sstatus);
        return 0;
    }
    buf = safe_malloc(len);
    sstatus = NCryptExportKey(ec, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, 
                              buf, len, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptExportKey failed", sstatus);
        free(buf);
        return 0;
    }
    blobheader = (BCRYPT_ECCKEY_BLOB *)buf;
    buf_key = buf + sizeof(BCRYPT_ECCKEY_BLOB);

    ecblob->blobtype = KEYBLOB_EC;
    ecblob->curve = get_EC_curve(ec);
    ecblob->keylen = htons((uint16_t)(blobheader->cbKey * 2));
    memcpy(keyval, buf_key, blobheader->cbKey * 2);
    *bloblen = (uint16_t)(sizeof(struct ec_blob_t) + (blobheader->cbKey * 2));

    free(buf);
    return 1;
}

/**
 * Generates an RSA private key with the given exponent and number of bits
 * and writes it into the specified key container
 */
RSA_key_t gen_RSA_key(int bits, int exponent, const char *container)
{
    NCRYPT_PROV_HANDLE prov;
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS sstatus;
    wchar_t wcontainer[256];

    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
        return 0;
    }
    memset(wcontainer, 0, sizeof(wcontainer));
    if (container && strcmp(container, "")) {
        mbstowcs(wcontainer, container, strlen(container));
    }
    sstatus = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM,
            (!wcscmp(wcontainer, L"") ? NULL : wcontainer), 0, machine_keyset);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptCreatePersistedKey failed", sstatus);
        NCryptFreeObject(prov);
        return 0;
    }
    if (!bits) bits = DEF_RSA_LEN;
    sstatus = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits,
                sizeof(bits), NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptSetProperty failed", sstatus);
        NCryptFreeObject(prov);
        return 0;
    }
    sstatus = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptFinalizeKey failed", sstatus);
        NCryptFreeObject(prov);
        return 0;
    }
    NCryptFreeObject(prov);
    return key;
}

/**
 * Loads an RSA private key from the specified key container
 */
RSA_key_t read_RSA_key(const char *container)
{
    union key_t key;
    int keytype;

    key = read_private_key(container, &keytype);
    if (keytype != KEYBLOB_RSA) {
        log0(0, 0, 0, "%s not an RSA key", container);
        NCryptFreeObject(key.rsa);
        return 0;
    }
    return key.rsa;
}

EC_key_t gen_EC_key(uint8_t curve, int isdh, const char *container)
{
    NCRYPT_PROV_HANDLE prov;
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS sstatus;
    LPCWSTR alg;
    wchar_t wcontainer[256];

    alg = get_curve_alg(curve, isdh);
    if (!alg) {
        log0(0, 0, 0, "curve not supported\n");
        return 0;
    }
    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
        return 0;
    }
    memset(wcontainer, 0, sizeof(wcontainer));
    if (container && strcmp(container, "")) {
        mbstowcs(wcontainer, container, strlen(container));
    }
    sstatus = NCryptCreatePersistedKey(prov, &key, alg,
                (!wcscmp(wcontainer, L"") || isdh ? NULL : wcontainer),
                0, machine_keyset);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptCreatePersistedKey failed", sstatus);
        NCryptFreeObject(prov);
        return 0;
    }
    if (!BCRYPT_SUCCESS(sstatus = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG))) {
        mserror("NCryptFinalizeKey failed", sstatus);
        NCryptFreeObject(prov);
        return 0;
    }
    NCryptFreeObject(prov);
    return key;
}


EC_key_t read_EC_key(const char *container)
{
    union key_t key;
    int keytype;

    key = read_private_key(container, &keytype);
    if (keytype != KEYBLOB_EC) {
        log0(0, 0, 0, "%s not an EC key", container);
        NCryptFreeObject(key.ec);
        return 0;
    }
    return key.ec;
}

union key_t read_private_key(const char *container, int *keytype)
{
    union key_t tmp;
    NCRYPT_PROV_HANDLE prov;
    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS sstatus;
    wchar_t algtype[20];
    wchar_t wcontainer[256];
    int len;

    tmp.key = 0;
    *keytype = 0;
    if (!BCRYPT_SUCCESS(sstatus = NCryptOpenStorageProvider(&prov, NULL, 0))) {
        mserror("NCryptOpenStorageProvider failed", sstatus);
        return tmp;
    }
    memset(wcontainer, 0, sizeof(wcontainer));
    mbstowcs(wcontainer, container, strlen(container));
    sstatus = NCryptOpenKey(prov, &key, wcontainer, 0,
                            NCRYPT_SILENT_FLAG | machine_keyset);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptOpenKey failed", sstatus);
        NCryptFreeObject(prov);
        return tmp;
    }

    sstatus = NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, NULL,
                                0, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptGetProperty failed", sstatus);
        NCryptFreeObject(key);
        NCryptFreeObject(prov);
        return tmp;
    }
    sstatus = NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY,
                (PBYTE)algtype, sizeof(algtype), &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptGetProperty failed", sstatus);
        NCryptFreeObject(key);
        NCryptFreeObject(prov);
        return tmp;
    }
    if (!wcscmp(algtype, NCRYPT_ECDSA_ALGORITHM_GROUP)) {
        tmp.ec = key;
        *keytype = KEYBLOB_EC;
    } else if (!wcscmp(algtype, NCRYPT_RSA_ALGORITHM_GROUP)) {
        tmp.rsa = key;
        *keytype = KEYBLOB_RSA;
    } else {
        log0(0, 0, 0, "Unexpected key type: %ws", algtype);
        NCryptFreeObject(key);
    }
    NCryptFreeObject(prov);
    return tmp;
}

uint8_t get_EC_curve(const EC_key_t ec)
{
    SECURITY_STATUS sstatus;
    wchar_t alg[20];
    int len;

    sstatus = NCryptGetProperty(ec, NCRYPT_ALGORITHM_PROPERTY, NULL,
                                0, &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptGetProperty failed", sstatus);
        return 0;
    }
    sstatus = NCryptGetProperty(ec, NCRYPT_ALGORITHM_PROPERTY,
                (PBYTE)alg, sizeof(alg), &len, NCRYPT_SILENT_FLAG);
    if (!BCRYPT_SUCCESS(sstatus)) {
        mserror("NCryptGetProperty failed", sstatus);
        return 0;
    }
    if (!wcscmp(alg, BCRYPT_ECDH_P256_ALGORITHM) ||
            !wcscmp(alg, BCRYPT_ECDSA_P256_ALGORITHM)) {
        return CURVE_prime256v1;
    } else if (!wcscmp(alg, BCRYPT_ECDH_P384_ALGORITHM) ||
            !wcscmp(alg, BCRYPT_ECDSA_P384_ALGORITHM)) {
        return CURVE_secp384r1;
    } else if (!wcscmp(alg, BCRYPT_ECDH_P521_ALGORITHM) ||
            !wcscmp(alg, BCRYPT_ECDSA_P521_ALGORITHM)) {
        return CURVE_secp521r1;
    } else {
        log0(0, 0, 0, "Unexpected key type: %ws", alg);
        return 0;
    }
}

void free_RSA_key(RSA_key_t rsa)
{
    SECURITY_STATUS sstatus;

    if (!BCRYPT_SUCCESS(sstatus = NCryptFreeObject(rsa))) {
        mserror("NCryptFreeObject failed", sstatus);
    }
}

void free_EC_key(EC_key_t ec)
{
    SECURITY_STATUS sstatus;

    if (!BCRYPT_SUCCESS(sstatus = NCryptFreeObject(ec))) {
        mserror("NCryptFreeObject failed", sstatus);
    }
}

void set_sys_keys(int set_sys_key)
{
    if (set_sys_key) {
        machine_keyset = NCRYPT_MACHINE_KEY_FLAG;
    } else {
        machine_keyset = 0;
    }
}
