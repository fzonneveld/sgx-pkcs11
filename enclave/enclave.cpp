#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "crypto_engine_t.h"
#include "tSgxSSL_api.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/rand.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../cryptoki/pkcs11.h"

#define ROOTKEY_LENGTH 32
static char rootKey_b64[(4 *((ROOTKEY_LENGTH + 2) / 3)) + 1];
static CK_BBOOL rootKeySet = CK_FALSE;

RSA *generateRSA(size_t bits, const uint8_t *exponent, size_t exponentLength) {
	RSA *ret = NULL;
	BIGNUM *bne = NULL;

	unsigned long e = RSA_F4;

	if ((bne = BN_new()) == NULL) return NULL;
	if (exponent == NULL) {
		if (BN_set_word(bne, e) != 1) goto generateRSA_err;
	} else {
		if (BN_bin2bn(exponent, exponentLength, bne) == NULL) goto generateRSA_err;
	}

	if ((ret = RSA_new()) == NULL) goto generateRSA_err;
	if ((RSA_generate_key_ex(ret, (int)bits, bne, NULL)) != 1) {
        RSA_free(ret);
        ret = NULL;
    }
generateRSA_err:
    BN_free(bne);
    return ret;
}


BUF_MEM *getRSAPubKey(const RSA *r){
	BIO *bp_public;
    BUF_MEM *ret;

	if ((bp_public = BIO_new(BIO_s_mem())) == NULL) return NULL;
	if (!PEM_write_bio_RSAPublicKey(bp_public, r)) goto getRSAPubKey_err;
    BIO_get_mem_ptr(bp_public, &ret);
    BIO_ctrl(bp_public, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
getRSAPubKey_err:
    BIO_free(bp_public);
    return ret;
}

BUF_MEM *getRSAPrivKey(const RSA *r, char *phrase){
	BIO *bp_priv;
    BUF_MEM *ret;

	if ((bp_priv = BIO_new(BIO_s_mem())) == NULL) return NULL;
	if (!PEM_write_bio_RSAPrivateKey(
        bp_priv, (RSA *)r, EVP_aes_256_cbc(), NULL, 0, 0, phrase)) goto getRSAPrivKey_err;
    BIO_get_mem_ptr(bp_priv, &ret);
    BIO_ctrl(bp_priv, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
getRSAPrivKey_err:
    BIO_free(bp_priv);
    return ret;
}

char *generatePassPhrase(){
    uint8_t buf[32];
    BIO *bp_b64, *bp_phrase;
    char *ret=NULL;
    BUF_MEM *p;

    RAND_bytes(buf, sizeof buf);
    if ((bp_b64 = BIO_new(BIO_f_base64())) == NULL) return NULL;
    if ((bp_phrase = BIO_new(BIO_s_mem())) == NULL) goto generatePassPhrase_err0;
    BIO_ctrl(bp_phrase, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
    BIO_set_flags(bp_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bp_b64, bp_phrase);
    BIO_write(bp_b64, buf, sizeof buf);
    BIO_ctrl(bp_b64,BIO_CTRL_FLUSH,0,NULL);
    BIO_get_mem_ptr(bp_phrase, &p);
    BIO_free(bp_phrase);
    // Enforce a NULL terminated string, not clear from
    // spec what is returned, it is without a newline but is
    // it a zero terminated string?
    ret = (char *) calloc(p->length + 1, 1);
    memcpy(ret, p->data, p->length);
    // Phrase is data contains a base64 string zero terminated.
    // Entropy in phrase is 32 * 8 == 256 bits.
    BUF_MEM_free(p);
generatePassPhrase_err0:
    BIO_free(bp_b64);
    return ret;
}


int SGXgenerateRSAKeyPair(char *RSAPublicKey, char *RSAPrivateKey, size_t bufferLength, size_t nrBits, const unsigned char *exponent, size_t exponentLength) {
    int ret = 1;
	BUF_MEM *public_key, *private_key;
    RSA *rsa_key;

    
    if (rootKeySet == CK_FALSE) return ret;

	if ((rsa_key = generateRSA(nrBits, exponent, exponentLength)) == NULL) goto generateRSAKeyPair_err0;
    ret = 2;
    if ((public_key = getRSAPubKey(rsa_key)) == NULL) goto generateRSAKeyPair_err1;
    ret = 3;
    if ((private_key = getRSAPrivKey(rsa_key, rootKey_b64)) == NULL) goto generateRSAKeyPair_err2;
    ret = 4;
    if (private_key->length > bufferLength) goto generateRSAKeyPair_err3;
    memcpy(RSAPrivateKey, private_key->data, private_key->length);
    memcpy(RSAPublicKey, public_key->data, public_key->length);
    ret = 0;
generateRSAKeyPair_err3:
    BUF_MEM_free(private_key);
generateRSAKeyPair_err2:
    BUF_MEM_free(public_key);
generateRSAKeyPair_err1:
    RSA_free(rsa_key);
generateRSAKeyPair_err0:
    return ret;
}

int SGXEncryptRSA(
        const char* public_key, size_t public_key_length,
        const uint8_t* plaintext, size_t plaintext_length,
        uint8_t* ciphertext, size_t ciphertext_length,
        size_t* cipherTextLength) {

	int padding = RSA_PKCS1_PADDING;
    int len;
	BIO *bp_public = NULL;
    int ret = -1;
    RSA *rsa;

	if ((rsa = RSA_new()) == NULL) return -1;

	if ((bp_public = BIO_new(BIO_s_mem())) == NULL) goto SGXEncryptRSA_err0;
	BIO_write(bp_public, public_key, public_key_length);
	if ((rsa = PEM_read_bio_RSAPublicKey(bp_public, &rsa, NULL, NULL)) == NULL) goto SGXEncryptRSA_err1;

	if (( len = RSA_public_encrypt(
            plaintext_length, (uint8_t*)plaintext, (unsigned char*)ciphertext, rsa, padding)) == -1)
        goto SGXEncryptRSA_err1;
	
	*cipherTextLength = (size_t)len;
    ret = 0;
SGXEncryptRSA_err1:
	BIO_free(bp_public);
SGXEncryptRSA_err0:
    RSA_free(rsa);
    return ret;
}

int SGXDecryptRSA(
        const uint8_t *private_key_ciphered,
        size_t private_key_ciphered_length,
        const uint8_t* ciphertext,
        size_t ciphertext_length,
        uint8_t* plaintext,
        size_t plaintext_length,
        size_t *plainTextLength) {

    uint8_t *to;
    int ret = -1;
	int padding = RSA_PKCS1_PADDING;
	BIO *bp_private = NULL;
	RSA *rsa = NULL;
    int to_len;

    if (rootKeySet == CK_FALSE) return ret;

	if ((bp_private = BIO_new(BIO_s_mem())) == NULL) return ret;
    ret = -2;
	if (!BIO_write(bp_private, private_key_ciphered, private_key_ciphered_length)) goto SGXDecryptRSA_err0;
    ret = -3;
	if ((rsa = PEM_read_bio_RSAPrivateKey(bp_private, &rsa, NULL, rootKey_b64)) == NULL) goto SGXDecryptRSA_err0;
    ret = -4;
    if ((to = (uint8_t *)malloc(RSA_size(rsa))) == NULL) goto SGXDecryptRSA_err1;
    ret = -5;
	to_len = RSA_private_decrypt(ciphertext_length, ciphertext, to, rsa, padding);
    if (to_len == -1) goto SGXDecryptRSA_err2;
    ret = -6;
    if ((size_t) to_len > plaintext_length) goto SGXDecryptRSA_err2;
    ret = -7;
    memcpy(plaintext, to, to_len);
    *plainTextLength = to_len;
    ret = 0;
SGXDecryptRSA_err2:
    free(to);
SGXDecryptRSA_err1:
    RSA_free(rsa);
SGXDecryptRSA_err0:
    BIO_free(bp_private);
    return ret;
}

size_t SGXGetSealedRootKeySize(){
    return sizeof(sgx_sealed_data_t) + ROOTKEY_LENGTH;
}

int SGXGenerateRootKey(uint8_t *rootKeySealed, size_t root_key_length, size_t *rootKeyLength){
    uint32_t sealedSize;
    uint8_t rootKey[ROOTKEY_LENGTH];
	sgx_status_t stat;
    rootKeySet = CK_FALSE;
    if (!RAND_bytes(rootKey, sizeof rootKey)) {
        return -1;
    }
    if ((sealedSize = sgx_calc_sealed_data_size(0, sizeof rootKey)) == UINT32_MAX)
        return -1;
    if (sealedSize > root_key_length)
        return -1;
    if ((SGX_SUCCESS != (stat = sgx_seal_data(
            0, NULL, sizeof(rootKey), (const uint8_t *)rootKey, root_key_length, (sgx_sealed_data_t *)rootKeySealed)))) 
        return -1;
    if ((sizeof(rootKey_b64) + 1) != EVP_EncodeBlock((uint8_t *)rootKey_b64, rootKey, ROOTKEY_LENGTH)) {
        return -1;
    }
    rootKeySet = CK_TRUE;
    return 0;
}

int SGXGetRootKeySealed(uint8_t *root_key_sealed, size_t root_key_len_sealed, size_t *rootKeyLenSealed){
	sgx_status_t stat;
    static uint8_t rootKey[ROOTKEY_LENGTH];

    *rootKeyLenSealed = SGXGetSealedRootKeySize();
    if (*rootKeyLenSealed > root_key_len_sealed) {
        return -1;
    }
    if ((SGX_SUCCESS != (stat = sgx_seal_data(
            0, NULL, sizeof(rootKey), (const uint8_t *)rootKey, sizeof rootKey, (sgx_sealed_data_t *)root_key_sealed)))) 
        return -1;
    return 0;
}


int SGXSetRootKeySealed(const uint8_t *root_key_sealed, size_t root_key_len_sealed){
    static uint8_t rootKey[ROOTKEY_LENGTH];
    uint32_t decrypted_text_length = sizeof rootKey;
	sgx_status_t stat;

    rootKeySet = CK_FALSE;
    if ((SGX_SUCCESS != (stat = sgx_unseal_data(
            (const sgx_sealed_data_t *)root_key_sealed,
            NULL, NULL,
            rootKey, &decrypted_text_length))))
        return -1;
    if ((sizeof(rootKey_b64) - 1) != EVP_EncodeBlock((uint8_t *)rootKey_b64, rootKey, ROOTKEY_LENGTH)) {
        return -1;
    }
    rootKeySet = CK_TRUE;
    return 0;
}

