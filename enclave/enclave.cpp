#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "crypto_engine_t.h"
#include "tSgxSSL_api.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/err.h"

#include "rsa.h"
#include "Attribute.h"
#include "AttributeSerial.h"
#include "ssss.h"
#include "arm.h"


CK_ATTRIBUTE *getType(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> pAttrMap, CK_KEY_TYPE type, size_t type_len) {
	CK_ATTRIBUTE *ret;
	if ((ret = getAttr(pAttrMap, type)) == NULL) {
		return NULL;
	}
	if (ret->ulValueLen != type_len) {
		return NULL;
	}
	return ret;
}

int SGXgenerateKeyPair(
        uint8_t *PublicKey, size_t PublicKeyLength, size_t *PublicKeyLengthOut,
		uint8_t *pPublicSerializedAttr, size_t publicSerializedAttrLen, size_t *publicSerializedAttrLenOut,
        uint8_t *PrivateKey, size_t PrivateKeyLength, size_t *PrivateKeyLengthOut,
		uint8_t *pPrivSerializedAttr, size_t privSerializedAttrLen, size_t *privSerializedAttrLenOut) {

	CK_ATTRIBUTE_PTR pKeyTypeAttr;

	AttributeSerial pubAttr = AttributeSerial(pPublicSerializedAttr, publicSerializedAttrLen);
	AttributeSerial privAttr = AttributeSerial(pPrivSerializedAttr, privSerializedAttrLen);
	if ((pKeyTypeAttr = pubAttr.get(CKA_KEY_TYPE)) == NULL) return -1;
	switch (*(CK_KEY_TYPE *)pKeyTypeAttr->pValue) {
	 	case CKK_RSA: {
                if (generateRSAKeyPair(
                        PublicKey, PublicKeyLength, PublicKeyLengthOut, pubAttr,
                        PrivateKey, PrivateKeyLength, PrivateKeyLengthOut, privAttr)) {
                    return -1;
                }
         		if (privAttr.serialize(pPrivSerializedAttr, *privSerializedAttrLenOut, privSerializedAttrLenOut))
         		   	return -2;
                if (pubAttr.serialize(pPublicSerializedAttr, *publicSerializedAttrLenOut, publicSerializedAttrLenOut))
                    return -3;
                return 0;
            }
	 	case CKK_EC:
	 		return -1;
	 	default:
	 		return -1;
	}
}


int SGXEncryptRSA(
        const uint8_t* public_key, size_t public_key_length,
        const uint8_t* plaintext, size_t plaintext_length,
        uint8_t* ciphertext, size_t ciphertext_length,
        size_t* cipherTextLength) {

	return EncryptRSA(
		public_key, public_key_length,
		plaintext, plaintext_length,
		ciphertext, ciphertext_length,
		cipherTextLength, RSA_PKCS1_PADDING);
}

CK_ULONG supportedKeyTypes[] = {
	CKK_RSA,
	CKK_EC,
};

int SGXDecrypt(
        const uint8_t *private_key_ciphered,
        size_t private_key_ciphered_length,
        const uint8_t *pSerializedAttr,
        size_t serializedAttrLen,
        const uint8_t* ciphertext,
        size_t ciphertext_length,
        uint8_t* plaintext,
        size_t plaintext_length,
        size_t *plainTextLength) {

    uint8_t *to = NULL;
    int ret = -1;
    int to_len = -1;
	EVP_PKEY *pKey = NULL;
	uint8_t *private_key_der = NULL;
	size_t privateKeyDERlength;
	const uint8_t *rootkey;
	CK_ULONG *pKeyType;

	AttributeSerial attr = AttributeSerial(pSerializedAttr, serializedAttrLen);

    if ((rootkey=getRootKey(NULL)) == NULL) goto SGXDecrypt_err;

	if (private_key_ciphered_length < (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE)) goto SGXDecrypt_err;
	privateKeyDERlength = private_key_ciphered_length - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);


	if (NULL == (private_key_der = (uint8_t *)malloc(privateKeyDERlength))) goto SGXDecrypt_err;
    ret -= 1;
	if (SGX_SUCCESS != sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t *) rootkey,
		private_key_ciphered + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		privateKeyDERlength,
		private_key_der,
		private_key_ciphered + SGX_AESGCM_MAC_SIZE,
		SGX_AESGCM_IV_SIZE,
		pSerializedAttr, serializedAttrLen,
		(sgx_aes_gcm_128bit_tag_t *) private_key_ciphered)) goto SGXDecrypt_err;

    ret -= 1;
	if (attr.check<CK_ULONG>(CKA_CLASS, CKO_PRIVATE_KEY) == false) goto SGXDecrypt_err;
	if ((pKeyType = attr.checkIn(CKA_KEY_TYPE, supportedKeyTypes, sizeof supportedKeyTypes / sizeof *supportedKeyTypes)) == NULL) goto SGXDecrypt_err;

	switch (*pKeyType) {
		case CKK_RSA:
			if ((to = DecryptRsa(private_key_der, privateKeyDERlength, ciphertext, ciphertext_length, RSA_PKCS1_PADDING, &to_len)) == NULL) {
				goto SGXDecrypt_err;
			}
			break;
		case CKK_EC:
			goto SGXDecrypt_err;
	}
    if ((size_t) to_len > plaintext_length) goto SGXDecrypt_err;
    memcpy(plaintext, to, to_len);
    *plainTextLength = to_len;
    ret = 0;
SGXDecrypt_err:
	if (to) free(to);
	if (private_key_der) free(private_key_der);
    if (pKey) EVP_PKEY_free(pKey);
    return ret;
}


int SGXGenerateRandom(uint8_t *random, size_t random_length){
    int ret = -1;
	if (SGX_SUCCESS != sgx_read_rand(random, random_length)) goto generateRandom_err;
generateRandom_err:
    ret = 0;
    return ret;
}

int SGXGetSealedRootKeySize(size_t *rootKeyLength){
	return GetSealedRootKeySize(rootKeyLength);
}

int SGXGenerateRootKey(uint8_t *rootKeySealed, size_t root_key_length, size_t *rootKeyLength){
	return GenerateRootKey(rootKeySealed, root_key_length, rootKeyLength);
}

int SGXGetRootKeySealed(uint8_t *root_key_sealed, size_t root_key_len_sealed, size_t *rootKeyLenSealed){
	return GetRootKeySealed(root_key_sealed, root_key_len_sealed, rootKeyLenSealed);
}


int SGXSetRootKeySealed(const uint8_t *root_key_sealed, size_t root_key_len_sealed){
	return SetRootKeySealed(root_key_sealed, root_key_len_sealed);
}


int SGXSetRootKeyShare(int x, const uint8_t *y, size_t y_length, int threshold)
{
	return SetRootKeyShare(x, y, y_length, threshold);
}

