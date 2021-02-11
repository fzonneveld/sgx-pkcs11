#include <stdio.h>
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
#include "ec.h"
#include "Attribute.h"
#include "AttributeSerial.h"
#include "ssss.h"
#include "arm.h"

int SGXgenerateKeyPair(
        uint8_t *pPublicKeyDER, size_t PublicKeyDERLength, size_t *pPublicKeyLengthOut,
		uint8_t *pPublicSerializedAttr, size_t publicSerializedAttrLen, size_t *publicSerializedAttrLenOut,
        uint8_t *PrivateKey, size_t PrivateKeyLength, size_t *PrivateKeyLengthOut,
		uint8_t *pPrivSerializedAttr, size_t privSerializedAttrLen, size_t *privSerializedAttrLenOut) {

	CK_KEY_TYPE *pKeyType;
    uint8_t *pPrivKeyDER = NULL, *pPubKeyDER = NULL;
    size_t privKeyDERLength = 0, pubKeyDERLength = 0;
    const uint8_t *rootKey;
	int ret = -1;

    if ((rootKey = getRootKey(NULL)) == NULL) return -1;

	AttributeSerial pubAttr = AttributeSerial(pPublicSerializedAttr, publicSerializedAttrLen);
	AttributeSerial privAttr = AttributeSerial(pPrivSerializedAttr, privSerializedAttrLen);
	if ((pKeyType = pubAttr.getType<CK_KEY_TYPE>(CKA_KEY_TYPE)) == NULL) return -1;
	switch (*pKeyType) {
	 	case CKK_RSA:
            if (generateRSAKeyPair(
                    &pPubKeyDER, &pubKeyDERLength, pubAttr,
                    &pPrivKeyDER, &privKeyDERLength, privAttr))
                return -1;
            break;
	 	case CKK_EC:
            if ((ret=generateECKeyPair(
                    &pPubKeyDER,  &pubKeyDERLength, pubAttr,
                    &pPrivKeyDER, &privKeyDERLength, privAttr)))
                return ret;
	 		break;
	 	default:
	 		return -1;
	}

    if (pubAttr.serialize(pPublicSerializedAttr, *publicSerializedAttrLenOut, publicSerializedAttrLenOut))
        goto SGXGenerateKeyPair_err;

    if (privAttr.serialize(pPrivSerializedAttr, *privSerializedAttrLenOut, privSerializedAttrLenOut)) goto SGXGenerateKeyPair_err;

	if (pubKeyDERLength > PublicKeyDERLength) goto SGXGenerateKeyPair_err;
	memcpy(pPublicKeyDER, pPubKeyDER, pubKeyDERLength);
	*pPublicKeyLengthOut = pubKeyDERLength;

    if ((privKeyDERLength  + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) > PrivateKeyLength) goto SGXGenerateKeyPair_err;

    *PrivateKeyLengthOut = privKeyDERLength + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

	if (SGX_SUCCESS != sgx_read_rand(PrivateKey + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE)) goto SGXGenerateKeyPair_err;

	if (SGX_SUCCESS != sgx_rijndael128GCM_encrypt(
		(sgx_aes_gcm_128bit_key_t *) rootKey,
		pPrivKeyDER, privKeyDERLength,
		PrivateKey + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		PrivateKey + SGX_AESGCM_MAC_SIZE,
		SGX_AESGCM_IV_SIZE,
		pPrivSerializedAttr, *privSerializedAttrLenOut,
		(sgx_aes_gcm_128bit_tag_t *) (PrivateKey))) goto SGXGenerateKeyPair_err;

	ret = 0;
SGXGenerateKeyPair_err:
    if (pPrivKeyDER && privKeyDERLength) OPENSSL_clear_free(pPrivKeyDER, privKeyDERLength);
    return ret;
}


CK_ULONG supportedKeyTypes[] = {
	CKK_RSA,
	CKK_EC,
};


uint8_t *decryptObject(
        const uint8_t *private_key_ciphered,
        size_t private_key_ciphered_length,
	    size_t *pPrivateKeyDERlength,
        const uint8_t *pSerializedAttr,
        size_t serializedAttrLen){
	const uint8_t *rootkey;
	uint8_t *ret = NULL;

    if ((rootkey=getRootKey(NULL)) == NULL) return ret;

	if (private_key_ciphered_length < (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE)) return ret;
	*pPrivateKeyDERlength = private_key_ciphered_length - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);


	if (NULL == (ret = (uint8_t *)malloc(*pPrivateKeyDERlength))) return ret;
	if (SGX_SUCCESS == sgx_rijndael128GCM_decrypt(
            (sgx_aes_gcm_128bit_key_t *) rootkey,
            private_key_ciphered + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
            *pPrivateKeyDERlength,
            ret,
            private_key_ciphered + SGX_AESGCM_MAC_SIZE,
            SGX_AESGCM_IV_SIZE,
            pSerializedAttr, serializedAttrLen,
            (sgx_aes_gcm_128bit_tag_t *) private_key_ciphered)) {
        return ret;
    }
    free(ret);
    return NULL;
}


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
	size_t privateKeyDERlength;
	uint8_t *private_key_der = NULL;
	CK_ULONG *pKeyType;
	CK_BBOOL *pDecrypt;

	AttributeSerial attr = AttributeSerial(pSerializedAttr, serializedAttrLen);

    if (NULL == (private_key_der = decryptObject(
        private_key_ciphered, private_key_ciphered_length, &privateKeyDERlength, pSerializedAttr, serializedAttrLen))) goto SGXDecrypt_err;

	if (attr.check<CK_ULONG>(CKA_CLASS, CKO_PRIVATE_KEY) == false) goto SGXDecrypt_err;
	if ((pKeyType = attr.checkIn(CKA_KEY_TYPE, supportedKeyTypes, sizeof supportedKeyTypes / sizeof *supportedKeyTypes)) == NULL) goto SGXDecrypt_err;

	pDecrypt = attr.getType<CK_BBOOL>(CKA_DECRYPT);
	if (pDecrypt == NULL || *pDecrypt != CK_TRUE) goto SGXDecrypt_err;

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


typedef int (* signFunc_t)(
        const uint8_t *private_key_der,
        size_t privateKeyDERlength,
        const uint8_t *pData,
        size_t dataLen,
        uint8_t *pSignature,
        size_t *pSignatureLengthOut,
        CK_MECHANISM_TYPE mechanism);

int SGXSign(
         const uint8_t *private_key_ciphered, size_t private_key_ciphered_length,
         const uint8_t *pSerializedKeyAttr, size_t serializedKeyAttrLength,
         const uint8_t *pData, size_t dataLen,
         uint8_t *pSignature, size_t signatureLength, size_t *pSignatureLenOut,
         CK_MECHANISM_TYPE mechanism){

    uint8_t *private_key_der;
    size_t privateKeyDERlength;
    int ret = -1;
    CK_OBJECT_CLASS *pObjectClass;
    CK_KEY_TYPE *pKeyType;
	signFunc_t sf;

	AttributeSerial attr = AttributeSerial(pSerializedKeyAttr, serializedKeyAttrLength);

    if (NULL == (private_key_der = decryptObject(
        private_key_ciphered, private_key_ciphered_length, &privateKeyDERlength, pSerializedKeyAttr, serializedKeyAttrLength))) goto SGXSign_err;

    pObjectClass = attr.getType<CK_OBJECT_CLASS>(CKA_CLASS);
    if (pObjectClass == NULL || *pObjectClass != CKO_PRIVATE_KEY) goto SGXSign_err;

    pKeyType = attr.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);
	if (pKeyType == NULL) goto SGXSign_err;

	switch (*pKeyType){
	 	case CKK_RSA:
			sf = SignRSA;
            break;
	 	case CKK_EC:
			sf = ECsign;
			break;
	 	default:
	 		goto SGXSign_err;
	}
	*pSignatureLenOut = signatureLength;
	ret = sf(
			private_key_der, privateKeyDERlength, pData, dataLen,
			pSignature, pSignatureLenOut, mechanism);
SGXSign_err:
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

