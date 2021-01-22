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
#include "attribute.h"
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
        uint8_t *PrivateKey, size_t PrivateKeyLength, size_t *PrivateKeyLengthOut,
		const uint8_t *pSerialAttr, size_t serialAttrLen) {

	int ret = -1;
    CK_ATTRIBUTE_PTR pAttr = NULL;
    CK_ATTRIBUTE_PTR attr_key_type;
    CK_ULONG nrAttributes;

    pAttr = attributeDeserialize(pSerialAttr, serialAttrLen, &nrAttributes);
    if (pAttr == NULL) return -1;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> pAttrMap;
    pAttrMap = attr2map(pAttr, nrAttributes);
	// Check which type of key to generate....
	if ((attr_key_type = getType(pAttrMap, CKA_KEY_TYPE, sizeof(CK_KEY_TYPE))) == NULL) return 1;
	switch (*(CK_KEY_TYPE *)attr_key_type->pValue) {
		case CKK_RSA:
			ret = generateRSAKeyPair(
				PublicKey, PublicKeyLength, PublicKeyLengthOut,
				PrivateKey, PrivateKeyLength, PrivateKeyLengthOut,
				pSerialAttr, serialAttrLen,
				pAttrMap);
			break;
		case CKK_EC:
			break;
		default:
			break;
	}
	return ret;
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

int SGXDecryptRSA(
        const uint8_t *private_key_ciphered,
        size_t private_key_ciphered_length,
        const uint8_t *attributes,
        size_t attributes_length,
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

    if ((rootkey=getRootKey(NULL)) == NULL) return ret;

	if (private_key_ciphered_length < (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE)) goto SGXDecryptRSA_err;
	privateKeyDERlength = private_key_ciphered_length - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);

	if (NULL == (private_key_der = (uint8_t *)malloc(privateKeyDERlength))) goto SGXDecryptRSA_err;
	ret = -2;
	if (SGX_SUCCESS != sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t *) rootkey,
		private_key_ciphered + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		privateKeyDERlength,
		private_key_der,
		private_key_ciphered + SGX_AESGCM_MAC_SIZE,
		SGX_AESGCM_IV_SIZE,
		attributes, attributes_length,
		(sgx_aes_gcm_128bit_tag_t *) private_key_ciphered)) goto SGXDecryptRSA_err;
	ret  = -3;
	if ((to = DecryptRsa(private_key_der, privateKeyDERlength, ciphertext, ciphertext_length, RSA_PKCS1_PADDING, &to_len)) == NULL) {
		goto SGXDecryptRSA_err;
	}
    ret = -6;
    if ((size_t) to_len > plaintext_length) goto SGXDecryptRSA_err;
    ret = -7;
    memcpy(plaintext, to, to_len);
    *plainTextLength = to_len;
    ret = 0;
SGXDecryptRSA_err:
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

//	static int local_threshold = 0;
//	static int *x_s = NULL;
//	static BIGNUM **y_s = NULL;
//	static int nr_shares = 0;
//
//	if (SGX_SUCCESS != sgx_read_rand(rootKey, ROOTKEY_LENGTH)) goto setRootKeyShare_err;
//	if (x_s == NULL) {
//		local_threshold = threshold;
//	}
//	if (threshold != local_threshold) return -3;
//	rootKeySet = CK_FALSE;
//	if (threshold < 2) return -1;
//	for (int i=0; i<nr_shares; i++) if (x_s[i] == x) return -2;
//	x_s = (int *) realloc(x_s, sizeof *x_s * (nr_shares + 1));
//	x_s[nr_shares] = x;
//	y_s = (BIGNUM **) realloc(y_s, sizeof *y_s * (nr_shares + 1));
//	y_s[nr_shares] = BN_new();
//	BN_bin2bn(y, y_length, y_s[nr_shares]);
//	x_s[nr_shares] = x;
//	nr_shares += 1;
//	if (nr_shares == threshold) {
//		BIGNUM *res = BN_new();
//		BIGNUM *prime = NULL;
//		BN_hex2bn(&prime, PRIME);
//		lagrange_interpolate(res, 0, x_s, y_s, nr_shares, prime);
//		BN_bn2bin(res, rootKey);
//		rootKeySet = CK_TRUE;
//		local_threshold = 0;
//		free(x_s); x_s = NULL;
//		free(y_s); y_s = NULL;
//		return 1;
//	}
//setRootKeyShare_err:
//	return 0;
}

