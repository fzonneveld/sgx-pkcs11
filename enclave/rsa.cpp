#include "rsa.h"
#include "arm.h"
#include "attribute.h"

#include "sgx_tseal.h"
#include "sgx_trts.h"

#include <openssl/evp.h>

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

typedef int (*i2d_pkey)(EVP_PKEY *a, unsigned char **pp);

int getRSAder(const RSA *r, uint8_t **ppRSAder, i2d_pkey f){
    EVP_PKEY *pKey = EVP_PKEY_new();
    int ret = -1;
    if (*ppRSAder != NULL) return -1;
    if (1 != EVP_PKEY_set1_RSA(pKey, (RSA *)r)) goto getRSAder_err;
    if ((ret = f(pKey, ppRSAder)) <= 0) goto getRSAder_err;
    goto  getRSAder_good;
getRSAder_err:
    if (*ppRSAder) free(*ppRSAder);
getRSAder_good:
    if (pKey) EVP_PKEY_free(pKey);
    return ret;
}


static CK_KEY_TYPE keyType = CKK_RSA;
static CK_BBOOL tr = CK_TRUE;
static CK_OBJECT_CLASS privObjecClass = CKO_PRIVATE_KEY;

CK_ATTRIBUTE defaultPrivateKeyAttr[] = {
    {CKA_CLASS, &privObjecClass, sizeof privObjecClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_SENSITIVE, &tr, sizeof(tr)},
	{CKA_ALWAYS_SENSITIVE, &tr, sizeof(tr)}
};
std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> defaultPrivateKKeyAttrMap = ATTR2MAP(defaultPrivateKeyAttr);

static CK_OBJECT_CLASS pubObjectClass = CKO_PUBLIC_KEY;

CK_ATTRIBUTE defaultPublicKeyAttr[] = {
    {CKA_CLASS, &pubObjectClass, sizeof pubObjectClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
};
std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> defaultPublicKeyAttrMap = ATTR2MAP(defaultPublicKeyAttr);


int generateRSAKeyPair(
        uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
        std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> &pubAttrMap,
        uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
        std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> &privAttrMap){

    CK_ATTRIBUTE_PTR attr_modulus_bits = getAttr(pubAttrMap, CKA_MODULUS_BITS);
    CK_ATTRIBUTE_PTR attr_public_exponent = getAttr(pubAttrMap, CKA_PUBLIC_EXPONENT);
    int ret = -1;
    RSA *rsa_key = NULL;
    size_t privateKeyDERlength, publicKeyLength;
    uint8_t *pPrivateKeyDER = NULL, *pPublicKeyDER = NULL;
    const uint8_t *rootKey;
    CK_ULONG modulus_bits;

    const unsigned char *exponent = NULL;
    size_t exponentLength = 0;
    uint8_t *privSerializedAttr  = NULL; size_t privSerLen = 0;
    CK_ATTRIBUTE_PTR privAttr = NULL; size_t nrPrivAttr;

    CK_BBOOL tr = CK_TRUE;
    bool priv_decrypt = checkAttr(privAttrMap, CKA_DECRYPT, &tr, sizeof tr);
    bool priv_sign = checkAttr(privAttrMap, CKA_SIGN, &tr, sizeof tr);
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> pubMap, privMap;

    if ((rootKey = getRootKey(NULL)) == NULL) goto generateRSAKeyPair_err;

    if (attr_modulus_bits == NULL || attr_modulus_bits->ulValueLen != sizeof(CK_ULONG)) goto generateRSAKeyPair_err;

    modulus_bits = *(CK_ULONG *)attr_modulus_bits->pValue;
    if (modulus_bits < 2048 || modulus_bits > 4096) goto generateRSAKeyPair_err;

    // Check attributes
    if (!( priv_sign ^ priv_decrypt)) goto generateRSAKeyPair_err;

    if (attr_public_exponent) {
        exponent = (uint8_t *)attr_public_exponent->pValue;
        exponentLength = attr_public_exponent->ulValueLen;
    }

    ret -= 1;
	if ((rsa_key = generateRSA(modulus_bits, exponent, exponentLength)) == NULL) goto generateRSAKeyPair_err;
    if ((privateKeyDERlength = getRSAder(rsa_key, &pPrivateKeyDER, i2d_PrivateKey)) <= 0) goto generateRSAKeyPair_err;
    if (0 >= (publicKeyLength = getRSAder(rsa_key, &pPublicKeyDER, i2d_PublicKey))) goto generateRSAKeyPair_err;
    if (publicKeyLength > RSAPublicKeyLength) goto generateRSAKeyPair_err;

    if ((privateKeyDERlength  + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) > RSAPrivateKeyLength) goto generateRSAKeyPair_err;

	if (SGX_SUCCESS != sgx_read_rand(RSAPrivateKey + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE)) goto generateRSAKeyPair_err;

    pubMap = attrMergeMaps(defaultPublicKeyAttrMap, pubAttrMap);
    privMap = attrMergeMaps(defaultPrivateKKeyAttrMap, privAttrMap);
    pubAttrMap = pubMap;
    privAttrMap = privMap;
    if ((privAttr = map2attr(privAttrMap, &nrPrivAttr)) == NULL) goto generateRSAKeyPair_err;
    if ((privSerializedAttr = attributeSerialize(privAttr,  nrPrivAttr, &privSerLen)) == NULL) goto generateRSAKeyPair_err;
	if (SGX_SUCCESS != sgx_rijndael128GCM_encrypt(
		(sgx_aes_gcm_128bit_key_t *) rootKey,
		pPrivateKeyDER, privateKeyDERlength,
		RSAPrivateKey + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		RSAPrivateKey + SGX_AESGCM_MAC_SIZE,
		SGX_AESGCM_IV_SIZE,
		privSerializedAttr, privSerLen,
		(sgx_aes_gcm_128bit_tag_t *) (RSAPrivateKey))) goto generateRSAKeyPair_err;

    *RSAPublicKeyLengthOut = publicKeyLength;
    *RSAPrivateKeyLengthOut = privateKeyDERlength + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
    memcpy(RSAPublicKey, pPublicKeyDER, publicKeyLength);
    ret = 0;
generateRSAKeyPair_err:
    if (pPrivateKeyDER) free(pPrivateKeyDER);
    if (pPublicKeyDER) free(pPublicKeyDER);
    if (rsa_key) RSA_free(rsa_key);
    if (privSerializedAttr) free(privSerializedAttr);
    if (privAttr) free(privAttr);
    return ret;
}


uint8_t *DecryptRsa(
        uint8_t *private_key_der, size_t privateKeyDERlength,
        const uint8_t *ciphertext, size_t ciphertext_length,
        int padding, int *to_len){
	const uint8_t *endptr;
	EVP_PKEY *pKey = NULL;
    RSA *rsa = NULL;
    uint8_t *ret = NULL;

	endptr = (const uint8_t *) private_key_der;
	if ((pKey = d2i_PrivateKey(EVP_PKEY_RSA, &pKey, &endptr, (long) privateKeyDERlength)) == NULL){
		return NULL;
    }
	if (NULL == (rsa = EVP_PKEY_get1_RSA(pKey))) goto DecryptRSA_err;
    if ((ret = (uint8_t *)malloc(RSA_size(rsa))) == NULL) goto DecryptRSA_err;
    *to_len = RSA_private_decrypt(ciphertext_length, ciphertext, ret, rsa, padding);
DecryptRSA_err:
    if (rsa) free(rsa);
    if (pKey) EVP_PKEY_free(pKey);
    return ret;
}

int EncryptRSA(
        const uint8_t* public_key, size_t public_key_length,
        const uint8_t* plaintext, size_t plaintext_length,
        uint8_t* ciphertext, size_t ciphertext_length,
        size_t* cipherTextLength, int padding) {
    int len;
    int ret = -1;
    RSA *rsa = NULL;
    EVP_PKEY *pKey = NULL;
	if (NULL == (pKey = EVP_PKEY_new())) goto SGXEncryptRSA_err;
	if (NULL == (pKey = d2i_PublicKey(EVP_PKEY_RSA, &pKey, &public_key, public_key_length))) goto SGXEncryptRSA_err;
	if (NULL == (rsa = EVP_PKEY_get1_RSA(pKey))) goto SGXEncryptRSA_err;

	if (( len = RSA_public_encrypt(
            plaintext_length, (uint8_t*)plaintext, (unsigned char*)ciphertext, rsa, padding)) == -1)
        goto SGXEncryptRSA_err;

	*cipherTextLength = (size_t)len;
    ret = 0;
SGXEncryptRSA_err:
    if (rsa) RSA_free(rsa);
	if (pKey) EVP_PKEY_free(pKey);
    return ret;
}
