#include <map>
#include "rsa.h"
#include "arm.h"

#include "sgx_tseal.h"
#include "sgx_trts.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

static CK_ATTRIBUTE defaultPrivateKeyAttr[] = {
    {CKA_CLASS, &privObjecClass, sizeof privObjecClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_SENSITIVE, &tr, sizeof(tr)},
	{CKA_ALWAYS_SENSITIVE, &tr, sizeof(tr)}
};



static auto defaultPrivateKKeyAttrMap = ATTR(defaultPrivateKeyAttr).map();

static CK_OBJECT_CLASS pubObjectClass = CKO_PUBLIC_KEY;

CK_ATTRIBUTE defaultPublicKeyAttr[] = {
    {CKA_CLASS, &pubObjectClass, sizeof pubObjectClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
};

static auto defaultPublicKeyAttrMap = ATTR(defaultPublicKeyAttr).map();


int generateRSAKeyPair(
        uint8_t **ppRSAPublicKey, size_t *pRSAPublicKeyLength, Attribute &pubAttr,
        uint8_t ** ppRSAPrivateKey, size_t *pRSAPrivateKeyLength, Attribute &privAttr){

    CK_ATTRIBUTE_PTR attr_modulus_bits = pubAttr.get(CKA_MODULUS_BITS);
    CK_ATTRIBUTE_PTR attr_public_exponent = pubAttr.get(CKA_PUBLIC_EXPONENT);
    int ret = -1;
    RSA *rsa_key = NULL;
    int privateKeyDERlength, publicKeyDERlength;
    uint8_t *pRSAPrivateKeyDER = NULL, *pRSAPublicKeyDER = NULL;
    CK_ULONG modulus_bits;

    const unsigned char *exponent = NULL;
    size_t exponentLength = 0;

    CK_BBOOL tr = CK_TRUE;
    bool priv_decrypt = privAttr.check(CKA_DECRYPT, tr);
    bool priv_sign = privAttr.check(CKA_SIGN, tr);


	ret -= 1;
    if (attr_modulus_bits == NULL || attr_modulus_bits->ulValueLen != sizeof(CK_ULONG)) goto generateRSAKeyPair_err;

    modulus_bits = *(CK_ULONG *)attr_modulus_bits->pValue;
	ret -= 1;
    if (modulus_bits < 2048 || modulus_bits > 4096) goto generateRSAKeyPair_err;

	ret -= 1;
    // Check attributes
    if (!( priv_sign ^ priv_decrypt)) goto generateRSAKeyPair_err;

    if (attr_public_exponent) {
        exponent = (uint8_t *)attr_public_exponent->pValue;
        exponentLength = attr_public_exponent->ulValueLen;
    }

    ret -= 1;
	if ((rsa_key = generateRSA(modulus_bits, exponent, exponentLength)) == NULL) goto generateRSAKeyPair_err;

    if ((publicKeyDERlength = getRSAder(rsa_key, &pRSAPublicKeyDER, i2d_PUBKEY)) < 0) goto generateRSAKeyPair_err;
    if ((privateKeyDERlength = getRSAder(rsa_key, &pRSAPrivateKeyDER, i2d_PrivateKey)) <= 0) goto generateRSAKeyPair_err;

	*pRSAPublicKeyLength = publicKeyDERlength;
	*pRSAPrivateKeyLength = privateKeyDERlength;


    pubAttr.merge(defaultPublicKeyAttrMap);
    privAttr.merge(defaultPrivateKKeyAttrMap);

	*ppRSAPublicKey = pRSAPublicKeyDER;
	*ppRSAPrivateKey = pRSAPrivateKeyDER;

	pRSAPublicKeyDER = NULL;
	pRSAPrivateKeyDER = NULL;
    ret = 0;
generateRSAKeyPair_err:
    if (pRSAPublicKeyDER) free(pRSAPublicKeyDER);
	if (pRSAPrivateKeyDER) free(pRSAPrivateKeyDER);
    if (rsa_key) RSA_free(rsa_key);
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
    if (-1 == (*to_len = RSA_private_decrypt(ciphertext_length, ciphertext, ret, rsa, padding))){
		return NULL;
	}
DecryptRSA_err:
    if (rsa) free(rsa);
    if (pKey) EVP_PKEY_free(pKey);
    return ret;
}


typedef const EVP_MD* (*md_func_t)(void);

struct mechanismType {
	int padding;
    md_func_t mdf;
} mechanismType_t;

static std::map<CK_MECHANISM_TYPE, mechanismType> allowedSignMechanisms = {
    { CKM_RSA_PKCS, { RSA_PKCS1_PADDING, NULL }},
    { CKM_SHA1_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha1 }},
    { CKM_SHA256_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha256 }},
    { CKM_SHA384_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha384 }},
    { CKM_SHA512_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha256 }},
};

int SignRSA(
        const uint8_t *private_key_der,
        size_t privateKeyDERlength,
        const uint8_t *pData,
        size_t dataLen,
        uint8_t *pSignature,
        size_t *pSignatureLengthOut,
        CK_MECHANISM_TYPE mechanism) {

    EVP_PKEY *pKey = NULL;
    auto it = allowedSignMechanisms.find(mechanism);
	const uint8_t *endptr;
	size_t outLen;
	int ret = -1;
	EVP_PKEY_CTX* ctx = NULL;

    if (it == allowedSignMechanisms.end()) return -1;

	endptr = (const uint8_t *) private_key_der;
	if ((pKey = d2i_PrivateKey(EVP_PKEY_RSA, &pKey, &endptr, (long) privateKeyDERlength)) == NULL){
		return ret;
    }
	ctx = EVP_PKEY_CTX_new(pKey, NULL);
	if (0 >= EVP_PKEY_sign_init(ctx)) goto SignRSA_err;
	if (0 >= EVP_PKEY_CTX_set_rsa_padding(ctx, it->second.padding)) goto SignRSA_err;
	if (0 >= EVP_PKEY_CTX_set_signature_md(ctx, it->second.mdf == NULL ? NULL: it->second.mdf())) goto SignRSA_err;
	if (0 >= EVP_PKEY_sign(ctx, NULL, &outLen, pData, dataLen)) goto SignRSA_err;
	if (outLen > *pSignatureLengthOut) goto SignRSA_err;
	if (0 >= EVP_PKEY_sign(ctx, pSignature, &outLen, pData, dataLen)) goto SignRSA_err;
	*pSignatureLengthOut = outLen;
    ret = 0;
SignRSA_err:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	if (pKey) EVP_PKEY_free(pKey);
    return ret;
}
