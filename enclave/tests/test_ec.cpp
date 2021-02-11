#include <stdio.h>

#include <CUnit/Basic.h>

#include "../crypto_engine_t.h"

#include "../Attribute.h"
#include "../AttributeSerial.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../../cryptoki/pkcs11.h"

#define MAX_ATTR_SIZE 2028

#include "../ec.h"


extern CK_BBOOL rootKeySet;
EC_KEY *generateEC(const uint8_t *ec_paramaters, size_t ec_parameters_len);
static const uint8_t CKA_EC_PARAM_PRIME_256V1[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};


void test_generateEC(void){

    EC_KEY *key;

    CU_ASSERT_FATAL((key = generateEC(CKA_EC_PARAM_PRIME_256V1, sizeof(CKA_EC_PARAM_PRIME_256V1))) != NULL);
}

static CK_BBOOL tr = CK_TRUE;
static CK_KEY_TYPE keyType = CKK_EC;

CK_ATTRIBUTE publicECKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_EC_PARAMS, (void *)CKA_EC_PARAM_PRIME_256V1, sizeof(CKA_EC_PARAM_PRIME_256V1)},
	{CKA_VERIFY, &tr, sizeof(tr)},
};


CK_ULONG publicECKeyTemplateLength = sizeof publicECKeyTemplate / sizeof *publicECKeyTemplate;;

CK_ATTRIBUTE privateECKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
	{CKA_SIGN, &tr, sizeof(tr)},
};

CK_ULONG privateECKeyTemplateLength = sizeof privateECKeyTemplate / sizeof *privateECKeyTemplate;;


int generate_ec_keypair(uint8_t **ppPrivateKey, size_t *pPrivateKeyLength, Attribute *privAttr){
	uint8_t *pubKey = NULL;
	size_t pubKeyLength;
    uint8_t *pPublicKeySerializedAttr=NULL;
    size_t publicKeySerializedLen=0;
    uint8_t *pPrivSerializedAttr=NULL;
    size_t privSerializedAttrLen=0;

    rootKeySet = CK_TRUE;

    Attribute pub = Attribute(publicECKeyTemplate, publicECKeyTemplateLength);
    pPublicKeySerializedAttr = pub.serialize(&publicKeySerializedLen);
    pPublicKeySerializedAttr  = (uint8_t *) realloc(pPublicKeySerializedAttr, MAX_ATTR_SIZE);

    privAttr->merge(privateECKeyTemplate, privateECKeyTemplateLength);
    pPrivSerializedAttr = privAttr->serialize(&privSerializedAttrLen);
    pPrivSerializedAttr  = (uint8_t *) realloc(pPrivSerializedAttr, MAX_ATTR_SIZE);

    return generateECKeyPair(&pubKey, &pubKeyLength, pub, ppPrivateKey, pPrivateKeyLength, *privAttr);
}

void test_generateECKeyPair(void) {
	uint8_t *privKey=NULL;
	size_t privKeyLength = 0;
    Attribute privAttr = Attribute();

    CU_ASSERT_FATAL(0 == generate_ec_keypair(&privKey, &privKeyLength, &privAttr));
}


void test_signEC(void){
	uint8_t *privKey=NULL;
	size_t privKeyLength;
    uint8_t data[] = {0x11, 0x22}, sig[72];
    size_t sigLen = sizeof(sig);
    int ret = 0;
    CK_MECHANISM_TYPE mechanism = CKM_ECDSA;
    Attribute privAttr = Attribute();

    CU_ASSERT_FATAL(0 == generate_ec_keypair(&privKey, &privKeyLength, &privAttr));
    ret = ECsign(privKey, privKeyLength, data, sizeof(data), sig, &sigLen, mechanism);
    CU_ASSERT_FATAL(ret == 0);
}


void test_SGXSignEC(void){
	uint8_t pubkey[2048], privkey[2048];
	size_t pubkeyLength, privkeyLength;
    uint8_t *pPublicKeySerializedAttr=NULL;
    size_t publicKeySerializedLen=0;
    size_t publicKeySerializedLenOut = MAX_ATTR_SIZE;
    uint8_t *pPrivSerializedAttr=NULL;
    size_t privSerializedAttrLen=0;
    size_t privSerializedAttrLenOut = MAX_ATTR_SIZE;
    int ret;

    rootKeySet = CK_TRUE;

    Attribute priv = Attribute(privateECKeyTemplate, privateECKeyTemplateLength);
    pPrivSerializedAttr = priv.serialize(&privSerializedAttrLen);
    pPrivSerializedAttr  = (uint8_t *) realloc(pPrivSerializedAttr, MAX_ATTR_SIZE);

    Attribute pub = Attribute(publicECKeyTemplate, publicECKeyTemplateLength);
    pPublicKeySerializedAttr = pub.serialize(&publicKeySerializedLen);
    pPublicKeySerializedAttr  = (uint8_t *) realloc(pPublicKeySerializedAttr, MAX_ATTR_SIZE);

	ret = SGXgenerateKeyPair(pubkey, sizeof pubkey, &pubkeyLength, pPublicKeySerializedAttr, publicKeySerializedLen, &publicKeySerializedLenOut, privkey, sizeof privkey, &privkeyLength, pPrivSerializedAttr, privSerializedAttrLen, &privSerializedAttrLenOut);
    CU_ASSERT_FATAL(0 == ret);

    uint8_t data[] = {0x01, 0x02};
    uint8_t sig[72];
    size_t  sigLen = sizeof(sig);
    CK_MECHANISM_TYPE mechanism = CKM_ECDSA;

    ret = SGXSign(privkey, privkeyLength, pPrivSerializedAttr, privSerializedAttrLenOut, data, sizeof(data), sig, sizeof(sig), &sigLen, mechanism);
    CU_ASSERT_FATAL(ret == 0);
}




CU_pSuite ec_suite(void){
    CU_pSuite pSuite = CU_add_suite("EC", NULL, NULL);
    CU_add_test(pSuite, "generateEC", test_generateEC);
    CU_add_test(pSuite, "generateECKeyPair", test_generateECKeyPair);
    CU_add_test(pSuite, "signEC", test_signEC);
    CU_add_test(pSuite, "SGXsignEC", test_SGXSignEC);
    return pSuite;
}
