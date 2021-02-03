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

static CK_BBOOL tr = CK_TRUE;
static CK_KEY_TYPE keyType = CKK_RSA;
static CK_ULONG modulus_bits = 2048;



static CK_ATTRIBUTE publicRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
	{CKA_ENCRYPT, &tr, sizeof(tr)},
};

static CK_ULONG publicRSAKeyTemplateLength = sizeof publicRSAKeyTemplate / sizeof *publicRSAKeyTemplate;;

static CK_ATTRIBUTE privateRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
	{CKA_DECRYPT, &tr, sizeof(tr)},
};

static CK_ULONG privateRSAKeyTemplateLength = sizeof privateRSAKeyTemplate / sizeof *privateRSAKeyTemplate;;


#define MAX_ATTR_SIZE 2028

void test_SGXcrypt(){
	uint8_t pubkey[2048], privkey[2048];
	uint8_t plaintext[16] = {0x11, 0x12};
	uint8_t exp_plaintext[16] = {0x11, 0x12};
	uint8_t ciphertext[256] = {0};
	size_t cipherTextLength;
	size_t plainTextLength;
	size_t pubkeyLength, privkeyLength;
    uint8_t *pPublicKeySerializedAttr=NULL;
    size_t publicSerializedAttrLen=0;
    size_t publicKeySerializedLenOut = MAX_ATTR_SIZE;
    uint8_t *pPrivSerializedAttr=NULL;
    size_t privSerializedAttrLen=0;
    size_t privSerializedAttrLenOut = MAX_ATTR_SIZE;

    Attribute pubAttr = Attribute(publicRSAKeyTemplate,publicRSAKeyTemplateLength);
    pPublicKeySerializedAttr = pubAttr.serialize(&publicSerializedAttrLen);
    pPublicKeySerializedAttr  = (uint8_t *) realloc(pPublicKeySerializedAttr, MAX_ATTR_SIZE);

    Attribute privAttr = Attribute(privateRSAKeyTemplate, privateRSAKeyTemplateLength);
    pPrivSerializedAttr = privAttr.serialize(&privSerializedAttrLen);
    pPrivSerializedAttr  = (uint8_t *) realloc(pPrivSerializedAttr, MAX_ATTR_SIZE);

	CU_ASSERT_FATAL(pPublicKeySerializedAttr != NULL);
	CU_ASSERT_FATAL(pPrivSerializedAttr != NULL);
    // printAttr(pPublicKeySerializedAttr, publicSerializedAttrLen);
    CU_ASSERT_FATAL(0 == SGXgenerateKeyPair(pubkey, sizeof pubkey,
        &pubkeyLength, pPublicKeySerializedAttr, publicSerializedAttrLen, &publicKeySerializedLenOut, privkey,
        sizeof privkey, &privkeyLength, pPrivSerializedAttr, privSerializedAttrLen, &privSerializedAttrLenOut));
    // printAttr(pPublicKeySerializedAttr, publicSerializedAttrLen);
	CU_ASSERT_FATAL(0 == SGXEncrypt(
		pubkey, pubkeyLength,
		plaintext, sizeof plaintext,
		ciphertext, sizeof ciphertext, &cipherTextLength));
	CU_ASSERT_FATAL(0 == SGXDecrypt(
		privkey, privkeyLength,
        pPrivSerializedAttr, privSerializedAttrLen,
		ciphertext, cipherTextLength,
		plaintext, sizeof plaintext, &plainTextLength));
	CU_ASSERT(plainTextLength == sizeof plaintext);
	CU_ASSERT(0 == memcmp(plaintext, exp_plaintext, sizeof plaintext));
}


CU_pSuite enclave_suite(void){
    CU_pSuite pSuite = CU_add_suite("Enclave", NULL, NULL);
    CU_add_test(pSuite, "SGXcrypt", test_SGXcrypt);
    return pSuite;
}
