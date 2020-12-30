#include <stdio.h>

#include <CUnit/Basic.h>

#include "../crypto_engine_t.h"

#include "../attribute.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../../cryptoki/pkcs11.h"

extern CK_BBOOL rootKeySet;


CK_BBOOL tr = CK_TRUE;
CK_KEY_TYPE keyType = CKK_RSA;
CK_BYTE subject[] = { "Ciphered private RSA key" };
CK_BYTE id[] = { 123 };
CK_BYTE dat[] = "";

CK_ATTRIBUTE privateRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
	{CKA_PRIVATE, &tr, sizeof(tr)},
	{CKA_SUBJECT, subject, sizeof(subject)},
	{CKA_ID, id, sizeof(id)},
	{CKA_SENSITIVE, &tr, sizeof(tr)},
	{CKA_DECRYPT, &tr, sizeof(tr)},
};

CK_ULONG privateRSAKeyTemplateLength = sizeof privateRSAKeyTemplate / sizeof *privateRSAKeyTemplate;;



int SGXgenerateRSAKeyPair(
        uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
        uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
		const uint8_t *pSerialAttr, size_t serialAttrLen,
        const unsigned char *exponent, size_t exponentLength,
        size_t bitLen);

void test_generateRSAKeyPair(){
	uint8_t pubkey[2048], privkey[2048];
	size_t pubkeyLength, privkeyLength;
    uint8_t *pSerializedAttr=NULL;
    size_t serializedAttrLen=0;
    int ret;

    rootKeySet = CK_TRUE;
    pSerializedAttr = attributeSerialize(
        privateRSAKeyTemplate, privateRSAKeyTemplateLength, &serializedAttrLen);
	ret = SGXgenerateRSAKeyPair(pubkey, sizeof pubkey, &pubkeyLength, privkey, sizeof privkey, &privkeyLength, pSerializedAttr, serializedAttrLen, NULL, 0, 2048);
	CU_ASSERT_FATAL(0 == ret);
	ret = SGXgenerateRSAKeyPair(pubkey, 10, &pubkeyLength, privkey, 10, &privkeyLength, pSerializedAttr, serializedAttrLen, NULL, 0, 2048);
	CU_ASSERT(-6 == ret);
}


int SGXEncryptRSA(
    const uint8_t* public_key, size_t public_key_length,
	const uint8_t* plaintext, size_t plaintext_length,
	uint8_t* ciphertext, size_t ciphertext_length,
	size_t* cipherTextLength);

int SGXDecryptRSA(
        const uint8_t *private_key_ciphered,
        size_t private_key_ciphered_length,
        const uint8_t *attributes,
        size_t attributes_length,
        const uint8_t* ciphertext,
        size_t ciphertext_length,
        uint8_t* plaintext,
        size_t plaintext_length,
        size_t *plainTextLength);


void test_SGXcryptRSA(){
	uint8_t pubkey[2048], privkey[2048];
	uint8_t plaintext[16] = {0x11, 0x12};
	uint8_t exp_plaintext[16] = {0x11, 0x12};
	uint8_t ciphertext[256] = {0};
	size_t cipherTextLength;
	size_t plainTextLength;
	size_t pubkeyLength, privkeyLength;
    uint8_t *pSerializedAttr;
    size_t serializedAttrLen=0;

    pSerializedAttr = attributeSerialize(
        privateRSAKeyTemplate, privateRSAKeyTemplateLength, &serializedAttrLen);

	CU_ASSERT_FATAL(pSerializedAttr != NULL);
	CU_ASSERT_FATAL(0 == SGXgenerateRSAKeyPair(pubkey, sizeof pubkey, &pubkeyLength, privkey, sizeof privkey, &privkeyLength, pSerializedAttr, serializedAttrLen, NULL, 0, 2048));
	CU_ASSERT_FATAL(0 == SGXEncryptRSA(
		pubkey, pubkeyLength,
		plaintext, sizeof plaintext,
		ciphertext, sizeof ciphertext, &cipherTextLength));
	CU_ASSERT_FATAL(0 == SGXDecryptRSA(
		privkey, privkeyLength,
        pSerializedAttr, serializedAttrLen,
		ciphertext, cipherTextLength,
		plaintext, sizeof plaintext, &plainTextLength));
	CU_ASSERT(plainTextLength == sizeof plaintext);
	CU_ASSERT(0 == memcmp(plaintext, exp_plaintext, sizeof plaintext));
}


int main(int argc, char *argv[]) {
	CU_pSuite pSuite = NULL;

/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	pSuite = CU_add_suite("PKCS11 test Suite RSA ", NULL, NULL);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	/* add the tests to the suite */
	if ((NULL == CU_add_test(pSuite, "generateRSAKeyPair()", test_generateRSAKeyPair))
	   // || (NULL == CU_add_test(pSuite, "generatePassPhrase()", test_generatePassPhrase))
	   || (NULL == CU_add_test(pSuite, "SGXEncryptRSA(), SGXDecryptRSA()", test_SGXcryptRSA))
	 )
	{
		CU_cleanup_registry();
		return CU_get_error();
	  /* Run all tests using the CUnit Basic interface */
	}
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
