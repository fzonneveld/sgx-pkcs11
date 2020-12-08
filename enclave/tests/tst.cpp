#include <stdio.h>

#include "CUnit/Basic.h"

#include "../crypto_engine_t.h"

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

int SGXgenerateRSAKeyPair(
        uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
        uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
        const unsigned char *exponent, size_t exponentLength,
        size_t bitLen);

void test_generateRSAKeyPair(){
	uint8_t pubkey[2048], privkey[2048];
	size_t pubkeyLength, privkeyLength;
    rootKeySet = CK_TRUE;
	CU_ASSERT(0 == SGXgenerateRSAKeyPair(pubkey, sizeof pubkey, &pubkeyLength, privkey, sizeof privkey, &privkeyLength, NULL, 0, 2048));
	CU_ASSERT(-6 == SGXgenerateRSAKeyPair(pubkey, 10, &pubkeyLength, privkey, 10, &privkeyLength, NULL, 0, 2048));
}


char *generatePassPhrase();
void test_generatePassPhrase(){
	char *p = generatePassPhrase();
	CU_ASSERT(44 == strlen(p));
}


int SGXEncryptRSA(
    const uint8_t* public_key, size_t public_key_length,
	const uint8_t* plaintext, size_t plaintext_length,
	uint8_t* ciphertext, size_t ciphertext_length,
	size_t* cipherTextLength);

int SGXDecryptRSA(
	const char* private_key_ciphered, size_t private_key_ciphered_length,
	const uint8_t* ciphertext, size_t ciphertext_length,
	uint8_t* plaintext, size_t plaintext_length,
	size_t* plainTextLength);

void test_SGXcryptRSA(){
	uint8_t pubkey[2048], privkey[2048];
	uint8_t plaintext[16] = {0x11, 0x12};
	uint8_t exp_plaintext[16] = {0x11, 0x12};
	uint8_t ciphertext[256] = {0};
	size_t cipherTextLength;
	size_t plainTextLength;
	size_t pubkeyLength, privkeyLength;

	CU_ASSERT_FATAL(0 == SGXgenerateRSAKeyPair(pubkey, sizeof pubkey, &pubkeyLength, privkey, sizeof privkey, &privkeyLength, NULL, 0, 2048));
	printf("%s:%i privkeyLength=%i \n", __FILE__, __LINE__, privkeyLength);
	CU_ASSERT_FATAL(0 == SGXEncryptRSA(
		pubkey, pubkeyLength,
		plaintext, sizeof plaintext,
		ciphertext, sizeof ciphertext, &cipherTextLength));
	printf("%s:%i privkeyLength=%i \n", __FILE__, __LINE__, privkeyLength);
	CU_ASSERT_FATAL(0 == SGXDecryptRSA(
		privkey, privkeyLength,
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

