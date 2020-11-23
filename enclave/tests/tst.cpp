#include <stdio.h>

#include "CUnit/Basic.h"

#include "../crypto_engine_t.h"


int SGXgenerateRSAKeyPair(char *, char *, size_t, size_t);

void test_generateRSAKeyPair(){
	char buf1[2048], buf2[2048];
	CU_ASSERT(0 == SGXgenerateRSAKeyPair(buf1, buf2, 2048, 2048));
	CU_ASSERT(1 == SGXgenerateRSAKeyPair(buf1, buf2, 10, 200));
	CU_ASSERT(4 == SGXgenerateRSAKeyPair(buf1, buf2, 10, 2048));
}


char *generatePassPhrase();
void test_generatePassPhrase(){
	char *p = generatePassPhrase();
	CU_ASSERT(44 == strlen(p));
}


int SGXEncryptRSA(
    const char* public_key, size_t public_key_length,
	const uint8_t* plaintext, size_t plaintext_length,
	uint8_t* ciphertext, size_t ciphertext_length,
	size_t* cipherTextLength);

int SGXDecryptRSA(
	const char* private_key_ciphered, size_t private_key_ciphered_length,
	const uint8_t* ciphertext, size_t ciphertext_length,
	uint8_t* plaintext, size_t plaintext_length,
	size_t* plainTextLength);

void test_SGXEncryptRSA(){
	char public_key[2048], private_key[2048];
	uint8_t plaintext[16] = {0x11, 0x12};
	uint8_t exp_plaintext[16] = {0x11, 0x12};
	uint8_t ciphertext[256] = {0};
	size_t cipherTextLength;
	size_t plainTextLength;

	CU_ASSERT(0 == SGXgenerateRSAKeyPair(public_key, private_key, 2048, 2048));
	CU_ASSERT(0 == SGXEncryptRSA(
		public_key, strlen(public_key),
		plaintext, sizeof plaintext,
		ciphertext, sizeof ciphertext, &cipherTextLength));
	CU_ASSERT(0 == SGXDecryptRSA(
		private_key, strlen(private_key),
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
	if ((NULL == CU_add_test(pSuite, "generateRSAKeyPair()", test_generateRSAKeyPair)) ||
	   (NULL == CU_add_test(pSuite, "generatePassPhrase()", test_generatePassPhrase)) ||
	   (NULL == CU_add_test(pSuite, "SGXEncryptRSA(), SGXDecryptRSA()", test_SGXEncryptRSA))
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

