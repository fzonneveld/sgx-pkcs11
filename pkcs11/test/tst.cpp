#include <stdio.h>

#include "CUnit/Basic.h"

// #include "../crypto_engine_t.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../../cryptoki/pkcs11.h"

void test_generateRSAKeyPair(){
}

void test_SGXcryptRSA(){
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
