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


extern CU_pSuite pkcs11_suite();
extern CU_pSuite attribute_suite();

typedef CU_pSuite (*t_suite_create)(void);

t_suite_create funcs[] = {
    pkcs11_suite,
    attribute_suite,
};

int main(int argc, char *argv[]) {
	CU_pSuite pSuite = NULL;

/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
    t_suite_create s;
    for  (t_suite_create &f : funcs) {
        CU_pSuite s = f();
    }
	/* add the tests to the suite */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
