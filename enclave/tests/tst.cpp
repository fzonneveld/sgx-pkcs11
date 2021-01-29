#include <stdio.h>

#include <CUnit/Basic.h>

extern CU_pSuite rsa_suite();
extern CU_pSuite ssss_suite();

typedef CU_pSuite (*t_suite_create)(void);

t_suite_create funcs[] = {
    rsa_suite,
    ssss_suite,
};

int main(int argc, char *argv[]) {
    /* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
    for  (t_suite_create &f : funcs) {
        f();
    }
	/* add the tests to the suite */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
