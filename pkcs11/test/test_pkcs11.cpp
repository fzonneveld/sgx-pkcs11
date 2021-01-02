#include <stdio.h>
#include "CUnit/Basic.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include "../../cryptoki/pkcs11.h"

void test_C_Initialize(){
    C_Initialize(NULL);
};

void test_C_Finalize(){
};


CU_pSuite pkcs11_suite(void){
    printf("%s:%i\n", __FILE__, __LINE__);
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "C_Initialize", test_C_Initialize);
    CU_add_test(pSuite, "C_Finalize", test_C_Finalize);
    return pSuite;
}
