#include <stdio.h>
#include "CUnit/Basic.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include "../../cryptoki/pkcs11.h"



void wrap_initialize(void (*func)(void)) {
	printf("%s:%i\n", __FILE__, __LINE__);
    CK_RV ret = C_Initialize(NULL);
	printf("%s:%i\n", __FILE__, __LINE__);
    CU_ASSERT_FATAL(CKR_OK == ret || ret == CKR_CRYPTOKI_NOT_INITIALIZED);
    if (func) func();
    CU_ASSERT_FATAL(CKR_OK == C_Finalize(NULL));
}

void test_initialize(){
    wrap_initialize(NULL);
}



void test_C_GetInfo(void) {
    auto func = []()
    {
        CK_INFO info;
        CK_RV ret = C_GetInfo(&info);
        CK_VERSION ck = {2,0};
        CU_ASSERT_FATAL(memcmp(&info.cryptokiVersion, &ck, sizeof ck) == 0);
        CK_VERSION lk = {2,1};
        CU_ASSERT_FATAL(memcmp(&info.libraryVersion, &lk, sizeof lk) == 0);
    };
    wrap_initialize(func);
}


void test_C_GetSlotList(){
    auto func = []() {
        CK_ULONG pulCount;
        CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, NULL, &pulCount));
        CU_ASSERT_FATAL(pulCount == 10);
        CK_SLOT_ID *slots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * pulCount);
        CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, slots, &pulCount));
    };
    wrap_initialize(func);
}


void wrap_slot(void (* func)(CK_SLOT_ID)) {
    CK_RV ret = C_Initialize(NULL);
    CU_ASSERT_FATAL(CKR_OK == ret || ret == CKR_CRYPTOKI_NOT_INITIALIZED);
    CK_ULONG pulCount;
    CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, NULL, &pulCount));
    CU_ASSERT_FATAL(pulCount == 10);
    CK_SLOT_ID *slots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * pulCount);
    CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, slots, &pulCount));
    func(slots[0]);
    CU_ASSERT_FATAL(CKR_OK == C_Finalize(NULL));
};


void test_C_GetSlotInfo(){
    auto func = [](CK_SLOT_ID slot) {
        CK_SLOT_INFO info;
        CU_ASSERT_FATAL(CKR_OK == C_GetSlotInfo(slot, &info));
        CK_VERSION hv = {1,0};
        CU_ASSERT_FATAL(memcmp(&info.hardwareVersion, &hv, sizeof hv) == 0);
        CK_VERSION fv = {2,0};
        CU_ASSERT_FATAL(memcmp(&info.firmwareVersion, &fv, sizeof fv) == 0);
    };
    wrap_slot(func);
}

void test_C_GetTokenInfo(){
    auto func = [](CK_SLOT_ID slot) {
        CK_TOKEN_INFO info;
        CU_ASSERT_FATAL(CKR_OK == C_GetTokenInfo(slot, &info));
        CU_ASSERT_FATAL(info.flags == CKF_RNG | CKF_TOKEN_INITIALIZED);
    };
    wrap_slot(func);
}

extern CK_MECHANISM_TYPE mechanismList[];

void test_C_GetMechanismList(){
    auto func = [](CK_SLOT_ID slot) {
        CK_MECHANISM_TYPE *pMechanismList;
        CK_ULONG pulCount;
        CU_ASSERT_FATAL(CKR_OK == C_GetMechanismList(slot, NULL, &pulCount));
        pMechanismList = (CK_MECHANISM_TYPE *) malloc(sizeof *pMechanismList * pulCount);
        CU_ASSERT_FATAL(CKR_OK == C_GetMechanismList(slot, pMechanismList, &pulCount));
        CU_ASSERT_FATAL(memcmp(pMechanismList, mechanismList, sizeof *pMechanismList * pulCount) == 0);
    };
    wrap_slot(func);
}


CU_pSuite pkcs11_suite(void){
    printf("%s:%i\n", __FILE__, __LINE__);
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "initialize", test_initialize);
    CU_add_test(pSuite, "C_GetInfo", test_C_GetInfo);
    CU_add_test(pSuite, "C_GetSlotList", test_C_GetSlotList);
    CU_add_test(pSuite, "C_GetSlotInfo", test_C_GetSlotInfo);
    CU_add_test(pSuite, "C_GetTokenInfo", test_C_GetTokenInfo);
    CU_add_test(pSuite, "C_GetMechanismList", test_C_GetMechanismList);
    return pSuite;
}
