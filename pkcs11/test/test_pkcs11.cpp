#include <stdio.h>
#include <stdint.h>
#include "CUnit/Basic.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include "../../cryptoki/pkcs11.h"

#define KEY_SIZE_BITS 2048
#define KEY_SIZE_BYTES (KEY_SIZE_BITS/8)

static CK_BBOOL tr = CK_TRUE;
static CK_KEY_TYPE keyTypeRSA = CKK_RSA;
static CK_KEY_TYPE keyTypeEC = CKK_EC;
static CK_BYTE subject[] = { "Ciphered private RSA key" };
static CK_BYTE id[] = { 123 };
static CK_BYTE dat[] = "";
static CK_ULONG modulusBits = KEY_SIZE_BITS;
static uint8_t CKA_EC_PARAM_PRIME_256V1[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};



CK_ATTRIBUTE publicECKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyTypeEC, sizeof keyTypeEC},
    {CKA_TOKEN, &tr, sizeof tr},
    {CKA_SIGN, &tr, sizeof(tr)},
    {CKA_EC_PARAMS, CKA_EC_PARAM_PRIME_256V1, sizeof(CKA_EC_PARAM_PRIME_256V1)}
};
CK_ULONG publicECKeyTemplateLength = sizeof publicECKeyTemplate / sizeof *publicECKeyTemplate;

CK_ATTRIBUTE privateECKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyTypeEC, sizeof keyTypeEC},
    {CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_PRIVATE, &tr, sizeof(tr)},
    {CKA_SUBJECT, subject, sizeof(subject)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &tr, sizeof(tr)},
    {CKA_VERIFY, &tr, sizeof(tr)},
};

CK_ATTRIBUTE publicRSAKeyTemplateConf[] = {
    {CKA_KEY_TYPE, &keyTypeRSA, sizeof keyTypeRSA},
    {CKA_TOKEN, &tr, sizeof tr},
    {CKA_ENCRYPT, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
};

CK_ATTRIBUTE publicRSAKeyTemplateInt[] = {
    {CKA_KEY_TYPE, &keyTypeRSA, sizeof keyTypeRSA},
    {CKA_TOKEN, &tr, sizeof tr},
    {CKA_VERIFY, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
};

CK_ULONG publicRSAKeyTemplateLength = sizeof publicRSAKeyTemplateConf / sizeof *publicRSAKeyTemplateConf;

CK_ATTRIBUTE privateRSAKeyTemplateConf[] = {
    {CKA_KEY_TYPE, &keyTypeRSA, sizeof keyTypeRSA},
    {CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_PRIVATE, &tr, sizeof(tr)},
    {CKA_SUBJECT, subject, sizeof(subject)},
    {CKA_ID, id, sizeof(id)},
    {CKA_DECRYPT, &tr, sizeof(tr)},
    {CKA_SENSITIVE, &tr, sizeof(tr)},
};

CK_ATTRIBUTE privateRSAKeyTemplateInt[] = {
    {CKA_KEY_TYPE, &keyTypeRSA, sizeof keyTypeRSA},
    {CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_PRIVATE, &tr, sizeof(tr)},
    {CKA_SUBJECT, subject, sizeof(subject)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SIGN, &tr, sizeof(tr)},
    {CKA_SENSITIVE, &tr, sizeof(tr)},
};


void wrap_initialize(void (*func)(void)) {
    CK_RV ret = C_Initialize(NULL);
    CU_ASSERT_FATAL(CKR_OK == ret || ret == CKR_CRYPTOKI_NOT_INITIALIZED);
    if (func) func();
    CU_ASSERT_FATAL(CKR_OK == C_Finalize(NULL));
}

void test_initialize(){
    wrap_initialize(NULL);
}

CK_ULONG privateRSAKeyTemplateLength = sizeof privateRSAKeyTemplateConf / sizeof *privateRSAKeyTemplateConf;

CK_ULONG privateECKeyTemplateLength = sizeof privateECKeyTemplate / sizeof *privateECKeyTemplate;;


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

void test_C_OpenSession(){
    auto func = [](CK_SLOT_ID slot) {
        CK_SESSION_HANDLE session;
        CU_ASSERT_FATAL(CKR_OK == C_OpenSession(slot, CKF_SERIAL_SESSION, (CK_VOID_PTR) NULL, NULL, &session));
    };
    wrap_slot(func);
}

CK_SESSION_HANDLE create_session() {
    CK_SESSION_HANDLE session;
    CK_RV ret = C_Initialize(NULL);
    CU_ASSERT_FATAL(CKR_OK == ret || ret == CKR_CRYPTOKI_NOT_INITIALIZED);
    CK_ULONG pulCount;
    CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, NULL, &pulCount));
    CU_ASSERT_FATAL(pulCount == 10);
    CK_SLOT_ID *slots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * pulCount);
    CU_ASSERT_FATAL(CKR_OK == C_GetSlotList(CK_TRUE, slots, &pulCount));
    CU_ASSERT_FATAL(CKR_OK == C_OpenSession(slots[0], CKF_SERIAL_SESSION, (CK_VOID_PTR) NULL, NULL, &session));
    return session;
}


void wrap_session(void (* func)(CK_SESSION_HANDLE handle)) {
    CK_SESSION_HANDLE session = create_session();
    func(session);
    CU_ASSERT_FATAL(CKR_OK == C_Finalize(NULL));
};


void test_C_GenerateKeyPair(void){
    typedef struct {
        CK_MECHANISM_TYPE mechanismType;
        CK_ATTRIBUTE *pub;
        CK_ULONG pubLen;
        CK_ATTRIBUTE *priv;
        CK_ULONG privLen;
    } test_key_attr_t;

    auto func = [](CK_SESSION_HANDLE session) {
        CK_OBJECT_HANDLE pubKey;
        CK_OBJECT_HANDLE privKey;

        test_key_attr_t tdata[] = {
            {CKM_EC_KEY_PAIR_GEN, publicECKeyTemplate, publicECKeyTemplateLength, privateECKeyTemplate, privateECKeyTemplateLength},
            {CKM_RSA_PKCS_KEY_PAIR_GEN, publicRSAKeyTemplateConf, publicRSAKeyTemplateLength, privateRSAKeyTemplateConf, privateRSAKeyTemplateLength},
            {CKM_RSA_PKCS_KEY_PAIR_GEN, publicRSAKeyTemplateInt, publicRSAKeyTemplateLength, privateRSAKeyTemplateInt, privateRSAKeyTemplateLength},
        };

        for (auto &td: tdata) {
            CK_RV ret;
            CK_MECHANISM mechanism = { td.mechanismType, NULL, 0 };
            ret = C_GenerateKeyPair(session, &mechanism, td.pub, td.pubLen, td.priv, td.privLen, &pubKey, &privKey);
            CU_ASSERT_FATAL(ret == CKR_OK);
        }
    };
    wrap_session(func);
}

void wrap_create_asym_object(void (*func)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_MECHANISM *pMechanism, CK_ATTRIBUTE *pubAttr, CK_ULONG pubAttrLen, CK_ATTRIBUTE *privAttr, CK_ULONG privAttrLen) {
    CK_SESSION_HANDLE session = create_session();
    CK_OBJECT_HANDLE pubKey, privKey;
    CU_ASSERT_FATAL(CKR_OK == C_GenerateKeyPair(session, pMechanism, pubAttr, pubAttrLen, privAttr, privAttrLen, &pubKey, &privKey));
    func(session, pubKey, privKey);
    CU_ASSERT_FATAL(CKR_OK == C_Finalize(NULL));
}

void test_C_EncryptDecrypt(void) {
    auto func = [](CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv) {
        uint8_t clearText[16] = {0x22, 0x11};
        uint8_t verifyText[1024];
        uint8_t cipherText[1024];
        CK_RV ret;
        CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL, 0 };
        CK_ULONG cipherTextLength = sizeof cipherText;
        CK_ULONG verifyTextLength = sizeof verifyText;
        CU_ASSERT_FATAL(CKR_OK == C_EncryptInit(session, &mechanism, pub));
        ret = C_Encrypt(session, clearText, sizeof clearText, cipherText, &cipherTextLength);
        CU_ASSERT_FATAL(CKR_OK == ret);
        CU_ASSERT_FATAL(CKR_OK == C_DecryptInit(session, &mechanism, priv));
        ret = C_Decrypt(session, cipherText, cipherTextLength, verifyText, &verifyTextLength);
        CU_ASSERT_FATAL(CKR_OK == ret);
        CU_ASSERT_FATAL(verifyTextLength == sizeof clearText);
        CU_ASSERT_FATAL(memcmp(clearText, verifyText, sizeof clearText) == 0);
    };
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    wrap_create_asym_object(func, &mechanism, publicRSAKeyTemplateConf, publicRSAKeyTemplateLength, privateRSAKeyTemplateConf, privateRSAKeyTemplateLength);
}

void test_C_SignVerify(void) {
    auto func = [](CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv) {
        uint8_t text[16] = {0x22, 0x11};
        uint8_t signature[1024];
        CK_RV ret;
        CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL, 0 };
        CK_ULONG signatureLength = sizeof signature;;
        CU_ASSERT_FATAL(CKR_OK == C_SignInit(session, &mechanism, pub));
        ret = C_Sign(session, text, sizeof text, signature, &signatureLength);
        CU_ASSERT_FATAL(CKR_OK == ret);
        ret = C_Verify(session, text, sizeof text, signature, signatureLength);
        CU_ASSERT_FATAL(CKR_OK == ret);
    };
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    wrap_create_asym_object(func, &mechanism, publicRSAKeyTemplateInt, publicRSAKeyTemplateLength, privateRSAKeyTemplateInt, privateRSAKeyTemplateLength);
    wrap_create_asym_object(func, &mechanism, publicECKeyTemplate, publicECKeyTemplateLength, privateECKeyTemplate, privateECKeyTemplateLength);
}

CU_pSuite pkcs11_suite(void){
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "initialize", test_initialize);
    CU_add_test(pSuite, "C_GetInfo", test_C_GetInfo);
    CU_add_test(pSuite, "C_GetSlotList", test_C_GetSlotList);
    CU_add_test(pSuite, "C_GetSlotInfo", test_C_GetSlotInfo);
    CU_add_test(pSuite, "C_GetTokenInfo", test_C_GetTokenInfo);
    CU_add_test(pSuite, "C_GetMechanismList", test_C_GetMechanismList);
    CU_add_test(pSuite, "C_OpenSession", test_C_OpenSession);
    CU_add_test(pSuite, "C_GenerateKeyPair", test_C_GenerateKeyPair);
    CU_add_test(pSuite, "C_EcnryptDecrypt", test_C_EncryptDecrypt);
    return pSuite;
}
