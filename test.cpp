#include <iostream>
#include <iomanip>
#include <map>
#include <string>

using namespace std;

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#define SGX_LABEL "SGX Label"

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "cryptoki/pkcs11.h"

static int verbose = 0;

CK_FUNCTION_LIST *funcs;

#define PKCS11_CALL(func, ...) { \
    CK_RV rc; \
    if (verbose == 1) cout << "Calling " << #func << endl; \
    if (funcs->func == NULL) { \
      cout << "Error" << #func << "== NULL\n"; \
      return 1; \
    } \
    rc = (funcs->func)(__VA_ARGS__); \
    if (rc != CKR_OK) { \
        cout << "Calling " << #func << " failed err=0x" << hex << rc << "\n"; \
        return 1; \
     } \
    if (verbose == 1) cout << "Called " << #func << endl; \
}

#define KEY_SIZE_BITS 4096
#define KEY_SIZE_BYTES (KEY_SIZE_BITS/8)

CK_BBOOL tr = CK_TRUE;
CK_KEY_TYPE keyType = CKK_RSA;
CK_BYTE subject[] = { "Ciphered private RSA key" };
CK_BYTE id[] = { 123 };
CK_BYTE dat[] = "";
CK_ULONG modulusBits = KEY_SIZE_BITS;


CK_ATTRIBUTE publicRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
    {CKA_TOKEN, &tr, sizeof tr},
	{CKA_ENCRYPT, &tr, sizeof(tr)},
	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
};
CK_ULONG publicRSAKeyTemplateLength = sizeof publicRSAKeyTemplate / sizeof *publicRSAKeyTemplate;

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

void printhex(const char *s, unsigned char *buf, unsigned long length){
    int i;
    printf("%s", s);
    for (i=0; i< (int)length; i++) {
        if ((i % 16) == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

#define DEFAULT_RUNS 1000

map<int, string> c_mechanisms = {
    // RSA
    {CKM_RSA_PKCS_KEY_PAIR_GEN, "CKM_RSA_PKCS_KEY_PAIR_GEN"},
    {CKM_RSA_PKCS, "CKM_RSA_PKCS"},
    {CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS"},
    {CKM_SHA384_RSA_PKCS, "CKM_SHA384_RSA_PKCS"},
    {CKM_SHA512_RSA_PKCS, "CKM_SHA512_RSA_PKCS"},
    {CKM_SHA256_RSA_PKCS_PSS, "CKM_SHA256_RSA_PKCS_PSS"},
    {CKM_SHA384_RSA_PKCS_PSS, "CKM_SHA384_RSA_PKCS_PSS"},
    {CKM_SHA512_RSA_PKCS_PSS, "CKM_SHA512_RSA_PKCS_PSS"},
    {CKM_SHA224_RSA_PKCS, "CKM_SHA224_RSA_PKCS"},
    {CKM_SHA224_RSA_PKCS_PSS, "CKM_SHA224_RSA_PKCS_PSS"},
    // EC
    {CKM_EC_KEY_PAIR_GEN, "CKM_EC_KEY_PAIR_GEN"},
    {CKM_ECDSA, "CKM_ECDSA"},
};

#define USAGE {cout << "Usage: [-i SOPIN] [-v] [-c] " << argv[0] << " <pkcs11 lib> [nr_times]" << endl;}

int main(int argc, char *argv[]) {
    void *d;
    CK_RV  (*pFunc)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV rc;
    CK_SESSION_HANDLE session;
	CK_MECHANISM mechanismGen = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};
    int opt;
    bool delete_objects_after = false;
    char *SOpin = NULL;

    while ((opt = getopt(argc,argv,"vci:")) != EOF){
        switch (opt) {
            case 'i': SOpin = optarg; break;
            case 'v': verbose=1; break;
            case 'c': delete_objects_after=true; break;
            case '?': USAGE; return 1;
            default: cout<<endl; abort();
        }
    }
    int nr_args = argc - optind;
    if (nr_args != 1 && nr_args != 2) {
        USAGE;
        return 1;
    }
    int nr_times = nr_args == 2 ? atoi(argv[optind + 1]) : DEFAULT_RUNS;
    char *mod = argv[optind];
    cout << "Opening module " << mod << endl;
    d = dlopen(mod, RTLD_LAZY);
    if ( d == NULL ) {
        cerr << "Error: " << dlerror() << endl;
        abort();
    }
    printf("Getting the PKCS11 function list...\n");

    pFunc = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(d,"C_GetFunctionList");
    if (pFunc == NULL ) {
        printf("C_GetFunctionList() not found in module \n"); // @D1A
        return 1;
    }
    rc = pFunc(&funcs);

    if (rc != CKR_OK) {
        fprintf(stderr, "Could not get function list\n");
        return 1;
    }
    PKCS11_CALL(C_Initialize, NULL);
    CK_INFO info;
    PKCS11_CALL(C_GetInfo, &info);
    CK_ULONG pulCount;
    PKCS11_CALL(C_GetSlotList, CK_TRUE, NULL, &pulCount);
    CK_SLOT_ID *slots = (CK_SLOT_ID *) malloc(sizeof *slots * pulCount);
    PKCS11_CALL(C_GetSlotList, CK_TRUE, slots, &pulCount);
    if (NULL != SOpin) {
        uint8_t label[32] = {0};
        memcpy(label, SGX_LABEL, strlen(SGX_LABEL));
        PKCS11_CALL(C_InitToken, slots[0], (uint8_t *)SOpin, strlen(SOpin), label);
    }
    CK_SLOT_INFO pInfo;
    PKCS11_CALL(C_GetSlotInfo, slots[0], &pInfo);
    printf("slotDescription='%s'\n", pInfo.slotDescription);
    printf("manufacturerID='%s'\n", pInfo.manufacturerID);
    CK_MECHANISM_TYPE_PTR pMechanismList=NULL;
    PKCS11_CALL(C_GetMechanismList, slots[0], pMechanismList, &pulCount);
    printf("mechanisms supported [%lu]:\n", pulCount);
    pMechanismList = (CK_MECHANISM_TYPE_PTR) malloc(sizeof *pMechanismList * pulCount);
    PKCS11_CALL(C_GetMechanismList, slots[0], pMechanismList, &pulCount);
    for (int i=0;i<(int)pulCount;i++) {
        map<int, string>::const_iterator iter = c_mechanisms.find(pMechanismList[i]);
        if (iter != c_mechanisms.end()) {
            cout << "\t" << "[0x" << setfill('0') << setw(8) << pMechanismList[i] << "]" << iter->second << "\n";
        } else {
            cout << "\t" << "[0x" << setfill('0') << setw(8) << pMechanismList[i] << "] <unknown>\n";
        }
    }
    PKCS11_CALL(C_OpenSession, slots[0], CKF_SERIAL_SESSION, (CK_VOID_PTR) NULL, NULL, &session);
    uint8_t random[16];
    PKCS11_CALL(C_GenerateRandom, session, random, sizeof *random);
    printf("Generating RSA key...\n");
    CK_OBJECT_HANDLE hPublicKey = (CK_OBJECT_HANDLE)NULL;
    CK_OBJECT_HANDLE hPrivateKey = (CK_OBJECT_HANDLE)NULL;
    PKCS11_CALL(
        C_GenerateKeyPair,
        session,
        &mechanismGen,
        publicRSAKeyTemplate, publicRSAKeyTemplateLength,
        privateRSAKeyTemplate, privateRSAKeyTemplateLength,
        &hPublicKey, &hPrivateKey);

	CK_MECHANISM mechanismRSA = { CKM_RSA_PKCS, NULL_PTR, 0 };
	PKCS11_CALL(C_EncryptInit, session, &mechanismRSA, hPublicKey);
    CK_BYTE clearText[] = { 0x11, 0x2 };
    CK_BYTE cipherText[KEY_SIZE_BYTES];
    CK_ULONG cipherTextLength = sizeof cipherText;
	PKCS11_CALL(C_Encrypt, session, clearText, sizeof clearText, cipherText, &cipherTextLength);
    CK_ULONG resLength;
    CK_BYTE res[KEY_SIZE_BYTES];
    int i;
    printf("Decrypting %i times...\n", nr_times);
    for (i=0; i<nr_times; i++) {
        PKCS11_CALL(C_DecryptInit, session, &mechanismRSA, hPrivateKey);
        resLength = sizeof res;
        PKCS11_CALL(C_Decrypt, session, cipherText, cipherTextLength, res, &resLength);
    }
    if (resLength == sizeof clearText && memcmp(clearText, res, sizeof clearText) == 0)
        printf("SUCCESS: RSA Generating, encrypt, decrypt successfull\n");
    else {
        printf("ERROR: resLength=%lu\n", resLength);
        printhex("Buffer", res, resLength);
    }
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL token = true;
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_TOKEN, &token, sizeof(token) }
    };
    PKCS11_CALL(C_FindObjectsInit, session, findTemplate, sizeof findTemplate / sizeof *findTemplate);
    CK_ULONG pullCount;
    PKCS11_CALL(C_FindObjects, session, NULL, 0, &pullCount);
    cout << "Found " << pullCount << " private key object handles\n";
    PKCS11_CALL(C_FindObjectsFinal, session);
    if (true == delete_objects_after) {
        cout << "Cleaning up all objects on token:" << endl;
        PKCS11_CALL(C_FindObjectsInit, session, NULL, 0);
        PKCS11_CALL(C_FindObjects, session, NULL, 0, &pullCount);
        CK_OBJECT_HANDLE *oh = (CK_OBJECT_HANDLE *)malloc(sizeof *oh * pullCount);
        PKCS11_CALL(C_FindObjects, session, oh, pullCount, &pullCount);
        PKCS11_CALL(C_FindObjectsFinal, session);
        for (i=0; i<(int)pullCount; i++) {
            PKCS11_CALL(C_DestroyObject, session, oh[i]);
            printf("\t [%i] %lu\n", i, oh[i]);
        }
    }
    PKCS11_CALL(C_CloseAllSessions, slots[0]);
    //PKCS11_CALL(C_CloseSession, session);
    PKCS11_CALL(C_Finalize, NULL);
    return 0;
}
