#include <sstream>
#include <iostream>
#include <map>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "pkcs11-interface.h"

#include "Attribute.h"
#include "AttributeSerial.h"
#include "Database.h"


CK_SLOT_ID PKCS11_SLOT_ID = 1;
CK_SESSION_HANDLE PKCS11_SESSION_ID = 1;
#define DEFAULT_NR_SLOTS 10

CK_ULONG pkcs11_SGX_session_state = CKS_RO_PUBLIC_SESSION;
CryptoEntity *crypto=NULL;
Database *db=NULL;


CK_FUNCTION_LIST functionList = {
#undef CK_NEED_ARG_LIST
#define CK_PKCS11_FUNCTION_INFO(name) name,
#include "../cryptoki/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
};

#define RSA_MIN_KEY_SIZE 1024
#define RSA_MAX_KEY_SIZE 8192

#define EC_MIN_KEY_SIZE 112
#define EC_MAX_KEY_SIZE 512

void printAttr(CK_ATTRIBUTE_PTR attr, CK_ULONG nrAttributes ){

    for (size_t i=0; i<nrAttributes; i++) {
        CK_ATTRIBUTE_PTR a = attr + i;
        printf("Attribute[%04lu] type 0x%08lx, value[%lu] ", i, a->type, a->ulValueLen);
        for (size_t j=0; j<a->ulValueLen; j++) {
            printf("%02X ", ((uint8_t *)a->pValue)[j]);
        }
        printf("\n");
    }
}


void printhex(const char *s, const uint8_t *buf, unsigned long length){
    int i;
    printf("%s [%lu]", s, length);
    for (i=0; i< (int)length; i++) {
        if ((i % 16) == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}




CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &functionList;
    return CKR_OK;
}

CK_SLOT_ID max_slots = -1;

typedef struct pkcs11_object {
	CK_ULONG ulAttributeCount;
	CK_ATTRIBUTE_PTR pAttributes;
    uint8_t *pValue;
    size_t valueLength;
} pkcs11_object_t;

typedef struct pkcs11_session {
    CK_ULONG slotID;
    CK_ULONG flags;
    struct {
        CK_OBJECT_HANDLE_PTR  hObject;
        CK_ULONG ulObjectCount;
    } FindObject;
    CK_OBJECT_HANDLE handle;
    PKCS_OPERATION operation;
    pkcs11_object_t operationObject;
    CK_MECHANISM_TYPE operationMechanismType;
	uint8_t *part;
	CK_ULONG partLen;
} pkcs11_session_t;

std::map<CK_SESSION_HANDLE, pkcs11_session_t> sessions;
static CK_ULONG sessionHandleCnt = 0;

static pkcs11_session_t *get_session(CK_SESSION_HANDLE handle) {

    // Find session handle
    std::map<CK_SESSION_HANDLE, pkcs11_session_t>::iterator iter = sessions.find(handle);

    return iter != sessions.end() ? &iter->second : NULL;
}

template <typename T>
T GetEnv(const char *env_name, T default_value){
    char *env = getenv(env_name);
    if (env == NULL)
        return default_value;
    std::string str(env);
    std::istringstream ss(str);
    T ret;
    ss >> ret;
    return ret;
}


int sha256(const uint8_t *message, size_t message_len, uint8_t **digest, size_t& digest_len)
{
    EVP_MD_CTX *mdctx = NULL;
    int ret = -1;

    *digest = NULL;

    if((mdctx = EVP_MD_CTX_new()) == NULL)
        goto digestMessage_err;

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        goto digestMessage_err;

    if(1 != EVP_DigestUpdate(mdctx, message, message_len))
        goto digestMessage_err;

    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        goto digestMessage_err;

    unsigned int dlen;
    if(1 != EVP_DigestFinal_ex(mdctx, *digest, &dlen))
        goto digestMessage_err;
    digest_len = dlen;
    ret = 0;
digestMessage_err:
    if (*digest) free(*digest);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return ret;
}




CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (crypto != NULL)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	try {
		crypto = new CryptoEntity();
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}
    // Set the slots, slots are simulated
    // Should be environment variable configurable
    max_slots =  GetEnv<int>((const char *)"PKCS_SGX_MAX_SLOTS", DEFAULT_NR_SLOTS);
    const char *dbFileName = GetEnv<std::string>((const char *)"PKCS_DB_NAME", DEFAULT_DB_NAME).c_str();
	try {
		db = new Database(dbFileName);
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}
    if (db->IsNewDatabase()) {
        size_t rootKeyLength = crypto->GetSealedRootKeySize();
        uint8_t *rootKey = alloca(rootKeyLength);
        try {
            crypto->GenerateRootKey(rootKey, &rootKeyLength);
        }
        catch (std::runtime_error) {
            return CKR_DEVICE_ERROR;
        }
        if (db->SetRootKey(rootKey, rootKeyLength)) {
            return CKR_DEVICE_ERROR;
        }
    } else {
		size_t rootKeyLength;
        uint8_t *rootKey;

		if (NULL == (rootKey = db->GetRootKey(rootKeyLength)))
            return CKR_DEVICE_ERROR;
        try {
            if (crypto->RestoreRootKey(rootKey, rootKeyLength)) {
                return CKR_DEVICE_ERROR;
            }
		}
        catch (std::runtime_error) {
            return CKR_DEVICE_ERROR;
        }
        free(rootKey);
    }
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    delete(db);
    delete(crypto);
    crypto = NULL;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 0;
	memset(pInfo->manufacturerID, 0, sizeof *pInfo->manufacturerID);
    memcpy(pInfo->manufacturerID, "ACME", 4);
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, 0, sizeof *pInfo->libraryDescription);
    memcpy(pInfo->libraryDescription, "SGX PKCS11", 10);
	pInfo->libraryVersion.major = 2;
    pInfo->libraryVersion.minor = 1;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    int i;
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pSlotList == NULL) {
        *pulCount = max_slots;
        return CKR_OK;
    };
    if (*pulCount > max_slots) return CKR_SLOT_ID_INVALID;
    for (i=0; (CK_ULONG)i < *pulCount; i++) {
        pSlotList[i] = (CK_SLOT_ID) i;
    }
	return CKR_OK;;
}


#define SLOT_DESCRIPTION "SGX PKCS11 Slot %lu"
#define MANUFACTURER_ID "Intel SGX"

#define SET_STRING(d, s) { \
        memcpy(d, s, strlen(s)); \
        memset(d + strlen(s), 0, sizeof d - strlen(s)); \
    }

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (max_slots <= slotID) return CKR_SLOT_ID_INVALID;

    char s[64] = {0};
    sprintf(s, SLOT_DESCRIPTION, slotID);
	SET_STRING(pInfo->slotDescription, s);
	SET_STRING(pInfo->manufacturerID, MANUFACTURER_ID);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0x01;
    pInfo->hardwareVersion.minor = 0x00;
    pInfo->firmwareVersion.major = 0x02;
    pInfo->firmwareVersion.minor = 0x00;
	return CKR_OK;
}

#define MAX_SESSION_COUNT 100
#define MAX_RW_SESSION_COUNT 100

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    memset(pInfo, 0, sizeof *pInfo);
    sprintf((char *)pInfo->label, "Intel SGX Token %lu", slotID);
    pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED;
    pInfo->ulMaxSessionCount = MAX_SESSION_COUNT;
    pInfo->ulMaxRwSessionCount = MAX_RW_SESSION_COUNT;
	return CKR_OK;;
}


CK_MECHANISM_TYPE mechanismList[] = {
    // RSA
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    // EC
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
};


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    CK_ULONG mechanismCount = sizeof mechanismList / sizeof *mechanismList;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (max_slots <= slotID) return CKR_SLOT_ID_INVALID;

    if (pMechanismList == NULL) {
        *pulCount = mechanismCount;
        return CKR_OK;
    }
    if (*pulCount < mechanismCount){
        *pulCount = mechanismCount;
        return CKR_BUFFER_TOO_SMALL;
    }
    *pulCount = mechanismCount;
    memcpy(pMechanismList, mechanismList, sizeof mechanismList);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    switch (type) {
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            pInfo->ulMinKeySize = RSA_MIN_KEY_SIZE;
            pInfo->ulMaxKeySize = RSA_MAX_KEY_SIZE;
            break;
        case CKM_EC_KEY_PAIR_GEN:
            pInfo->ulMinKeySize = EC_MIN_KEY_SIZE;
            pInfo->ulMaxKeySize = EC_MAX_KEY_SIZE;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    CK_RV ret = CKR_DEVICE_ERROR;
    if (NULL == pPin) return CKR_ARGUMENTS_BAD;
    if (NULL == pLabel) return CKR_ARGUMENTS_BAD;
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (max_slots <= slotID) return CKR_SLOT_ID_INVALID;

    uint8_t *pL = NULL, *pS = NULL, *pU = NULL;
    size_t labelLength, SOpinLength, userPinLength;
    int rc;
    uint8_t *pPinDigest = NULL;
    size_t pinDigestLen;

    if (0 != sha256(pPin, ulPinLen, &pPinDigest, pinDigestLen))
        goto InitToken_err;
    if (0 > (rc = db->getToken(slotID, &pL, labelLength, &pS, SOpinLength, &pU, userPinLength)))
        goto InitToken_err;
    if (rc == 0) {
        pU = NULL;
        userPinLength = 0;
        labelLength = 32;
        if (SQLITE_OK != db->initToken(slotID, pLabel, labelLength, pPinDigest, pinDigestLen, pU, userPinLength))
            goto InitToken_err;
    } else {
        // Check passowrd
        ret  = CKR_PIN_INCORRECT;
        if (pinDigestLen != SOpinLength)
            goto InitToken_err;
        if (CRYPTO_memcmp(pPinDigest, pS, ulPinLen))
            goto InitToken_err;
        if (SQLITE_OK != db->updateToken(slotID, pLabel, labelLength))
            goto InitToken_err;
    }
    ret = CKR_OK;
InitToken_err:
    if (pL) free(pL);
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID >= max_slots)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;
    CK_FLAGS rflags = flags & CKF_RW_SESSION ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    sessions[sessionHandleCnt] = {slotID, rflags};
    *phSession = sessionHandleCnt;
    sessionHandleCnt++;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
    sessions.erase(hSession);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	sessions.clear();
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	pInfo->slotID = s->slotID;
	pInfo->flags = s->flags;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    // Do not require any PIN
    switch (userType) {
        case CKU_SO:
            break;
        case CKU_USER:
            break;
        default:
            return CKR_USER_TYPE_INVALID;
    }
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    int err;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    if (0 > (err = db->deleteObject(hObject))) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	uint8_t *pValue = NULL;
	size_t valueLength;
	CK_ATTRIBUTE *pAttributes = NULL;
	CK_ULONG attributeCount;
    int rc;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    if (0 > (rc =db->getObject(hObject, &pValue, valueLength, &pAttributes, attributeCount))) {
        return CKR_DEVICE_ERROR;
    }
	*pulSize = valueLength;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	uint8_t *pValue = NULL;
	size_t valueLength;
	CK_ATTRIBUTE *pAttributes = NULL;
	CK_ULONG attributeCount;
    int rc;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    if (0 > (rc =db->getObject(hObject, &pValue, valueLength, &pAttributes, attributeCount))) {
        return CKR_DEVICE_ERROR;
    }

	while(ulCount--) {
		Attribute attr = Attribute(pAttributes, attributeCount);
		CK_ATTRIBUTE *pAttr = attr.get(pTemplate->type);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = pAttr == NULL ? CK_UNAVAILABLE_INFORMATION : pAttr->ulValueLen;
		} else {
			if (pTemplate->ulValueLen >= pAttr->ulValueLen) {
				memcpy(pTemplate->pValue, pAttr->pValue, pAttr->ulValueLen);
			} else {
				pTemplate->ulValueLen = CK_UNAVAILABLE_INFORMATION;
			}
		}
		pTemplate++;
	}
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

    if (s->FindObject.hObject != NULL) free(s->FindObject.hObject);
    s->operation = PKCS11_CK_OPERATION_FIND;
    int nrItems = 0;
    s->FindObject.hObject = db->getObjectIds(pTemplate, ulCount, nrItems);
    if (nrItems < 0) {
        return CKR_DEVICE_ERROR;
    }
    s->FindObject.ulObjectCount = nrItems;
    s->operation = PKCS11_CK_OPERATION_FIND;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    if (PKCS11_CK_OPERATION_FIND != s->operation)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (NULL == phObject) {
        *pulObjectCount = s->FindObject.ulObjectCount;
    } else {
        memcpy(phObject, s->FindObject.hObject, std::min(ulMaxObjectCount, s->FindObject.ulObjectCount) * sizeof *phObject);
    }
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;

    if (NULL == (s = get_session(hSession))) return CKR_SESSION_HANDLE_INVALID;

    if (s->FindObject.hObject) free(s->FindObject.hObject);
    s->FindObject.hObject = NULL;
    s->FindObject.ulObjectCount = 0;

    if (PKCS11_CK_OPERATION_FIND != s->operation) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    s->operation = PKCS11_CK_OPERATION_NONE;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
	case CKM_RSA_PKCS:

		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

    pkcs11_object_t *o = &s->operationObject;
    if (o->pValue) free(o->pValue);
    if (o->pAttributes) free(o->pAttributes);
    memset(o, 0, sizeof *o);
    int rc;
    if (0 > (rc =db->getObject(hKey, &o->pValue, o->valueLength, &o->pAttributes, o->ulAttributeCount))) {
        return CKR_DEVICE_ERROR;
    }
	s->operation = PKCS11_CK_OPERATION_ENCRYPT;
    s->operationMechanismType = CKM_RSA_PKCS;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

    int len;
	CK_RV ret = CKR_DEVICE_ERROR;
    RSA *rsa = NULL;
    EVP_PKEY *pKey = NULL;
	int padding = RSA_PKCS1_PADDING;
	const uint8_t *endptr;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_ENCRYPT != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

    Attribute attr = Attribute(s->operationObject.pAttributes, s->operationObject.ulAttributeCount);

	if (*attr.getType<CK_OBJECT_CLASS>(CKA_CLASS) != CKO_PUBLIC_KEY) return CKR_KEY_HANDLE_INVALID;

	CK_KEY_TYPE *pKeyType;
    pKeyType = attr.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);
	switch (*pKeyType) {
		case CKK_RSA:
			if (NULL == (pKey = EVP_PKEY_new())) goto C_Encrypt_err;
			endptr = s->operationObject.pValue;
			if (NULL == (pKey = d2i_PUBKEY(&pKey, &endptr, s->operationObject.valueLength))) goto C_Encrypt_err;
			if (NULL == (rsa = EVP_PKEY_get1_RSA(pKey))) goto C_Encrypt_err;

			if (*pulEncryptedDataLen < (CK_ULONG) RSA_size(rsa)) goto C_Encrypt_err;

			if (( len = RSA_public_encrypt(
					ulDataLen, (uint8_t*)pData, (uint8_t*)pEncryptedData, rsa, padding)) < 0)
				goto C_Encrypt_err;

			*pulEncryptedDataLen = (CK_ULONG)len;
			ret = CKR_OK;
			s->operation = PKCS11_CK_OPERATION_NONE;
			break;
		default:
			return CKR_KEY_HANDLE_INVALID;
	}
C_Encrypt_err:
    if (rsa) RSA_free(rsa);
	if (pKey) EVP_PKEY_free(pKey);

    return ret;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

    pkcs11_object_t *o = &s->operationObject;
    if (db->getObject(hKey, &o->pValue, o->valueLength, &o->pAttributes, o->ulAttributeCount)) {
        return CKR_DEVICE_ERROR;
    }

    Attribute a = Attribute(o->pAttributes, o->ulAttributeCount);
    CK_OBJECT_CLASS_PTR pObjectClass = a.getType<CK_OBJECT_CLASS>(CKA_CLASS);
    CK_KEY_TYPE *pKeyType = a.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);

	switch (pMechanism->mechanism)
	{
        case CKM_RSA_PKCS: {
                if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
                    return CKR_MECHANISM_PARAM_INVALID;
                if (*pObjectClass != CKO_PRIVATE_KEY || *pKeyType != CKK_RSA)
                    return CKR_OBJECT_HANDLE_INVALID;
            }
            break;

        default:
            return CKR_MECHANISM_INVALID;
	}
	s->operation = PKCS11_CK_OPERATION_DECRYPT;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_DECRYPT != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pEncryptedData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	try {
        CK_ULONG resLength;
        uint8_t *serialized_attr;
        size_t attrLen;
        Attribute attr = Attribute(s->operationObject.pAttributes, s->operationObject.ulAttributeCount);
        serialized_attr = attr.serialize(&attrLen);
		CK_BYTE_PTR res = crypto->RSADecrypt(s->operationObject.pValue, s->operationObject.valueLength, serialized_attr, attrLen, (const CK_BYTE*)pEncryptedData, (CK_ULONG) ulEncryptedDataLen, &resLength);
        if (res == NULL) {
            return CKR_DEVICE_ERROR;
        }
        if (resLength > *pulDataLen) {
            free(res);
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(pData, res, resLength);
        *pulDataLen = resLength;
        free(res);
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}

	s->operation = PKCS11_CK_OPERATION_NONE;

	if (s->part) free(s->part);
	s->part = NULL;
	s->partLen = 0;
	return CKR_OK;
}

CK_RV partProcess(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSuppliedPart, CK_ULONG ulSuppliedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen, PKCS_OPERATION operation) {

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (operation != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (NULL == (s->part = (uint8_t *)realloc(s->part, s->partLen + ulSuppliedPartLen))) {
		return CKR_DEVICE_MEMORY;
	}
	memcpy(s->part + s->partLen, pSuppliedPart, ulSuppliedPartLen);
	s->partLen += ulSuppliedPartLen;
	// Always return NULL
	// Just return all the data at once.
	*pulPartLen = 0;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return partProcess(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen, PKCS11_CK_OPERATION_DECRYPT);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV ret;
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (PKCS11_CK_OPERATION_DECRYPT != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	ret = C_Decrypt(hSession, s->part, s->partLen, pLastPart, pulLastPartLen);
	if (s->part) free(s->part);
	s->part = NULL;
	s->partLen = 0;
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

    pkcs11_object_t *o = &s->operationObject;
    if (db->getObject(hKey, &o->pValue, o->valueLength, &o->pAttributes, o->ulAttributeCount)) {
        return CKR_DEVICE_ERROR;
    }

    Attribute a = Attribute(o->pAttributes, o->ulAttributeCount);
    CK_OBJECT_CLASS_PTR pObjectClass = a.getType<CK_OBJECT_CLASS>(CKA_CLASS);
    CK_KEY_TYPE *pKeyType = a.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);

    if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
        return CKR_MECHANISM_PARAM_INVALID;
    if (pObjectClass == NULL || *pObjectClass != CKO_PRIVATE_KEY) return CKR_OBJECT_HANDLE_INVALID;
    if (pKeyType == NULL) return CKR_OBJECT_HANDLE_INVALID;
	switch (pMechanism->mechanism)
	{
        case CKM_RSA_PKCS:
            if (*pKeyType != CKK_RSA) return CKR_OBJECT_HANDLE_INVALID;
            break;
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
            if (*pKeyType != CKK_EC) return CKR_OBJECT_HANDLE_INVALID;
            break;
        default:
            return CKR_MECHANISM_INVALID;
	}
	s->operation = PKCS11_CK_OPERATION_SIGN;
    s->operationMechanismType = pMechanism->mechanism;
    // Implementing RSA_PSS requires paramaters if non default are required
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_SIGN != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	try {
        CK_ULONG resLength;
        uint8_t *serialized_attr;
        size_t attrLen;
        Attribute attr = Attribute(s->operationObject.pAttributes, s->operationObject.ulAttributeCount);
        serialized_attr = attr.serialize(&attrLen);
		CK_BYTE_PTR res = crypto->Sign(s->operationObject.pValue, s->operationObject.valueLength, serialized_attr, attrLen, pData, ulDataLen, &resLength, s->operationMechanismType);
        if (res == NULL) {
            return CKR_DEVICE_ERROR;
        }
        if (resLength > *pulSignatureLen) {
            free(res);
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(pSignature, res, resLength);
        *pulSignatureLen = resLength;
        free(res);
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}

	s->operation = PKCS11_CK_OPERATION_NONE;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_SIGN != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (NULL == (s->part = (uint8_t *) realloc(s->part, s->partLen + ulPartLen)))
		return CKR_DEVICE_MEMORY;
	memcpy(s->part + s->partLen, pPart, ulPartLen);
	s->partLen += ulPartLen;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV ret;
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (PKCS11_CK_OPERATION_SIGN != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	ret = C_Sign(hSession, s->part, s->partLen, pSignature, pulSignatureLen);
	if (s->part) free(s->part);
	s->part = NULL;
	s->partLen = 0;
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_ECDSA:
			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			break;
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
    pkcs11_object_t *o = &s->operationObject;
    if (o->pValue) free(o->pValue);
    if (o->pAttributes) free(o->pAttributes);
    memset(o, 0, sizeof *o);
    int rc;
    if (0 > (rc =db->getObject(hKey, &o->pValue, o->valueLength, &o->pAttributes, o->ulAttributeCount))) {
        return CKR_DEVICE_ERROR;
    }
	s->operation = PKCS11_CK_OPERATION_VERIFY;
    s->operationMechanismType = pMechanism->mechanism;
	return CKR_OK;
}


typedef const EVP_MD* (*md_func_t)(void);

struct mechanismType {
	int padding;
    md_func_t mdf;
} mechanismType_t;

static std::map<CK_MECHANISM_TYPE, mechanismType> allowedSignMechanisms = {
	{ CKM_RSA_PKCS, { RSA_PKCS1_PADDING, NULL }},
	{ CKM_SHA1_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha1 }},
	{ CKM_SHA256_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha256 }},
	{ CKM_SHA384_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha384 }},
	{ CKM_SHA512_RSA_PKCS, { RSA_PKCS1_PADDING, EVP_sha256 }},
};

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV ret = CKR_DEVICE_ERROR;
    EVP_PKEY *pKey = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	int type;
	const uint8_t *endptr;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_VERIFY != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

    Attribute attr = Attribute(s->operationObject.pAttributes, s->operationObject.ulAttributeCount);

	if (*attr.getType<CK_OBJECT_CLASS>(CKA_CLASS) != CKO_PUBLIC_KEY) return CKR_KEY_HANDLE_INVALID;

	CK_KEY_TYPE *pKeyType;
	s->operation = PKCS11_CK_OPERATION_NONE;
    pKeyType = attr.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);
	endptr = s->operationObject.pValue;
	if (NULL == (pKey = d2i_PUBKEY(&pKey, &endptr,  s->operationObject.valueLength))) goto C_Verify_err;
    type = EVP_PKEY_id(pKey);
	if (NULL == (pkey_ctx = EVP_PKEY_CTX_new(pKey, NULL))) goto C_Verify_err;
	if (EVP_PKEY_verify_init(pkey_ctx) != 1) goto C_Verify_err;
	switch (*pKeyType) {
		case CKK_RSA: {
				ret = CKR_MECHANISM_INVALID;
				auto it = allowedSignMechanisms.find(s->operationMechanismType);
				if (it == allowedSignMechanisms.end()) goto C_Verify_err;
				ret = CKR_DEVICE_ERROR;
				if (0 >= EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, it->second.padding)) goto C_Verify_err;
				if (0 >= EVP_PKEY_CTX_set_signature_md(pkey_ctx, it->second.mdf)) goto C_Verify_err;
				if (type != EVP_PKEY_RSA) goto C_Verify_err;
			}
			break;
		case CKK_ECDSA:
			if (type != EVP_PKEY_EC) goto C_Verify_err;
			break;
		default:
			ret = CKR_KEY_HANDLE_INVALID;
			goto C_Verify_err;
	}
	if (1 != EVP_PKEY_verify(pkey_ctx, pSignature, ulSignatureLen, pData, ulDataLen)) goto C_Verify_err;
	ret = CKR_OK;
C_Verify_err:
	if (pKey) EVP_PKEY_free(pKey);
	if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_CK_OPERATION_VERIFY != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (NULL == (s->part = (uint8_t *) realloc(s->part, s->partLen + ulPartLen)))
		return CKR_DEVICE_MEMORY;
	memcpy(s->part + s->partLen, pPart, ulPartLen);
	s->partLen += ulPartLen;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV ret;
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (PKCS11_CK_OPERATION_VERIFY != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;
	ret = C_Verify(hSession, s->part, s->partLen, pSignature, ulSignatureLen);
	if (s->part) free(s->part);
	s->part = NULL;
	s->partLen = 0;
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV GenerateKeyPair(
    pkcs11_session_t *session,
    Attribute pubAttr,
    Attribute privAttr,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

	uint8_t* pPublicKey = NULL;
	size_t publicKeyLength;
	uint8_t* pPrivateKey = NULL;
	size_t privateKeyLength;
    size_t privAttrLen, pubAttrLen;
    uint8_t *privSerializedAttr, *publicSerializedAttr;

    CK_RV ret = CKR_OK;
    CK_BBOOL *pToken;

    if ((pToken = pubAttr.getType<CK_BBOOL>(CKA_TOKEN)) == NULL) return CKR_ATTRIBUTE_VALUE_INVALID;
    if (pToken == NULL || *pToken == CK_FALSE) {
		// For now session objects not supported
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    publicSerializedAttr = pubAttr.serialize(&pubAttrLen);
    privSerializedAttr = privAttr.serialize(&privAttrLen);

	try {
		crypto->KeyGeneration(
			&pPublicKey, &publicKeyLength, &publicSerializedAttr, &pubAttrLen, &pPrivateKey, &privateKeyLength, &privSerializedAttr, &privAttrLen);
	}
	catch (std::exception e) {
		return CKR_DEVICE_ERROR;
	}

    int privHandle;
    CK_ATTRIBUTE_PTR pPrivAttributes;
    CK_ULONG privAttributesCnt;

    AttributeSerial pubAttr2 = AttributeSerial(publicSerializedAttr, pubAttrLen);
    AttributeSerial privAttr2 = AttributeSerial(privSerializedAttr, privAttrLen);

    pPrivAttributes = privAttr2.attributes(privAttributesCnt);

    int pubHandle;
    CK_ATTRIBUTE_PTR pPubAttributes;
    CK_ULONG pubAttributesCnt;

    pPubAttributes = pubAttr2.attributes(pubAttributesCnt);

    if (0 > (pubHandle = db->setObject(CKO_PUBLIC_KEY, pPublicKey, publicKeyLength, pPubAttributes, pubAttributesCnt))) {
        return CKR_DEVICE_ERROR;
    }
    *phPublicKey = (CK_ULONG)pubHandle;

    pPrivAttributes = privAttr2.attributes(privAttributesCnt);

    if (0 > (privHandle = db->setObject(CKO_PRIVATE_KEY, pPrivateKey, privateKeyLength, pPrivAttributes, privAttributesCnt))) {
        return CKR_DEVICE_ERROR;
    }
    *phPrivateKey = (CK_ULONG)privHandle;
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pMechanism) return CKR_ARGUMENTS_BAD;
	if (NULL == pPublicKeyTemplate) return CKR_ARGUMENTS_BAD;
	if (NULL == pPrivateKeyTemplate) return CKR_ARGUMENTS_BAD;
	if (NULL == phPublicKey) return CKR_ARGUMENTS_BAD;
	if (NULL == phPrivateKey) return CKR_ARGUMENTS_BAD;


    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    Attribute pubAttr = Attribute(pPublicKeyTemplate, ulPublicKeyAttributeCount);
    Attribute privAttr = Attribute(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);

    CK_OBJECT_CLASS *pPubKeyObjectClass, *pPrivKeyObjectClass;
    CK_KEY_TYPE *pPubKeyType, *pPrivKeyType;
    if ((pPubKeyObjectClass  = pubAttr.getType<CK_OBJECT_CLASS>(CKA_CLASS)) != NULL && *pPubKeyObjectClass != CKO_PUBLIC_KEY)
        return CKR_ATTRIBUTE_TYPE_INVALID;
    pPubKeyType  = pubAttr.getType<CK_ULONG>(CKA_KEY_TYPE);


    if ((pPrivKeyObjectClass  = privAttr.getType<CK_OBJECT_CLASS>(CKA_CLASS)) != NULL && *pPubKeyObjectClass != CKO_PRIVATE_KEY)
        return CKR_ATTRIBUTE_TYPE_INVALID;
    pPrivKeyType  = privAttr.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);

    CK_RV ret = CKR_DEVICE_ERROR;
    switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            {
                CK_KEY_TYPE keyType = CKK_RSA;
                CK_ULONG *pModulusBits;

                ret = CKR_ATTRIBUTE_TYPE_INVALID;
                if (pPubKeyType && *pPubKeyType != CKK_RSA) return ret;
                if (pPrivKeyType && *pPrivKeyType != CKK_RSA) return ret;

                if ((pModulusBits = pubAttr.getType<CK_ULONG>(CKA_MODULUS_BITS)) == NULL) return ret;
                CK_ATTRIBUTE keyAttribs[] = {
                    {CKA_KEY_TYPE, &keyType, sizeof keyType },
                };
                pubAttr.merge(keyAttribs, sizeof keyAttribs / sizeof *keyAttribs);
                privAttr.merge(keyAttribs, sizeof keyAttribs / sizeof *keyAttribs);
            }
			break;
        case CKM_EC_KEY_PAIR_GEN:
            {
                CK_KEY_TYPE keyType = CKK_EC;
                CK_ATTRIBUTE *pECParamsAttr;

                ret = CKR_ATTRIBUTE_TYPE_INVALID;
                if (pPubKeyType && *pPubKeyType != CKK_EC) return ret;
                if (pPrivKeyType && *pPrivKeyType != CKK_EC) return ret;

                if ((pECParamsAttr = pubAttr.get(CKA_EC_PARAMS)) == NULL) return ret;
                CK_ATTRIBUTE keyAttribs[] = {
                    {CKA_KEY_TYPE, &keyType, sizeof keyType },
                };
                pubAttr.merge(keyAttribs, sizeof keyAttribs / sizeof *keyAttribs);
                privAttr.merge(keyAttribs, sizeof keyAttribs / sizeof *keyAttribs);
            }
			break;
        default:
            ret = CKR_MECHANISM_INVALID;
			return ret;
    }
    ret = GenerateKeyPair(
        s, pubAttr.map(), privAttr.map(),
        pPublicKeyTemplate, ulPublicKeyAttributeCount,
        pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
        phPublicKey, phPrivateKey);
    return ret;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (NULL == RandomData) return CKR_ARGUMENTS_BAD;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

    if (crypto->GenerateRandom(RandomData, ulRandomLen)) {
        return CKR_DEVICE_ERROR;
    }
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
