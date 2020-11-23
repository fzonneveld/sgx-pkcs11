#include <map>
#include "pkcs11-interface.h"


CK_SLOT_ID PKCS11_SLOT_ID = 1;
CK_SESSION_HANDLE PKCS11_SESSION_ID = 1;

CK_ULONG pkcs11_SGX_session_state = CKS_RO_PUBLIC_SESSION;
CryptoEntity *crypto=NULL;


CK_FUNCTION_LIST functionList = {
#undef CK_NEED_ARG_LIST
#define CK_PKCS11_FUNCTION_INFO(name) name,
#include "../cryptoki/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
};

typedef struct session_state {
    CK_ULONG slotID;
    CK_ULONG sessionState;
} session_state_t;

typedef struct pkcs11_session {
    CK_ULONG slotID;
    CK_ULONG state;
    CK_OBJECT_HANDLE handle;
    PKCS_SGX_CK_OPERATION operation;
} pkcs11_session_t;

std::map<CK_SESSION_HANDLE, pkcs11_session_t> sessions;
static CK_ULONG sessionHandleCnt = 0;

static CK_ULONG nr_slots=0;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &functionList;
    return CKR_OK;
}

static pkcs11_session_t *get_session(CK_SESSION_HANDLE handle) {

    // Find session handle
    std::map<CK_SESSION_HANDLE, pkcs11_session_t>::iterator iter = sessions.find(handle);
    
    return iter != sessions.end() ? &iter->second : NULL;
}

static int get_env_int(const char *env_name, int default_value) {
    const char *env = std::getenv(env_name);
    return env == NULL ? default_value : atoi(env);
}
    

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (crypto != NULL) return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	try {
		crypto = new CryptoEntity();
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}
    // Set the slots, slots are simulated
    // Should be environment variable configurable
    nr_slots = get_env_int("PKCS_SGX_NR_SLOTS", DEFAULT_NR_SLOTS);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    delete(crypto);
    crypto = NULL;
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    int i;
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pSlotList == NULL) {
        *pulCount = nr_slots;
        return CKR_OK;
    };
    if (*pulCount > nr_slots) return CKR_SLOT_ID_INVALID;
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
    if (nr_slots <= slotID) return CKR_SLOT_ID_INVALID;
    
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
    CKM_RSA_PKCS_KEY_PAIR_GEN,
};


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    CK_ULONG mechanismCount = sizeof mechanismList / sizeof *mechanismList;

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (nr_slots <= slotID) return CKR_SLOT_ID_INVALID;
    
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
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            pInfo->ulMinKeySize = 1024;
            pInfo->ulMaxKeySize = 8192;
            return CKR_OK;
        default:
            return CKR_MECHANISM_INVALID;
    }
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID >= nr_slots)
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
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_SGX_CK_OPERATION_NONE != s->operation)
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

	s->operation = PKCS11_SGX_CK_OPERATION_ENCRYPT;

	CK_ATTRIBUTE extractedPublicKey = ((CK_ATTRIBUTE_PTR)(CK_ULONG)hKey)[2];
	crypto->RSAInitEncrypt((char*)extractedPublicKey.pValue);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, 
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, 
	CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_SGX_CK_OPERATION_ENCRYPT != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	try {
        CK_ULONG len;
        CK_BYTE_PTR res = crypto->RSAEncrypt((const uint8_t *)pData, (size_t)ulDataLen, (size_t*)&len);
        if (len > *pulEncryptedDataLen) {
            free(res);
            return CKR_ARGUMENTS_BAD;
        }
        memcpy(pEncryptedData, res, len);
        *pulEncryptedDataLen = len;
        free(res);
	}
	catch (std::runtime_error) {
		return CKR_DEVICE_ERROR;
	}

	s->operation = PKCS11_SGX_CK_OPERATION_NONE;

	return CKR_OK;
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

	if (PKCS11_SGX_CK_OPERATION_NONE != s->operation)
		return CKR_OPERATION_ACTIVE;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
	case CKM_RSA_PKCS:

		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		break;

		return CKR_MECHANISM_INVALID;
	}

	CK_ATTRIBUTE extractedPrivateKey = ((CK_ATTRIBUTE_PTR)(CK_ULONG)hKey)[7];
	crypto->RSAInitDecrypt((char*)extractedPrivateKey.pValue);
	s->operation = PKCS11_SGX_CK_OPERATION_DECRYPT;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_SGX_CK_OPERATION_DECRYPT != s->operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pEncryptedData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	try {
        CK_ULONG resLength;
		CK_BYTE_PTR res = crypto->RSADecrypt((const CK_BYTE*)pEncryptedData, (CK_ULONG) ulEncryptedDataLen, &resLength);
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

	s->operation = PKCS11_SGX_CK_OPERATION_NONE;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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


static int check_epmty_attr(CK_ATTRIBUTE_PTR pAttr, CK_ULONG ulAttrCount){
    CK_ULONG i;
    for (i = 0; i < ulAttrCount; i++) {
        if (NULL == pAttr[i].pValue || 0 >= pAttr[i].ulValueLen)
            return 1;
    };
    return 0;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (crypto == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_session_t *s;
    if ((s = get_session(hSession)) == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pPublicKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPublicKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pPrivateKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPrivateKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPublicKey)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPrivateKey)
		return CKR_ARGUMENTS_BAD;


    if (check_epmty_attr(pPublicKeyTemplate, ulPublicKeyAttributeCount))
			return CKR_ATTRIBUTE_VALUE_INVALID;

    if (check_epmty_attr(pPrivateKeyTemplate, ulPrivateKeyAttributeCount))
			return CKR_ATTRIBUTE_VALUE_INVALID;

	char* publicKeyChar = (char*)malloc(KEY_SIZE * sizeof(char));
	char* privateKeyChar = (char*)malloc(KEY_SIZE * sizeof(char));

	try {
		crypto->RSAKeyGeneration(publicKeyChar, privateKeyChar);
	}
	catch (std::exception e) {
		return CKR_DEVICE_ERROR;
	}

	CK_ATTRIBUTE_PTR publicKey = (CK_ATTRIBUTE_PTR)malloc(ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE));
	publicKey[0] = pPublicKeyTemplate[0];
	publicKey[1] = pPublicKeyTemplate[1];
	publicKey[2] = pPublicKeyTemplate[2];
	publicKey[2].pValue = publicKeyChar;
	publicKey[2].ulValueLen = strlen(publicKeyChar);
	*phPublicKey = (CK_ULONG)publicKey;

	CK_ATTRIBUTE_PTR privateKey = (CK_ATTRIBUTE_PTR)malloc(ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE));
	privateKey[0] = pPrivateKeyTemplate[0];
	privateKey[1] = pPrivateKeyTemplate[1];
	privateKey[2] = pPrivateKeyTemplate[2];
	privateKey[3] = pPrivateKeyTemplate[3];
	privateKey[4] = pPrivateKeyTemplate[4];
	privateKey[5] = pPrivateKeyTemplate[5];
	privateKey[6] = pPrivateKeyTemplate[6];
	privateKey[7] = pPrivateKeyTemplate[7];
	privateKey[7].pValue = privateKeyChar;
	privateKey[7].ulValueLen = strlen(privateKeyChar);
	*phPrivateKey = (CK_ULONG)privateKey;
	return CKR_OK;
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
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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
