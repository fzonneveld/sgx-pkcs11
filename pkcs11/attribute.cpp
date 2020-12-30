#include <map>
 #include <openssl/crypto.h>
#include "attribute.h"

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_ULONG ulValueLen;
    CK_BYTE pValue[0];
} serializedAttr;




CK_ATTRIBUTE_PTR attributeDeserialize(const uint8_t *data, size_t dataLen, CK_ULONG *nrAttributes){
    CK_ATTRIBUTE_PTR ret = NULL;
    *nrAttributes = 0;
    while (dataLen != 0) {
        serializedAttr *pSerAttr = (serializedAttr *)data;
        if (dataLen < sizeof *pSerAttr) goto error_exit;
        if (pSerAttr->ulValueLen == 0 || dataLen < (sizeof *pSerAttr + pSerAttr->ulValueLen)) goto error_exit;

        ret = (CK_ATTRIBUTE_PTR)realloc(ret, sizeof (*ret) * (*nrAttributes + 1));
        CK_ATTRIBUTE_PTR pAttr = ret + *nrAttributes;
        pAttr->type = pSerAttr->type;
        pAttr->ulValueLen = pSerAttr->ulValueLen;
        if ((pAttr->pValue = malloc(pSerAttr->ulValueLen)) == NULL) goto error_exit;
        memcpy(pAttr->pValue, pSerAttr->pValue, pSerAttr->ulValueLen);
        dataLen -= (sizeof *pSerAttr + pSerAttr->ulValueLen);
        data = data + (sizeof *pSerAttr + pSerAttr->ulValueLen);
        *nrAttributes = *nrAttributes + 1;
    }
    return ret;
error_exit:
    if (ret) {
        CK_ULONG i;
        for (i=0; i< *nrAttributes; i++) if (ret[i].pValue) free(ret[i].pValue);
        free(ret);
    }
    return NULL;
}

uint8_t *attributeSerialize(CK_ATTRIBUTE *pAttribute, CK_ULONG nrAttributes, size_t *pDataLen){
    uint8_t *ret = NULL;
    *pDataLen = 0;
    while (nrAttributes > 0) {
        ret = (uint8_t *) realloc(ret, *pDataLen + pAttribute->ulValueLen + sizeof pAttribute->type + sizeof pAttribute->ulValueLen);
        *((CK_ATTRIBUTE_TYPE *)(ret + *pDataLen))= pAttribute->type;
        *((CK_ULONG *)(ret + *pDataLen + sizeof pAttribute->type))= pAttribute->ulValueLen;
        *pDataLen = *pDataLen + sizeof pAttribute->type + sizeof pAttribute->ulValueLen;
        memcpy(ret + (*pDataLen), pAttribute->pValue, pAttribute->ulValueLen);
        nrAttributes -= 1;
        *pDataLen = *pDataLen + pAttribute->ulValueLen;
        pAttribute++;
    }
    return ret;
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attr2map(CK_ATTRIBUTE_PTR pAttr, CK_ULONG ulAttrCount) {
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap;
    do {
        attrMap[pAttr->type] = pAttr;
        pAttr++;
    } while (--ulAttrCount != 0);
    return attrMap;
}


//   New
CK_ATTRIBUTE_PTR getAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type) {
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    it = attrMap.find(type);
    if (it == attrMap.end()) return NULL;
    return it->second;
}

CK_RV matchUlAttr(CK_ATTRIBUTE *p, CK_ULONG ul) {
    if (p) {
        if (sizeof(CK_ULONG) != p->ulValueLen) return CKR_ATTRIBUTE_VALUE_INVALID;
        if (*((CK_ULONG *)p->pValue) != ul) return CKR_TEMPLATE_INCONSISTENT;
    }
    return CKR_OK;
}

CK_BBOOL getAttrBool(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultVale, CK_BBOOL *boolValue) {
    CK_ATTRIBUTE *pAttr;
    if ((pAttr = getAttr(attrMap, type)) == NULL) {
        *boolValue = defaultVale;
    } else {
        if (pAttr->ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
        *boolValue = *((CK_BBOOL *)pAttr->pValue);
    }
    return CKR_OK;
}

CK_ATTRIBUTE *map2attr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> m, CK_ULONG *pAttrLenth){
	int i;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
	CK_ATTRIBUTE *pRes;
    if ((pRes = (CK_ATTRIBUTE *)malloc(sizeof *pRes * m.size())) == NULL) {
		return NULL;
	};
	for (i=0, it=m.begin(); it != m.end(); it++, i++){
		CK_ATTRIBUTE_PTR pDest = pRes + i;
		CK_ATTRIBUTE_PTR pSrc = it->second;
		if ((pDest->pValue = malloc(pSrc->ulValueLen)) == NULL) {
			return NULL;
		}
		memcpy(pDest->pValue, pSrc->pValue, pSrc->ulValueLen);
		pDest->ulValueLen = pSrc->ulValueLen;
		pDest->type = pSrc->type;
	}
	*pAttrLenth = (CK_ULONG)i;
	return pRes;
}


CK_ATTRIBUTE_PTR attrMerge(
		CK_ATTRIBUTE_PTR pA, CK_ULONG aLen, CK_ATTRIBUTE_PTR  pB, CK_ULONG bLen, CK_ULONG *pAttrLength) {
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a = attr2map(pA, aLen);
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b = attr2map(pB, bLen);

	a.insert(b.begin(), b.end());
	CK_ATTRIBUTE_PTR ret=map2attr(a, pAttrLength);
	a.clear();
	b.clear();
	return ret;
}


bool checkAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, uint8_t *pValue, CK_ULONG ulValueLen){
    CK_ATTRIBUTE_PTR pAttr;
    if ((pAttr = getAttr(attrMap, type)) == NULL) return false;
    if (ulValueLen != pAttr->ulValueLen) return false;
    if (CRYPTO_memcmp(pAttr->pValue, pValue, ulValueLen) == 0) return true;
    return false;
}
