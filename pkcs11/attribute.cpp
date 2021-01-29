#include <stdio.h>
#include <map>
#include <openssl/crypto.h>
#include "attribute.h"
#include <stdio.h>

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

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrSerialized2map(const uint8_t *data, size_t dataLen) {
    CK_ULONG nrAttributes;
    CK_ATTRIBUTE_PTR pAttr = attributeDeserialize(data, dataLen, &nrAttributes);
    if (pAttr == NULL) throw std::invalid_argument("Cannot parse attributes");
    auto attrMap = attr2map(pAttr, nrAttributes);
    return attrMap;
}

uint8_t *attributeSerialize(CK_ATTRIBUTE *pAttribute, CK_ULONG nrAttributes, size_t *pDataLen){
    uint8_t *ret = NULL;
    *pDataLen = 0;
    // Enforce the order of the map, which is by type
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrmap = attr2map(pAttribute, nrAttributes);
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    for (it=attrmap.begin(); it != attrmap.end(); it++) {
        CK_ATTRIBUTE_PTR pAttr=it->second;;
        ret = (uint8_t *) realloc(ret, *pDataLen + pAttr->ulValueLen + sizeof pAttr->type + sizeof pAttr->ulValueLen);
        *((CK_ATTRIBUTE_TYPE *)(ret + *pDataLen))= pAttr->type;
        *((CK_ULONG *)(ret + *pDataLen + sizeof pAttr->type))= pAttr->ulValueLen;
        *pDataLen = *pDataLen + sizeof pAttr->type + sizeof pAttr->ulValueLen;
        memcpy(ret + (*pDataLen), pAttr->pValue, pAttr->ulValueLen);
        nrAttributes -= 1;
        *pDataLen = *pDataLen + pAttr->ulValueLen;
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


CK_ATTRIBUTE_PTR getAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type) {
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    it = attrMap.find(type);
	return it == attrMap.end() ? NULL : it->second;
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

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>  attrMergeMaps(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b){
	a.insert(b.begin(), b.end());
    return a;
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

bool attrcmp(CK_ATTRIBUTE_PTR a, CK_ATTRIBUTE_PTR b){
	if (a->type != b->type) return false;
	if (a->ulValueLen != b->ulValueLen) return false;
	return memcmp(a->pValue, b->pValue, a->ulValueLen) == 0 ? true : false;
}


bool checkAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, uint8_t *pValue, CK_ULONG ulValueLen){
    CK_ATTRIBUTE_PTR pAttr;
    if ((pAttr = getAttr(attrMap, type)) == NULL) return false;
    if (ulValueLen != pAttr->ulValueLen) return false;
    if (CRYPTO_memcmp(pAttr->pValue, pValue, ulValueLen) == 0) return true;
    return false;
}


int attrMap2serialized(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, uint8_t  *pSerialAttr, size_t serializedAttrLen, size_t *pSerializedAttrLenOut) {
	CK_ATTRIBUTE_PTR pAttr;
	size_t nrAttributes;
	uint8_t *sa;
	size_t saLen;

	if ((pAttr = map2attr(attrMap, &nrAttributes)) == NULL) return -1;
	if ((sa = attributeSerialize(pAttr , nrAttributes, &saLen)) == NULL) return -1;
	if (pSerialAttr == NULL) return -1;
	if (saLen > serializedAttrLen) {
		free(sa);
		return -1;
	}
	memcpy(pSerialAttr, sa, saLen);
	*pSerializedAttrLenOut = saLen;
	free(sa);
	return 0;
}


Attribute::Attribute(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes){
    do {
        this->attrMap[pAttr->type] = pAttr;
        pAttr++;
    } while (--nrAttributes != 0);
}

Attribute::Attribute(const uint8_t *pSerialized, size_t serializedLen) {
    this->nrAttributes = 0;
    while (serializedLen != 0) {
        serializedAttr *pSerAttr = (serializedAttr *)pSerialized;
        if (serializedLen < sizeof *pSerAttr) {
            if (this->pAttr) free(pAttr);
            throw std::runtime_error("Invalid attributes");
        }
        if (pSerAttr->ulValueLen == 0 || serializedLen < (sizeof *pSerAttr + pSerAttr->ulValueLen)) {
            if (this->pAttr) free(this->pAttr);
            throw std::runtime_error("Invalid attributes");
        }
        if ((this->pAttr = (CK_ATTRIBUTE_PTR)realloc(this->pAttr, sizeof (*this->pAttr) * (this->nrAttributes + 1))) == NULL)
            throw std::runtime_error("Invalid attributes");
        CK_ATTRIBUTE_PTR pAttr = this->pAttr + this->nrAttributes;
        pAttr->type = pSerAttr->type;
        pAttr->ulValueLen = pSerAttr->ulValueLen;
        pAttr->pValue = pSerAttr->pValue;
        serializedLen -= (sizeof *pSerAttr + pSerAttr->ulValueLen);
        pSerialized = pSerialized + (sizeof *pSerAttr + pSerAttr->ulValueLen);
        this->nrAttributes += 1;
    }
    for (CK_ULONG i=0; i< this->nrAttributes; i++) {
        CK_ATTRIBUTE_PTR a = this->pAttr + i;
        this->attrMap[a->type] = a;
    }
}

uint8_t *Attribute::serialize(size_t *pDataLen){
    uint8_t *ret = NULL;
    *pDataLen = 0;
    // Enforce the order of the map, which is by type
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    for (it=this->attrMap.begin(); it != this->attrMap.end(); it++) {
        CK_ATTRIBUTE_PTR pAttr=it->second;;
        ret = (uint8_t *) realloc(ret, *pDataLen + pAttr->ulValueLen + sizeof pAttr->type + sizeof pAttr->ulValueLen);
        *((CK_ATTRIBUTE_TYPE *)(ret + *pDataLen))= pAttr->type;
        *((CK_ULONG *)(ret + *pDataLen + sizeof pAttr->type))= pAttr->ulValueLen;
        *pDataLen = *pDataLen + sizeof pAttr->type + sizeof pAttr->ulValueLen;
        memcpy(ret + (*pDataLen), pAttr->pValue, pAttr->ulValueLen);
        nrAttributes -= 1;
        *pDataLen = *pDataLen + pAttr->ulValueLen;
    }
    return ret;
}

CK_ATTRIBUTE_PTR Attribute::get(CK_ATTRIBUTE_TYPE type){
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    it = this->attrMap.find(type);
    if (it == this->attrMap.end()) return NULL;
    return it->second;
}


bool Attribute::check(CK_ATTRIBUTE_TYPE type, CK_ULONG ul) {
    CK_ATTRIBUTE_PTR p = this->get(type);
    if (p == NULL) return false;
    if (sizeof(CK_ULONG) != p->ulValueLen) return false;
    if (*((CK_ULONG *)p->pValue) != ul) return false;
    return true;
}


CK_ULONG *Attribute::checkIn(CK_ATTRIBUTE_TYPE type, CK_ULONG *uls, size_t nrUl) {
    CK_ATTRIBUTE_PTR p = this->get(type);
    if (p == NULL) return NULL;
    if (sizeof(CK_ULONG) != p->ulValueLen) return NULL;
    for (CK_ULONG i=0; i<nrUl; i++) {
        if (*((CK_ULONG *)p->pValue) == uls[i]) return (CK_ULONG *)p->pValue;
    }
    return NULL;
}


std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> Attribute::map() {
    return this->attrMap;
}


Attribute::~Attribute() {
    if (this->pAttr) free(this->pAttr);
}
