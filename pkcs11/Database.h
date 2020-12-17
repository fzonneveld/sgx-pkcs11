#pragma once
#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <stdint.h>
#include <sqlite3.h>

class Database {
private:
    sqlite3 *db=NULL;
    bool newlyCreated=true;
public:
	Database(const char *pDbFileName);
    bool IsNewDatabase();
    int SetRootKey(uint8_t *rootKey, size_t rootKeyLength);
    uint8_t *GetRootKey(size_t& rootKeyLength);
    int getToken(CK_SLOT_ID slotID, uint8_t **ppLabel, size_t& labelLength, uint8_t **ppSOpin, size_t& SOpinLength, uint8_t **ppUserPIN, size_t& userPINlength);
    int initToken(CK_SLOT_ID slotID, uint8_t *pLabel, size_t labelLength, uint8_t *pSOpin, size_t SOpinLength, uint8_t *pUserPIN, size_t userPINlength);
    int updateToken(CK_SLOT_ID slotID, uint8_t *pLabel, size_t labelLength);
    int updateUserPin(CK_SLOT_ID slotID, uint8_t *pUserPin, size_t userPinLength);
    int setObject(CK_KEY_TYPE type, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_ATTRIBUTE *pAttributes, CK_ULONG ulAttributeCount);
    int deleteObject(CK_OBJECT_HANDLE hObject);
    int getObject(CK_OBJECT_HANDLE hObject, uint8_t **ppValue, size_t& valueLen, CK_ATTRIBUTE **ppAttribute, CK_ULONG& ulAttrCount);
    CK_OBJECT_HANDLE *getObjectIds(CK_ATTRIBUTE *pTemlate, CK_ULONG ulCount, int& nrFound);
	~Database();
};

#endif
