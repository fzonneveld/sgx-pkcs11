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
    uint8_t *GetRootKey(size_t *rootKeyLength);
    int setObject(CK_KEY_TYPE type, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_ATTRIBUTE *pAttributes, CK_ULONG ulAttributeCount);
    int deleteObject(CK_OBJECT_HANDLE hObject);
    int getObject(CK_OBJECT_HANDLE hObject, uint8_t **ppValue, size_t& valueLen, CK_ATTRIBUTE **ppAttribute, CK_ULONG& ulAttrCount);
    CK_OBJECT_HANDLE *getObjectIds(CK_ATTRIBUTE *pTemlate, CK_ULONG ulCount, int& nrFound);
	~Database();
};

#endif
