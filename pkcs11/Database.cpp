#include <exception>
#include <stdexcept>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "pkcs11-interface.h"

#include "Database.h"



#define CREATE_DB \
	"CREATE TABLE RootKey(value BLOB);" \
    "CREATE TABLE Token(slotID INTEGER, label BLOB, soPIN BLOB, userPIN BLOB);" \
	"CREATE TABLE Object(ID INTEGER NOT NULL PRIMARY KEY, objectClass INTEGER, value BLOB);" \
	"CREATE TABLE Attribute(" \
         "ID INTEGER" \
         ", attributeType INTEGER" \
         ", value BLOB" \
         ", objectID INTEGER REFERENCES Object(id)" \
    ");"


Database::Database(const char * pDbFileName) {
    struct stat st;
    this->newlyCreated = true ? stat(pDbFileName, &st) < 0 : false;

    if (SQLITE_OK != sqlite3_open(pDbFileName, &this->db)) {
        throw std::runtime_error("Cannot open DB");
    }
    if (this->newlyCreated) {
        char sql[] = CREATE_DB;
        if (SQLITE_OK != sqlite3_exec(db, sql, NULL, 0, NULL)) {
            throw std::runtime_error("Cannot create DB");
        }
    };
}

int Database::SetRootKey(uint8_t *rootKey, size_t rootKeyLength){
	sqlite3_stmt *pStmt;
    char sql[] = "INSERT INTO RootKey(value) VALUES(?);";
    int rc;
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL))
        return -1;
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 1, rootKey, rootKeyLength, SQLITE_STATIC))
        return -1;
    if (SQLITE_DONE != (rc = sqlite3_step(pStmt))) {
        return -1;
    }
    sqlite3_finalize(pStmt);
    return 0;
}

uint8_t *getBlob(sqlite3_stmt *pStmt, int iCol, size_t& length) {
    uint8_t *ret = NULL;
    length = sqlite3_column_bytes(pStmt, iCol);
    if (NULL == (ret = (uint8_t *) malloc(length)))
        goto getBlob_err;
    memcpy(ret, sqlite3_column_blob(pStmt, iCol), length);
getBlob_err:
    return ret;
}


uint8_t *Database::GetRootKey(size_t& rootKeyLength) {
	sqlite3_stmt *pStmt;
    char sql[] = "SELECT value FROM RootKey LIMIT 1;";
    uint8_t *ret = NULL;
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL))
        return ret;
    if (SQLITE_ROW != sqlite3_step(pStmt))
        return ret;
    if (NULL == (ret = getBlob(pStmt, 0, rootKeyLength)))
        return NULL;
    sqlite3_finalize(pStmt);
    return ret;
}

int Database::deleteObject(CK_OBJECT_HANDLE hObject) {
    int ret = -1;
    std::string s = std::to_string(hObject);
    std::string sql = \
        "DELETE FROM Object WHERE id=" + s + ";"
        "DELETE FROM Attribute WHERE objectID=" + s + ";";

    if (SQLITE_OK != sqlite3_exec(this->db, sql.c_str(), 0, 0, NULL))
        goto deleteObject_err;
    ret = 0;
deleteObject_err:
    return ret;
}

int Database::getObject(CK_OBJECT_HANDLE hObject, uint8_t **ppValue, size_t& valueLen, CK_ATTRIBUTE **ppAttribute, CK_ULONG& ulAttrCount) {
    int rc;
    int res = -1;
	sqlite3_stmt *pStmt = NULL;
    CK_ATTRIBUTE *pAttribute = NULL;
    const char *sql = "SELECT value FROM Object WHERE ID=?";

    if (ppValue == NULL || ppAttribute == NULL)
        goto getObject_err;
    res -= 1;
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL)) {
        goto getObject_err;
    }
    res -= 1;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, (int) hObject)) {
        goto getObject_err;
    }
    res -= 1;

    if (SQLITE_ROW != (rc = sqlite3_step(pStmt))) {
        goto getObject_err;
    }
    res -= 1;
    valueLen = sqlite3_column_bytes(pStmt, 0);
    if (NULL == (*ppValue = (CK_BYTE *)malloc(valueLen))) {
        goto getObject_err;
    }
    res -= 1;
    memcpy(*ppValue, sqlite3_column_blob(pStmt,0), valueLen);
    res -= 1;
    sqlite3_finalize(pStmt);
    sql = "SELECT attributeType, value FROM Attribute WHERE objectID=? ORDER BY id";
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL)) {
        goto getObject_err;
    }
    res -= 1;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, (int) hObject)) {
        goto getObject_err;
    }
    ulAttrCount = 0;
    while (SQLITE_ROW == (rc = sqlite3_step(pStmt))){
        ulAttrCount++;
        CK_ATTRIBUTE *pAttr=NULL;
        pAttribute = (CK_ATTRIBUTE *)realloc(pAttribute, sizeof *pAttribute * ulAttrCount);
        pAttr = pAttribute + (ulAttrCount - 1);
        pAttr->type = sqlite3_column_int(pStmt, 0);
        pAttr->ulValueLen = sqlite3_column_bytes(pStmt, 1);
        if (NULL == (pAttr->pValue = (CK_BYTE *)malloc(pAttr->ulValueLen))) {
            goto getObject_err;
        }
        memcpy(pAttr->pValue, sqlite3_column_blob(pStmt,1), pAttr->ulValueLen);
    }
    *ppAttribute = pAttribute;
    res = 0;
getObject_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return res;
}



CK_OBJECT_HANDLE *Database::getObjectIds(CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount, int& nrFound) {
    int rc;
    CK_OBJECT_HANDLE *res = NULL;
    CK_ULONG i=0;
    int found = 0;

    nrFound = -1;
	sqlite3_stmt *pStmt = NULL;
    if (NULL == pTemplate) {
        std::string sql = "SELECT ID FROM Object";
        if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql.c_str(), -1, &pStmt, NULL)) {
            goto getObjectIds_err;
        }
    } else {
        std::string sql = "SELECT Object.id,COUNT(Object.id) FROM Object JOIN Attribute ON Object.id=objectID ";
        for (CK_ULONG i=0; i<ulCount; i++) {
            if (i==0)
                sql.append(" WHERE ");
            else
                sql.append(" OR ");
            sql.append(" (AttributeType=?  AND Attribute.value=?) ");
        }
        sql.append(" GROUP BY Object.id");
        sql.append(" HAVING COUNT(Object.id) = ?");
        if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql.c_str(), -1, &pStmt, NULL)) {
            goto getObjectIds_err;
        }
        for (i=0; i<ulCount; i++) {
            if (SQLITE_OK != sqlite3_bind_int(pStmt, (i * 2) + 1, pTemplate[i].type))
                goto getObjectIds_err;
            if (SQLITE_OK != sqlite3_bind_blob(pStmt, (i *2) + 2, pTemplate[i].pValue, pTemplate[i].ulValueLen, SQLITE_STATIC))
                goto getObjectIds_err;
        }
        if (SQLITE_OK != sqlite3_bind_int(pStmt, (i * 2) + 1, ulCount))
            goto getObjectIds_err;
    }

    while (SQLITE_ROW == (rc = sqlite3_step(pStmt))){
        found++;
        if (NULL == (res = (CK_OBJECT_HANDLE *)realloc(res, sizeof *res * found))) {
           if (res) free(res);
           goto getObjectIds_err;
        }
        res[found - 1] = (CK_OBJECT_HANDLE) sqlite3_column_int(pStmt, 0);
    }
    if (SQLITE_DONE != rc) {
        if (res) free(res);
        goto getObjectIds_err;
    }
    nrFound = found;
getObjectIds_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return res;
}


int Database::getToken(CK_SLOT_ID slotID, uint8_t **ppLabel, size_t& labelLength, uint8_t **ppSOpin, size_t& SOpinLength, uint8_t **ppUserPIN, size_t& userPINlength)
{
    int ret = -1, rc;
	sqlite3_stmt *pStmt = NULL;
    const char *sql = "SELECT label, soPIN, userPIN FROM Token WHERE slotID=?";
    *ppLabel = *ppSOpin = *ppUserPIN = NULL;
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL))
        goto getToken_err;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, (int) slotID))
        goto getToken_err;
    rc = sqlite3_step(pStmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(pStmt);
        return 0;
    }
    if (rc != SQLITE_ROW) goto getToken_err;
    if (ppLabel && NULL == (*ppLabel = getBlob(pStmt, 0, labelLength)))
        goto getToken_err;
    if (ppSOpin && NULL == (*ppSOpin = getBlob(pStmt, 1, SOpinLength)))
        goto getToken_err;
    if (ppUserPIN && NULL == (*ppUserPIN = getBlob(pStmt, 2, userPINlength)))
        goto getToken_err;
    if (SQLITE_DONE != (rc = sqlite3_step(pStmt))) goto getToken_err;
    ret = 1;
    goto getToken_ok;
getToken_err:
    if (*ppLabel) free(*ppLabel);
    if (*ppSOpin) free(*ppSOpin);
    if (*ppUserPIN) free(*ppUserPIN);
    *ppLabel = *ppSOpin = *ppUserPIN = NULL;
getToken_ok:
    if (pStmt) sqlite3_finalize(pStmt);
    return ret;
}


int Database::updateUserPin(CK_SLOT_ID slotID, uint8_t *pUserPin, size_t userPinLength) {
    int ret = -1;
	sqlite3_stmt *pStmt = NULL;
    const char *sql = "UPDATE Token SET userPIN=? WHERE slotID=?;";
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL)) {
        fprintf(stderr,"SQL error: %s\n", sqlite3_errmsg(this->db));
        goto setUserPIN_err;
    }
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 1, pUserPin, userPinLength, SQLITE_STATIC))
        goto setUserPIN_err;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 2, slotID))
        goto setUserPIN_err;
    if (SQLITE_DONE != sqlite3_step(pStmt)) goto setUserPIN_err;
    ret = 0;
setUserPIN_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return ret;
}


int Database::initToken(CK_SLOT_ID slotID, uint8_t *pLabel, size_t labelLength, uint8_t *pSOpin, size_t SOpinLength, uint8_t *pUserPin, size_t userPinLength) {
    int ret = -1;
	sqlite3_stmt *pStmt = NULL;
    const char *sql = "INSERT INTO Token(slotID, label, soPIN)  VALUES(?,?,?);";

    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL)) {
        fprintf(stderr,"SQL error: %s\n", sqlite3_errmsg(this->db));
        goto initToken_err;
    }
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, slotID))
        goto initToken_err;
    ret -=1;
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 2, pLabel, labelLength, SQLITE_STATIC))
        goto initToken_err;
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 3, pSOpin, SOpinLength, SQLITE_STATIC))
        goto initToken_err;
    if (SQLITE_DONE != sqlite3_step(pStmt)) goto initToken_err;
    sqlite3_finalize(pStmt);
    pStmt = NULL;
    if (NULL != pUserPin && 0 != this->updateUserPin(slotID, pUserPin, userPinLength))
        goto initToken_err;
    ret = 0;
initToken_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return ret;
}



int Database::updateToken(CK_SLOT_ID slotID, uint8_t *pLabel, size_t labelLength){
    int ret = -1;
	sqlite3_stmt *pStmt = NULL;
    const char *sql = "UPDATE Token SET label=? WHERE slotId=?";
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL)) {
        fprintf(stderr,"SQL error: %s\n", sqlite3_errmsg(this->db));
        goto updateToken_err;
    }
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 1, pLabel, labelLength, SQLITE_STATIC))
        goto updateToken_err;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 2, slotID))
        goto updateToken_err;
    ret = 0;
updateToken_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return ret;
}





int Database::setObject(CK_KEY_TYPE type, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_ATTRIBUTE *pAttribute, CK_ULONG ulAttributeCount) {
    bool rollback = true;
	sqlite3_stmt *pStmt, *pStmtA = NULL;
    rollback = true;
    char sql[] = "INSERT INTO Object(objectClass, value) VALUES(?, ?);";
    char sqlA[] = "INSERT INTO Attribute(ID, attributeType, value, objectID) VALUES(?,?,?,?);";
    int ret = -1, id;
    CK_ULONG i;
    int rc;
    if (SQLITE_OK != sqlite3_exec(db, "BEGIN", 0, 0, 0))
        goto setObject_err;
    ret -=1;
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL))
        goto setObject_err;
    ret -=1;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, type))
        goto setObject_err;
    ret -=1;
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 2, pValue, ulValueLen, SQLITE_STATIC))
        goto setObject_err;
    ret -=1;
    if (SQLITE_DONE != (rc = sqlite3_step(pStmt)))
        goto setObject_err;
    ret -=1;
    id = sqlite3_last_insert_rowid(this->db);
    for  (i=0; i<ulAttributeCount; i++, pAttribute++) {
        if (SQLITE_OK != sqlite3_prepare_v2(this->db, sqlA, -1, &pStmtA, NULL))
            goto setObject_err;
        if (SQLITE_OK != sqlite3_bind_int(pStmtA, 1, i))
            goto setObject_err;
        if (SQLITE_OK != sqlite3_bind_int(pStmtA, 2, pAttribute->type))
            goto setObject_err;
        if (SQLITE_OK != sqlite3_bind_blob(pStmtA, 3, pAttribute->pValue, pAttribute->ulValueLen, SQLITE_STATIC))
            goto setObject_err;
        if (SQLITE_OK != sqlite3_bind_int(pStmtA, 4, id))
            goto setObject_err;
        if (SQLITE_DONE != (rc = sqlite3_step(pStmtA)))
            goto setObject_err;
        sqlite3_finalize(pStmtA);
        pStmtA = NULL;
    }
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    rollback = false;
    ret = id;
setObject_err:
    if (pStmtA) sqlite3_finalize(pStmtA);
    if (pStmt) sqlite3_finalize(pStmt);
    if (rollback == true) sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
    return ret;
}



bool Database::IsNewDatabase(){
    return this->newlyCreated;
}

Database::~Database() {
    sqlite3_close(this->db);
}


