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
	"CREATE TABLE Object(id INTEGER NOT NULL PRIMARY KEY, objectClass INTEGER, value BLOB);" \
	"CREATE TABLE Attribute(" \
         "id INTEGER" \
         ", attributeType INTEGER" \
         ", value BLOB" \
         ", objectId INTEGER REFERENCES Object(id)" \
    ");"


Database::Database(const char * pDbFileName) {
    struct stat st;
    this->newlyCreated = true ? stat(pDbFileName, &st) < 0 : false;

    if (SQLITE_OK != sqlite3_open(pDbFileName, &this->db)) {
        throw std::runtime_error("Cannot open DB");
    }
    printf("%s: %i\n", __FILE__, __LINE__);
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

uint8_t *Database::GetRootKey(size_t *rootKeyLength) {
	sqlite3_stmt *pStmt;
    char sql[] = "SELECT value FROM RootKey LIMIT 1;";
    uint8_t *ret = NULL;
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL))
        return ret;
    if (SQLITE_ROW != sqlite3_step(pStmt))
        return ret;
    *rootKeyLength = sqlite3_column_bytes(pStmt, 0);
    uint8_t *rootKey = (uint8_t *) sqlite3_column_blob(pStmt, 0);
    if (NULL == (ret = (uint8_t *) malloc(*rootKeyLength)))
        return NULL;
    memcpy(ret, rootKey, *rootKeyLength);
    sqlite3_finalize(pStmt);
    return ret;
}

int Database::deleteObject(CK_OBJECT_HANDLE hObject) {
    int ret = -1;
    int rc;
	sqlite3_stmt *pStmt = NULL;
    char sql[] = "DELETE FROM Attribute WHERE objectId=?";
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL))
        goto deleteObject_err;
    ret -= 1;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, (int)hObject))
        goto deleteObject_err;
    //printf("%s\n", sqlite3_expanded_sql(pStmt));
    ret -= 1;
    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
        goto deleteObject_err;
    }
    ret = 0;
deleteObject_err:
    if (pStmt) sqlite3_finalize(pStmt);
    return ret;
}

int Database::getObject(CK_OBJECT_HANDLE hObject, uint8_t **ppValue, size_t& valueLen, CK_ATTRIBUTE **ppAttribute, CK_ULONG& ulAttrCount) {
    int rc;
    int res = -1;
	sqlite3_stmt *pStmt = NULL;
    std::string sql = "SELECT Object.value FROM Object where id=?";
    CK_ATTRIBUTE *pAttribute = NULL;

    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql.c_str(), -1, &pStmt, NULL)) {
        goto getObject_err;
    }
    printf("%s\n", sqlite3_expanded_sql(pStmt));
    if (SQLITE_ROW == sqlite3_step(pStmt))
        goto getObject_err;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, (int) hObject))
        goto getObject_err;
    sqlite3_finalize(pStmt);
    sql = "SELECT type, value, FROM Attribute WHERE id=? ORDER BY id";
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql.c_str(), -1, &pStmt, NULL)) {
        goto getObject_err;
    }
    ulAttrCount = 0;
    while (SQLITE_ROW == (rc = sqlite3_step(pStmt))){
        ulAttrCount++;
        CK_ATTRIBUTE *pAttr;
        pAttribute = (CK_ATTRIBUTE *)realloc(pAttribute, sizeof *pAttribute * ulAttrCount);
        pAttr = (*ppAttribute) + ulAttrCount - 1;
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
    std::string sql = "SELECT Object.id,COUNT(Object.id) FROM Object JOIN Attribute ON Object.id=objectId ";
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
    // printf("%s\n", sqlite3_expanded_sql(pStmt));

    while (SQLITE_ROW == (rc = sqlite3_step(pStmt))){
        found++;
        if (NULL == (res = (CK_OBJECT_HANDLE *)realloc(res, sizeof *res * found))) {
           if (res) free(res);
           goto getObjectIds_err;
        }
        res[found - 1] = (CK_OBJECT_HANDLE) sqlite3_column_int(pStmt, 0);
        printf("%lu\n", res[found - 1]);
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


int Database::setObject(CK_KEY_TYPE type, CK_BYTE_PTR pValue, CK_ULONG ulValueLen, CK_ATTRIBUTE *pAttribute, CK_ULONG ulAttributeCount) {
    bool rollback = false;
	sqlite3_stmt *pStmt, *pStmtA = NULL;
    rollback = true;
    char sql[] = "INSERT INTO Object(objectClass, value) VALUES(?, ?);";
    char sqlA[] = "INSERT INTO Attribute(id, attributeType, value, objectId) VALUES(?,?,?,?);";
    int ret = -1, id;
    CK_ULONG i;
    int rc;
    if (SQLITE_OK != sqlite3_exec(db, "BEGIN", 0, 0, 0))
        goto setObject_err;
    if (SQLITE_OK != sqlite3_prepare_v2(this->db, sql, -1, &pStmt, NULL))
        goto setObject_err;
    if (SQLITE_OK != sqlite3_bind_int(pStmt, 1, type))
        goto setObject_err;
    if (SQLITE_OK != sqlite3_bind_blob(pStmt, 2, pValue, ulValueLen, SQLITE_STATIC))
        goto setObject_err;
    if (SQLITE_DONE != (rc = sqlite3_step(pStmt)))
        goto setObject_err;
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
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
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


