#include <exception>
#include <stdexcept>
#include <sqlite3.h>
#include "CryptoEntity.h"

CryptoEntity::CryptoEntity() {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_launch_token_t launch_token = { 0 };
	int updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	auto fp = fopen(this->kTokenFile, "rb");
	if (fp == nullptr) {
		if ((fp = fopen(this->kTokenFile, "wb")) == nullptr) {
			throw std::runtime_error("Failed to create the launch token file.");
		}
	}

	else {
		// read the token from saved file
		const size_t read_num = fread(launch_token, 1,
			sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			// if token is invalid, clear the buffer
			memset(&launch_token, 0, sizeof(sgx_launch_token_t));
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	ret = sgx_create_enclave(this->kEnclaveFile, SGX_DEBUG_FLAG, &launch_token, &updated, &this->enclave_id_, NULL);
	if (ret != SGX_SUCCESS) {
        printf("%s:%i\n", __FILE__, __LINE__);
		throw std::runtime_error("Failed to create enclave.");
	}

	// Step 3: save the launch token if it is updated
	if (updated) {
		fp = freopen(this->kTokenFile, "wb", fp);
		if (fp == nullptr) {
			throw std::runtime_error("Failed to save launch token.");
		}
		const std::size_t write_num = fwrite(launch_token, 1, sizeof(sgx_launch_token_t), fp);
		if (write_num != sizeof(sgx_launch_token_t)) {
			throw std::runtime_error("Failed to save launch token.");
		}
	}
	fclose(fp);
}

void CryptoEntity::RSAKeyGeneration(char* publicKey, char* privateKey) {
	sgx_status_t stat;
    int ret;

	stat = SGXgenerateRSAKeyPair(this->enclave_id_, &ret, publicKey, privateKey, KEY_SIZE, 2048);
	if (stat != SGX_SUCCESS)
		throw new std::exception;
	if (ret != 0)
		throw new std::exception;
}

void CryptoEntity::RSAInitEncrypt(char* key) {
	this->initializedKey = key;
}

#if 0
void printhex(const char *s, unsigned char *buf, unsigned long length){
    int i;
    printf("%s\n", s);
    for (i=0; i< (int)length; i++) {
        if ((i % 16) == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}
#endif


unsigned char* CryptoEntity::RSAEncrypt(const unsigned char* plainData, size_t plainDataLength, size_t* cipherLength) {
	sgx_status_t ret;
	unsigned char* cipherData = (unsigned char*)malloc(CIPHER_BUFFER_LENGTH * sizeof(unsigned char));
    int retval;

	ret = SGXEncryptRSA(this->enclave_id_, &retval, this->initializedKey, strlen(this->initializedKey),
		plainData, plainDataLength, cipherData, CIPHER_BUFFER_LENGTH, cipherLength);
    
	if (ret != SGX_SUCCESS || retval != 0)
		throw std::runtime_error("Encryption failed\n");
	return cipherData;
}

void CryptoEntity::RSAInitDecrypt(char* key) {
	this->initializedKey = key;
}


uint8_t* CryptoEntity::RSADecrypt(const uint8_t* cipherData, size_t cipherDataLength, size_t* plainLength) {
	sgx_status_t stat;
    int max_rsa_size = 8 * 1024;

	uint8_t* plainData = (uint8_t*)malloc(max_rsa_size * sizeof(uint8_t));
    int retval;
	stat = SGXDecryptRSA(
            this->enclave_id_,
            &retval,
			this->initializedKey, KEY_SIZE,
			cipherData, cipherDataLength,
			plainData, max_rsa_size, plainLength);
	if (stat != SGX_SUCCESS || retval != 0) {
		throw std::runtime_error("Decryption failed\n");
    }
	return plainData;
}

CryptoEntity::~CryptoEntity() {
	sgx_destroy_enclave(this->enclave_id_);
}
