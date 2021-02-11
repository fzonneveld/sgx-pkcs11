#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sgx_tseal.h"
#include "sgx_trts.h"

#include "../AttributeSerial.h"

sgx_status_t sgx_read_rand(uint8_t *buf, size_t size){
    int i;
    for (i=0;i<(int)size; i++) buf[i] = '\xAA';
    return SGX_SUCCESS;
}

sgx_status_t sgx_seal_data(uint32_t additional_MACtext_length,
    const uint8_t *p_additional_MACtext,
    uint32_t text2encrypt_length,
    const uint8_t *p_text2encrypt,
    uint32_t sealed_data_size,
    sgx_sealed_data_t *p_sealed_data) {
        return SGX_SUCCESS;
}


uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size, const uint32_t txt_encrypt_size){
    return SGX_SUCCESS;
}

sgx_status_t SGXAPI sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data, uint8_t *p_additional_MACtext, uint32_t *p_additional_MACtext_length, uint8_t *p_decrypted_text, uint32_t *p_decrypted_text_length) {
    return SGX_SUCCESS;
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

void printAttr(uint8_t *pAttr, size_t attrLen){
    size_t nrAttributes;

    AttributeSerial a = AttributeSerial(pAttr, attrLen);
    CK_ATTRIBUTE_PTR attr = a.attributes(nrAttributes);
    printf("\n");
    for (size_t i=0; i<nrAttributes; i++) {
        CK_ATTRIBUTE_PTR a = attr + i;
        printf("Attribute[%04lu] type 0x%08lx, value[%lu] ", i, a->type, a->ulValueLen);
        for (size_t j=0; j<a->ulValueLen; j++) {
            printf("%02X ", ((uint8_t *)a->pValue)[j]);
        }
        printf("\n");
    }
}




sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                                const uint8_t *p_src,
                                                uint32_t src_len,
                                                uint8_t *p_dst,
                                                const uint8_t *p_iv,
                                                uint32_t iv_len,
                                                const uint8_t *p_aad,
                                                uint32_t aad_len,
                                                sgx_aes_gcm_128bit_tag_t *p_out_mac){
    memcpy(p_dst, p_src, src_len);
    return SGX_SUCCESS;
}

sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                                const uint8_t *p_src,
                                                uint32_t src_len,
                                                uint8_t *p_dst,
                                                const uint8_t *p_iv,
                                                uint32_t iv_len,
                                                const uint8_t *p_aad,
                                                uint32_t aad_len,
                                                const sgx_aes_gcm_128bit_tag_t *p_in_mac){
    memcpy(p_dst, p_src, src_len);
    return SGX_SUCCESS;
}
