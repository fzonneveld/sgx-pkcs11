#include <stdint.h>
#include "sgx_tseal.h"


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
