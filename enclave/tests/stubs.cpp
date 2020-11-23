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
