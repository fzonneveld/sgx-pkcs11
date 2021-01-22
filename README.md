# PKCS#11 implementation in Intel SGX enclaves

## Extended original sgx-pkcs11 with following features:
  * Root key can be set per enclave. Root keys are sealed and enclave specific
  * Bit size for RSA keys can be specified
  * PKCS11 Objects are stored sealed in SQLite3 DB as PKCS11 objects
  * PKCS11 Objects can be listed, and retrieved as handles
  * PKCS11 Objects are stored in DB GCM ecnrypted and authenticated using rootKey
  * Attributes of PKCS11 Objects are authenticated as metadata
  * Attributes are serialized and added as authentication for PKCS#11 objects
  * root key can be randomly generated
  * root key can be loaded using Shamir secre Sharing Scheme with a prime
    set to first prime number from 2<<256 downwards, which is 0xFF{31},0X43.
  * This makes it possible to dowload 32 bytes root keys in shares.

## Wishlist:
  * Add support for EC
  * Add support for symmetric key generation

## Build
1. Install the [SGX driver](https://github.com/intel/linux-sgx-driver);
2. Install the [SGX SDK and SGX PSW](https://github.com/intel/linux-sgx):
    * when you'll be asked where to install SGX SDK, enter `/opt/intel`;
3. Compile SGX SSL Library:
   * Download [openssl-1.1.1*.tar.gz](https://www.openssl.org/source/openssl-1.1.1c.tar.gz).
   * Download [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl).
   * Move `openssl-1.1.1*.tar.gz` into `intel-sgx-ssl/openssl_source`
   * Compile intel-sgx-ssl:
        ```
        cd intel-sgx-ssl/Linux
        make all test
        sudo make install
        ```
4.  Clone this project.
5.  Compile this project:
    ```
    cd SGX-PKCS11
    make
    ```
