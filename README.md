# PKCS#11 implementation in Intel SGX enclaves

## Extended original sgx-pkcs11 with following features:
  * Root key can be set per enclave. Root keys are sealed and enclave specific
  * Bit size for RSA keys can be specified
  * RSA keys are stored in SQLite3 DB as PKCS11 objects
  * Objects can be listed, and retrieved as handles
  * Objects are stored in DB GCM ecnrypted and authenticated using rootKey
  * Attributes are serialized and added as authentication for PKCS#11 objects

## Wishlist:
  * Add support for C_login, needs to have a little bit of thought how to link it
    to the objects. See comments below.
  * Add support for EC
  * Add support for symmetric key generation
  * Enable loading of rootkey (outside of PKCS11 interface) using Shamir Secret Sharing Scheme (SSSS)

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

## Wishlist: C_Login

We can link the C_Login token to an object, but we cannot link it to a PIN,
because PIN's can cahnge.  Linking the object to a static token idx does not
help, we can just remove the token, reinit it with a PIN and the objects can
still be accessed. We need to randomize the token generiation every time we do
an init.  When we do an C_InitToken with a SO_PIN we give back a random UUID.
