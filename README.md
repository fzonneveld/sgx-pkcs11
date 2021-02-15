# PKCS#11 implementation in Intel SGX enclaves

This is a fork from https://github.com/mlavacca/sgx-pkcs11

The main goal of this forl is to create a fully functional
PKCS#11 device, where all the keys are protected using
the SGX enclave architecture.

Sealing key is used to protect a root key. Root key can be
randomly generated, but also loaded using Shamir Seret Sharing Scheme.
The root key protects all the keys in the DB (sqlite3).
This design allows a cluster of machines to use the same root
key and therefore transfer PKCS#11 objects from one machine
to another.


## Extended original sgx-pkcs11 with following features:
  * Root key to protect all data in enclave
     * Are sealed and enclave specific
     * Can be randomly generated or
     * Can be loaded using Shamir secre Sharing Scheme with a prime
       set to first prime number from 2<<256 downwards, which is 0xFF{31},0X43.
     * Are 32 bytes root keys in shares.

  * PKCS11 Objects
     * Are stored encrypted using root key  in SQLite3 DB as PKCS11 objects
     * Can be listed, and retrieved as handles
     * stored in DB GCM ecnrypted and authenticated using rootKey
     * Its Attributes are authenticated as metadata

## Wishlist:
  * Add support for symmetric key generation
  * Add support for remote attestaion


## Testing

CUnit is used for testing and needs to be installed:

```
    $ sudo apt-get install libcunit1-dev
```

After this 2 different makefile rules are provided for testing:
```
    $ make test_pkcs11

    $ make  test_enclave.
```

Both run the tests and should not result in errors.


## Build (Copy from the original code)
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
