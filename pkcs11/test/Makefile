OPENSSL_PATH ?= /usr/local/ssl
# LOCAL_OBJECTS=stubs.o
OBJECTS = Attribute.o AttributeSerial.o pkcs11.o Database.o CryptoEntity.o
C_OBJECTS = crypto_engine_u.o
TEST_OBJECTS = tst.o test_pkcs11.o test_attribute.o

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl

SGX_COMMON_CFLAGS += -O0 -g
SGX_SSL_LIB := $(SGX_SSL)/lib64
LDLIBS = -L$(SGX_SSL_LIB) -lssl -lcrypto -lsqlite3 -lstdc++ -lcunit -lsgx_usgxssl -lsgx_uae_service -lsgx_urts -lpthread

Enclave_Include_Paths := -I../../cryptoki

App_Include_Paths := -Ipkcs11 -I$(SGX_SDK)/include -I$(OPENSSL_PATH)/include
CXXFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -fpermissive

tst:  $(LOCAL_OBJECTS) $(TEST_OBJECTS) $(OBJECTS) $(C_OBJECTS)


$(TEST_OBJECTS) $(LOCAL_OBJECTS): %.o: %.cpp ../../PKCS11_crypto_engine.signed.so

$(OBJECTS): %.o: ../%.cpp
	$(CXX) -c $(CXXFLAGS) -o $@ $^

$(C_OBJECTS): %.o: ../%.c
	$(CXX) -c $(CXXFLAGS) -o $@ $^

../../PKCS11_crypto_engine.signed.so:
	make -C ../.. PKCS11_crypto_engine.signed.so

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(LOCAL_OBJECTS)

checkvars:
	@echo "SOURCES=$(SOURCES)"
	@echo "OBJECTS=$(OBJECTS)"
