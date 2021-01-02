OPENSSL_PATH ?= /usr/local/ssl
LOCAL_OBJECTS=stubs.o
OBJECTS = attribute.o pkcs11.o Database.o CryptoEntity.o
TEST_OBJECTS = tst.o test_pkcs11.o test_attribute.o
LDLIBS = -lssl -lcrypto -lsqlite3 -lstdc++ -lcunit -lpthread

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
Enclave_Include_Paths := -I../../cryptoki

App_Include_Paths := -Ipkcs11 -I$(SGX_SDK)/include -I$(OPENSSL_PATH)/include
CXXFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -fpermissive

tst:  $(LOCAL_OBJECTS) $(TEST_OBJECTS) $(OBJECTS)


$(TEST_OBJECTS) $(LOCAL_OBJECTS): %.o: %.cpp

$(OBJECTS): %.o: ../%.cpp
	$(CXX) -c $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(LOCAL_OBJECTS)

checkvars:
	@echo "SOURCES=$(SOURCES)"
	@echo "OBJECTS=$(OBJECTS)"
