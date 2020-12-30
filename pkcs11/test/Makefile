OPENSSL_PATH ?= /usr/local/ssl
OBJECTS = attribute.o
TEST_OBJECTS = tst.o
LDLIBS = -lssl -lcrypto -lstdc++ -lcunit -lpthread

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
Enclave_Include_Paths := -I../../cryptoki

App_Include_Paths := -Ipkcs11 -I$(SGX_SDK)/include -I$(OPENSSL_PATH)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Flags := $(App_C_Flags) -fpermissive 

tst: $(TEST_OBJECTS) $(OBJECTS)

$(TEST_OBJECTS): %.o: %.cpp
	$(CXX) -c $(App_Cpp_Flags) -o $@ $^

$(OBJECTS): %.o: ../%.cpp
	$(CXX) -c $(App_Cpp_Flags) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)

checkvars:
	@echo "SOURCES=$(SOURCES)"
	@echo "OBJECTS=$(OBJECTS)"
