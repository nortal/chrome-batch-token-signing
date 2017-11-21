COMPILER=G++
C = cpp
CC = cc
OUTPUT_PATH = out/
SOURCE_PATH = host/
SMARTCARDPP_SOURCE_PATH = smartcardpp/
JSON_SOURCE_PATH = json/
TEST_PATH = test/
EXE = $(OUTPUT_PATH)chrome-digidoc-signing
TEST_EXE = $(OUTPUT_PATH)chrome-digidoc-signing-test

OBJ = o
COPT = -O2
CCMD = g++
OBJFLAG = -o
EXEFLAG = -o
INCLUDES = -Ismartcardpp -Igooglemock/include -Igooglemock/gtest/include -Ihost -Ijson -Ipkcs11 -I/usr/include/openssl `pkg-config --cflags gtk+-3.0` `pkg-config --cflags gtkmm-3.0` `pkg-config --cflags libpcsclite`
LIBS = -ldl `pkg-config --libs gtk+-3.0` `pkg-config --libs gtkmm-3.0` `pkg-config --libs libpcsclite` `pkg-config --libs openssl`
LIBPATH = 
CPPFLAGS = $(COPT) -g $(INCLUDES) -std=c++0x -pthread 
LDFLAGS = $(LIBPATH) -g $(LIBS)
DEP = dep
GTEST_DIR=googlemock/gtest
GMOCK_DIR=googlemock

test: PP = -D_TEST

OBJS := $(patsubst %.$(C),%.$(OBJ),$(wildcard $(SOURCE_PATH)*.$(C)))
SMARTCARDPP_OBJS := $(patsubst %.$(C),%.$(OBJ),$(wildcard $(SMARTCARDPP_SOURCE_PATH)*.$(C)))
JSON_OBJS := $(patsubst %.$(CC),%.$(OBJ),$(wildcard $(JSON_SOURCE_PATH)*.$(CC)))
JSON_OBJS := $(filter-out $(JSON_SOURCE_PATH)jsonxx_test.o, $(JSON_OBJS))	
TEST_OBJS := $(patsubst %.$(C),%.$(OBJ),$(wildcard $(TEST_PATH)*.$(C)))

%.$(OBJ):%.$(C)
	@echo Compiling $(basename $<)...
	$(CCMD) -c $(CPPFLAGS) $(CXXFLAGS) $(PP) $< $(OBJFLAG)$@ 

all: $(JSON_OBJS) $(SMARTCARDPP_OBJS) $(OBJS)
	mkdir -p $(OUTPUT_PATH)
	@echo Linking...
	$(CCMD) $(LDFLAGS) $^ $(LIBS) $(EXEFLAG) $(EXE)
	
test: $(JSON_OBJS) $(SMARTCARDPP_OBJS) $(filter-out $(SOURCE_PATH)chrome-host.o, $(OBJS)) $(TEST_OBJS)
	$(CCMD) -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -isystem ${GMOCK_DIR}/include -I${GMOCK_DIR} -pthread -c ${GTEST_DIR}/src/gtest-all.cc
	$(CCMD) -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -isystem ${GMOCK_DIR}/include -I${GMOCK_DIR} -pthread -c ${GMOCK_DIR}/src/gmock-all.cc
	ar -rv libgmock.a gtest-all.o gmock-all.o
	mkdir -p $(OUTPUT_PATH)
	$(CCMD) -isystem ${GMOCK_DIR}/include -isystem ${GTEST_DIR}/include -pthread \
	$(LDFLAGS) $^ libgmock.a $(LIBS) $(EXEFLAG) $(TEST_EXE)
	$(TEST_EXE) --gtest_output=xml:test_report.xml
	
clean:
	rm -rf $(SOURCE_PATH)*.$(OBJ) $(EXE) $(SMARTCARDPP_SOURCE_PATH)*.$(OBJ) $(TEST_PATH)*.$(OBJ)
	rm -rf googlemock/make/g*

install:
	cp $(EXE) /usr/bin
	mkdir -p /etc/opt/chrome/native-messaging-hosts
	cp ee.ria.esteid.json /etc/opt/chrome/native-messaging-hosts/