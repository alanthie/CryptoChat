cmake_minimum_required(VERSION 3.28)
project(lnx_chatsrv)

set(CMAKE_CXX_STANDARD 20)

include(FindCURL)
find_package(CURL REQUIRED)

if (NOT CURL_FOUND)
    message (FATAL_ERROR "Curl is not supported")
endif (NOT CURL_FOUND)

include_directories(CURL_INCLUDE_DIRS)

set(CMAKE_REQUIRED_LIBRARIES "${CURL_LIBRARIES}")
list(APPEND LIBS "${CURL_LIBRARIES}")

LINK_DIRECTORIES(/usr/lib/x86_64-linux-gnu)

include_directories(../../wide-decimal  /usr/include)

add_executable(lnx_chatsrv
        ../src/Base64.cpp
        ../src/chat_server_main.cpp
        ../src/crc32a.cpp
        ../src/crypto_file.cpp
        ../src/crypto_keymgr.cpp
        ../src/crypto_server.cpp
        ../src/encdec_algo.cpp
        ../src/encrypt.cpp
        ../src/includes.cpp
        ../src/machineid.cpp
        ../src/netw_msg.cpp
        ../src/SHA256.cpp
        ../src/socket_node.cpp
        ../src/srv_test.cpp
        ../src/twofish.c
        ../src/twofish_cfb.c
        ../src/vigenere.cpp
        ../include/AESa.cpp
        ../include/DES.cpp
        ../include/SymAlg.cpp
        ../include/exclusive-lock-file.cpp
	    ../include/qa/SystemProperties.cpp

        ../include/qa/Bin2PNG/lodepng.cpp
        ../include/qa/RSA-GMP/RSAGMP.cpp
        ../include/qa/RSA-GMP/RSAGMPPrime.cpp
        ../include/qa/RSA-GMP/RSAGMPTest.cpp
        ../include/qa/RSA-GMP/RSAGMPUtils.cpp
        ../include/qa/RSA_generate/bigint/BigInteger.cc
        ../include/qa/RSA_generate/bigint/BigIntegerAlgorithms.cc
        ../include/qa/RSA_generate/bigint/BigIntegerUtils.cc
        ../include/qa/RSA_generate/bigint/BigUnsigned.cc
        ../include/qa/RSA_generate/bigint/BigUnsignedInABase.cc
        ../include/qa/RSA_generate/bigint/BigUnsignedInABase.hh
        ../include/qa/RSA_generate/bigint/NumberlikeArray.hh
        ../include/qa/RSA_generate/bigint/run-testsuite

        ../include/qa/ecc_point/ecc_curve.cpp
        ../include/qa/ecc_point/ecc_elgamal.cpp
        ../include/qa/rsa_gen.cpp
)


link_libraries(gmp curl openssl nghttp2 gssapi2 ${LIBS})

target_link_libraries(lnx_chatsrv
/usr/lib/x86_64-linux-gnu/libgmp.a
#curl
${LIBS}
)
