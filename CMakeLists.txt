cmake_minimum_required(VERSION 3.4)

project(TinyCrypto)

# set compiler options
if (MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS True)
endif()

# set cmake options, if ON, export headers to include/TinyCrypto/...
set(EXPORT_HEADER OFF)

# set build cipher suites
set(ENABLE_CIPHER_AES_AESNI         ON)
set(ENABLE_CIPHER_AES_LUT           ON)
set(ENABLE_CIPHER_BALLET_STANDARD   ON)
set(ENABLE_CIPHER_DES_COMMON        ON)
set(ENABLE_CIPHER_SM4_COMMON        ON)
set(ENABLE_CIPHER_SM4_LUT           ON)
set(ENABLE_CIPHER_UBLOCK_COMMON     ON)
set(ENABLE_CIPHER_UBLOCK_STANDARD   ON)
set(ENABLE_ENCODING_BASE64_AVX2     ON)
set(ENABLE_ENCODING_BASE64_CHROMIUM ON)
set(ENABLE_ENCODING_BASE64          ON)
set(ENABLE_ENCODING_STR_BINARY      ON)
set(ENABLE_ENCODING_STR_HEXADECIMAL ON)
set(ENABLE_HASH_GHASH_COMMON        ON)
set(ENABLE_HASH_GHASH_LUT256        ON)
set(ENABLE_HASH_GHASH_PCLMUL        ON)
set(ENABLE_HASH_MD5_STANDARD        ON)
set(ENABLE_HASH_SHA1_STANDARD       ON)
set(ENABLE_HASH_SHA2_STANDARD       ON)
set(ENABLE_HASH_SM3_FAST            ON)
set(ENABLE_PKC_BN_UINT              ON)
set(ENABLE_PKC_BN_UINT256_MONT      ON)
set(ENABLE_PKC_BN_UINT256           ON)
set(ENABLE_PKC_SM2_SM2P256V1        ON)

# cipher suites source files

if(ENABLE_CIPHER_AES_AESNI)
    list(APPEND TC_SOURCE_FILES cipher/aes/aes_aesni.cpp)
endif()

if(ENABLE_CIPHER_AES_LUT)
    list(APPEND TC_SOURCE_FILES cipher/aes/aes_lut.cpp)
endif()

if(ENABLE_CIPHER_BALLET_STANDARD)
    list(APPEND TC_SOURCE_FILES cipher/ballet/ballet_standard.cpp)
endif()

if(ENABLE_CIPHER_DES_COMMON)
    list(APPEND TC_SOURCE_FILES cipher/des/des_common.cpp)
endif()

if(ENABLE_CIPHER_SM4_COMMON)
    list(APPEND TC_SOURCE_FILES cipher/sm4/sm4_common.cpp)
endif()

if(ENABLE_CIPHER_SM4_LUT)
    list(APPEND TC_SOURCE_FILES cipher/sm4/sm4_lut.cpp)
endif()

if(ENABLE_CIPHER_UBLOCK_COMMON)
    list(APPEND TC_SOURCE_FILES cipher/ublock/ublock_common.cpp)
endif()

if(ENABLE_CIPHER_UBLOCK_STANDARD)
    list(APPEND TC_SOURCE_FILES cipher/ublock/ublock_standard.cpp)
endif()

if(ENABLE_ENCODING_BASE64_AVX2)
    list(APPEND TC_SOURCE_FILES encoding/base/base64_avx2.cpp)
endif()

if(ENABLE_ENCODING_BASE64_CHROMIUM)
    list(APPEND TC_SOURCE_FILES encoding/base/base64_chromium.cpp)
endif()

if(ENABLE_ENCODING_BASE64)
    list(APPEND TC_SOURCE_FILES encoding/base/base64.cpp)
endif()

if(ENABLE_ENCODING_STR_BINARY)
    list(APPEND TC_SOURCE_FILES encoding/str/binary.cpp)
endif()

if(ENABLE_ENCODING_STR_HEXADECIMAL)
    list(APPEND TC_SOURCE_FILES encoding/str/hexadecimal.cpp)
endif()

if(ENABLE_HASH_GHASH_COMMON)
    list(APPEND TC_SOURCE_FILES hash/ghash/ghash_common.cpp)
endif()

if(ENABLE_HASH_GHASH_LUT256)
    list(APPEND TC_SOURCE_FILES hash/ghash/ghash_lut256.cpp)
endif()

if(ENABLE_HASH_GHASH_PCLMUL)
    list(APPEND TC_SOURCE_FILES hash/ghash/ghash_pclmul.cpp)
endif()

if(ENABLE_HASH_MD5_STANDARD)
    list(APPEND TC_SOURCE_FILES hash/md5/md5_standard.cpp)
endif()

if(ENABLE_HASH_SHA1_STANDARD)
    list(APPEND TC_SOURCE_FILES hash/sha1/sha1_standard.cpp)
endif()

if(ENABLE_HASH_SHA2_STANDARD)
    list(APPEND TC_SOURCE_FILES hash/sha2/sha2_standard.cpp)
endif()

if(ENABLE_HASH_SM3_FAST)
    list(APPEND TC_SOURCE_FILES hash/sm3/sm3_fast.cpp)
endif()

if(ENABLE_PKC_BN_UINT)
    list(APPEND TC_SOURCE_FILES pkc/bn/uint.cpp)
endif()

if(ENABLE_PKC_BN_UINT256_MONT)
    if(NOT ENABLE_PKC_BN_UINT256)
        message(FATAL_ERROR "BN_UINT256_MONT need BN_UINT256")
    endif()
    list(APPEND TC_SOURCE_FILES pkc/bn/uint256_mont.cpp)
endif()

if(ENABLE_PKC_BN_UINT256)
    list(APPEND TC_SOURCE_FILES pkc/bn/uint256.cpp)
endif()

if(ENABLE_PKC_SM2_SM2P256V1)
    if(NOT ENABLE_PKC_BN_UINT256_MONT OR NOT ENABLE_PKC_BN_UINT256)
        message(FATAL_ERROR "SM2_SM2P256V1 need BN_UINT256_MONT and BN_UINT256")
    endif()
    list(APPEND TC_SOURCE_FILES pkc/sm2/sm2p256v1.cpp)
endif()

file(GLOB_RECURSE TC_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/cipher/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/encoding/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hash/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/math/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/pkc/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/stream/*.h
)

# build library
add_library(tinycrypto SHARED ${TC_HEADER_FILES} ${TC_SOURCE_FILES})

# export header(*.h)
if(EXPORT_HEADER)
    message(STATUS "start copy header files")
    foreach(_file ${TC_HEADER_FILES})
        string(REPLACE 
            ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}/include/TinyCrypto 
            result ${_file}
        )
        file(COPY ${_file} DESTINATION ${result})
        message(STATUS "copy file to " ${result})
    endforeach(_file )
    message(STATUS "finish copy header files")
endif()