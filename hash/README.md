# TinyCrypto -- Hash

国家标准GB查询：https://openstd.samr.gov.cn/bzgk/gb/index

行业标准GM查询：http://www.gmbz.org.cn/main/bzlb.html

## GHash

需要进一步测试

> Dworkin M. Recommendation for block cipher modes of operation: Galois/Counter Mode (GCM) and GMAC[R]. National Institute of Standards and Technology, 2007.
> https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

* ghash common

* ghash lut

> McGrew D, Viega J. The Galois/counter mode of operation (GCM)[J]. submission to NIST Modes of Operation Process, 2004, 20: 0278-0070.
> https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

* ghash pclmul

> Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode.
> https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf

> Copyright (c) 2010 Intel Corporation. All rights reserved.

需要处理器支持Intel的SSSE3和PCLMUL指令集，需要添加编译参数`-mssse3 -mpclmul`（使用MSVC编译器除外）

```
-mssse3 -mpclmul
```

## MD5

* md5 standard

> RFC 1321: The MD5 Message-Digest Algorithm
> https://www.rfc-editor.org/rfc/rfc1321

> Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.

```
g++ -DTINY_CRYPTO_TEST -o main.exe md5_standard.cpp test_md5_standard.cpp
```

## SHA1

> FIPS 180-4 Secure Hash Standard (SHS), 
> https://csrc.nist.gov/pubs/fips/180-4/upd1/final

* sha1 standard

> Copyright (c) 2011 IETF Trust and the persons identified as authors of the code.  All rights reserved.

> RFC 3174: US Secure Hash Algorithm 1 (SHA1),
> https://www.rfc-editor.org/rfc/rfc3174

```
g++ -DTINY_CRYPTO_TEST -o main.exe sha1_standard.cpp test_sha1_standard.cpp
```

## SHA2

> FIPS 180-4 Secure Hash Standard (SHS)
> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

* sha2 standard

> US Secure Hash Algorithms(SHA and SHA-based HMAC and HKDF)
> https://www.rfc-editor.org/rfc/rfc6234

> Copyright (c) 2011 IETF Trust and the persons identified as authors of the code.  All rights reserved.

sha224, sha256, sha384, sha512

```
g++ -DTINY_CRYPTO_TEST -o main.exe sha2_standard.cpp test_sha2_standard.cpp
```

## SM3

> GB/T 32905-2016 信息安全技术 SM3密码杂凑算法\
> GB/T 32905-2016 Information security techniques—SM3 cryptographic hash algorithm

* sm3 fast

> 杨先伟,康红娟.SM3杂凑算法的软件快速实现研究[J].智能系统学报,2015,10(06):954-959.\
> YANG Xianwei, KANG Hongjuan. Fast software implementation of SM3 Hash algorithm[J]. CAAI Transactions on Intelligent Systems, 2015, 10(2): 954-95.

```
g++ -DTINY_CRYPTO_TEST -o main.exe sm3_fast.cpp test_sm3_fast.cpp
```