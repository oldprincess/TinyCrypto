# TinyCrypto -- Cipher

国家标准GB查询：https://openstd.samr.gov.cn/bzgk/gb/index

行业标准GM查询：http://www.gmbz.org.cn/main/bzlb.html

## AES

> FIPS 197. Advanced Encryption Standard (AES).
> https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

* aes-lut

> J.Daemen, V.Rijmen. The Design of Rijndael[M]. Berlin: Springer, 2020: 53-63. 
> https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf

```
g++ -DTINY_CRYPTO_TEST -o main.exe aes_lut.cpp test_aes_lut.cpp
```

* aes-aesni

>  MIT License, Copyright (c) 2023 Jubal Mordecai Velasco, @cite https://github.com/mrdcvlsc/AES/blob/main/AES.hpp

> Intel Intrinsics Guide. https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html

需要处理器支持Intel的AES指令集，需要添加编译参数`-maes`（使用MSVC编译器除外）

```
g++ -DTINY_CRYPTO_TEST -o main.exe -maes aes_aesni.cpp test_aes_aesni.cpp
```

## DES

> FIPS 46-3: Data Encryption Standard (DES)
> https://csrc.nist.gov/pubs/fips/46-3/final

> NIST SP 800-67 Rev. 2: Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
> https://csrc.nist.gov/pubs/sp/800/67/r2/final

* des common

```
g++ -DTINY_CRYPTO_TEST -o main.exe des_common.cpp test_des_common.cpp
```

## SM4

> GB/T 32907-2016 信息安全技术 SM4分组密码算法

> GB/T 32907-2016 Information security technology—SM4 block cipher algorthm

* sm4-common

```
g++ -DTINY_CRYPTO_TEST -o main.exe sm4_common.cpp test_sm4_common.cpp 
```

* sm4-lut

> 郎欢,张蕾,吴文玲.SM4的快速软件实现技术[J].中国科学院大学学报,2018,35(02):180-187.

> Lang H, Zhang L, Wu W L. Fast software implementation of SM4[J]. Journal of University of Chinese Academy of Sciences, 2018, 35(2): 180-187.

```
g++ -DTINY_CRYPTO_TEST -o main.exe sm4_lut.cpp test_sm4_lut.cpp
```

## uBlock

> 吴文玲, 张蕾, 郑雅菲, 李灵琛. 分组密码 uBlock[J]. 密码学报, 2019, 6(6): 690–703.

> WU W L, ZHANG L, ZHENG Y F, LI L C. The block cipher uBlock[J]. Journal of Cryptologic Research, 2019, 6(6): 690–703.

* ublock common

```
g++ -DTINY_CRYPTO_TEST -o main.exe ublock_common.cpp test_ublock_common.cpp
```

* ublock standard

> 全国密码算法设计竞赛进入第二轮分组算法
> https://sfjs.cacrnet.org.cn/site/term/list_76_1.html

需要处理器支持Intel的SSSE3指令集，需要添加编译参数`-mssse3`（使用MSVC编译器除外）

```
g++ -DTINY_CRYPTO_TEST -o main.exe ublock_standard.cpp test_ublock_standard.cpp -mssse3
```