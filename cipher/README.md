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
gcc -o main.exe aes_lut.c test_aes_lut.c 
```

* aes-aesni

>  MIT License, Copyright (c) 2023 Jubal Mordecai Velasco, @cite https://github.com/mrdcvlsc/AES/blob/main/AES.hpp

> Intel Intrinsics Guide. https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html

需要处理器支持Intel的AES指令集，需要添加编译参数`-maes`（使用MSVC编译器除外）

```
gcc -o main.exe -maes aes_aesni.c test_aes_aesni.c
```

## SM4

> GB/T 32907-2016 信息安全技术 SM4分组密码算法

> GB/T 32907-2016 Information security technology—SM4 block cipher algorthm

* sm4-common

```
gcc -o main.exe sm4_common.c test_sm4_common.c 
```

* sm4-lut

> 郎欢,张蕾,吴文玲.SM4的快速软件实现技术[J].中国科学院大学学报,2018,35(02):180-187.

> Lang H, Zhang L, Wu W L. Fast software implementation of SM4[J]. Journal of University of Chinese Academy of Sciences, 2018, 35(2): 180-187.

```
gcc -o main.exe sm4_lut.c test_sm4_lut.c 
```

## uBlock

> 吴文玲, 张蕾, 郑雅菲, 李灵琛. 分组密码 uBlock[J]. 密码学报, 2019, 6(6): 690–703.

> WU W L, ZHANG L, ZHENG Y F, LI L C. The block cipher uBlock[J]. Journal of Cryptologic Research, 2019, 6(6): 690–703.

> 全国密码算法设计竞赛分组算法（按第一设计者姓氏笔画为序）
> https://sfjs.cacrnet.org.cn/site/term/list_73_1.html

需要处理器支持Intel的SSSE3指令集，需要添加编译参数`-mssse3`（使用MSVC编译器除外）

```
gcc -o main.exe ublock_standard.c test_ublock_standard.c -mssse3
```