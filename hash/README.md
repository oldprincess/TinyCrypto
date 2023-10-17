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

需要处理器支持Intel的SSSE3和PCLMUL指令集，需要添加编译参数`-mssse3 -mpclmul`（使用MSVC编译器除外）

```
-mssse3 -mpclmul
```

## MD5

* md5 standard

> RFC 1321: The MD5 Message-Digest Algorithm
> https://www.rfc-editor.org/rfc/rfc1321

```
gcc -o main.exe md5_standard.c test_md5_standard.c
```

## SHA1

> FIPS 180-4 Secure Hash Standard (SHS), 
> https://csrc.nist.gov/pubs/fips/180-4/upd1/final

* sha1 standard

> RFC 3174: US Secure Hash Algorithm 1 (SHA1),
> https://www.rfc-editor.org/rfc/rfc3174

```
gcc -o main.exe sha1_standard.c test_sha1_standard.c
```

## SM3

> GB/T 32905-2016 信息安全技术 SM3密码杂凑算法

> GB/T 32905-2016 Information security techniques—SM3 cryptographic hash algorithm

* sm3 fast

> 杨先伟,康红娟.SM3杂凑算法的软件快速实现研究[J].智能系统学报,2015,10(06):954-959.

> YANG Xianwei, KANG Hongjuan. Fast software implementation of SM3 Hash algorithm[J]. CAAI Transactions on Intelligent Systems, 2015, 10(2): 954-95.

```
gcc -o main.exe sm3_fast.c test_sm3_fast.c
```