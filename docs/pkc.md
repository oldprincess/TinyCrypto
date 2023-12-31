# TinyCrypto -- PKC

国家标准GB查询：https://openstd.samr.gov.cn/bzgk/gb/index

行业标准GM查询：http://www.gmbz.org.cn/main/bzlb.html

## bn

* uint

```
g++ -DTINY_CRYPTO_TEST -o main.exe uint.cpp test_uint.cpp
```

* uint256

```
g++ -DTINY_CRYPTO_TEST -o main.exe uint256.cpp test_uint256.cpp
```

* uint256 mont

```
g++ -DTINY_CRYPTO_TEST -o main.exe uint256.cpp uint256_mont.cpp test_uint256_mont.cpp
```

## SM2

> GB/T 32918.1-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则\
> GB/T 32918.1-2016 Information security technology—Public key cryptographic algorithm SM2 based on elliptic curves—Part 1: General

> GB/T 32918.2-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法\
> GB/T 32918.2-2016 Information security technology—Public key cryptographic algorithm SM2 based on elliptic curves—Part 2: Digital signature algorithm

> GB/T 32918.3-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议\
> GB/T 32918.3-2016 Information security technology—Public key cryptographic algorithm SM2 based on elliptic curves—Part 3: Key exchange protocol

> GB/T 32918.4-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法\
> GB/T 32918.4-2016 Information security technology—Public key cryptographic algorithm SM2 based on elliptic curves—Part 4: Public key encryption algorithm

> GB/T 32918.5-2017 信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义\
> GB/T 32918.5-2017 Information security technology—Public key cryptographic algorithm SM2 based on elliptic curves—Part 5: Parameter definition

* sm2p256v1 asn.1

> GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范\
> GB/T 35275-2017 Information security technology—SM2 cryptographic algorithm encrypted signature message syntax specification

```
g++ -DTINY_CRYPTO_TEST -o main.exe test_sm2p256v1_asn1.cpp sm2p256v1_asn1.cpp ../../encoding/str/hexadecimal.cpp ../../encoding/asn1/asn1.cpp
```

* sm2p256v1

> 椭圆曲线Jacobian+Affine
> http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl

> 椭圆曲线Jacobian二倍点
> http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b

> 椭圆曲线Jacobian点加
> http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl

> 蒙哥马利模乘
> https://en.wikipedia.org/wiki/Montgomery_modular_multiplication

```
g++ -DTINY_CRYPTO_TEST -o main.exe test_sm2p256v1.cpp sm2p256v1.cpp ../bn/uint256.cpp ../bn/uint256_mont.cpp
```