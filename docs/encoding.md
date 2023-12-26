# TinyCrypto--encoding

## asn1

* asn1

> X.680-X.693 : Information Technology - Abstract Syntax Notation One (ASN.1) & ASN.1 encoding rules. 
> https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en

```
g++ -DTINY_CRYPTO_TEST -o main.exe asn1.cpp test_asn1.cpp
```

## base

* base64 avx2

> Copyright (c) 2015-2016, Wojciech Muła, Alfred Klomp,  Daniel Lemire. (Unless otherwise stated in the source code) All rights reserved.
> https://github.com/lemire/fastbase64/blob/master/src/klompavxbase64.c

> BSD. Copyright (c) 2013-2015, Alfred Klomp. All rights reserved.

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64_avx2.cpp test_base64_avx2.cpp -mavx2
```

* base64 chromium

> Copyright (c) 2015-2016, Wojciech Muła, Alfred Klomp,  Daniel Lemire. (Unless otherwise stated in the source code) All rights reserved.
> https://github.com/lemire/fastbase64/blob/master/src/chromiumbase64.c

> Copyright (c) 2005, 2006, Nick Galbreath -- nickg [at] modp [dot] com. All rights reserved.\
> Released under bsd license.  See modp_b64.c for details.

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64_chromium.cpp test_base64_chromium.cpp
```

* base64 common

> RFC 4648: The Base16, Base32, and Base64 Data Encodings
> https://www.rfc-editor.org/rfc/rfc4648

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64_common.cpp test_base64_common.cpp
```

## str

* binary

二进制转换

```
g++ -DTINY_CRYPTO_TEST -o main.exe binary.cpp test_binary.cpp
```

* hexadecimal

十六进制转换

```
g++ -DTINY_CRYPTO_TEST -o main.exe hexadecimal.cpp test_hexadecimal.cpp
```