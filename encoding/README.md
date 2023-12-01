# TinyCrypto--encoding

## base

* base64 chromium

> Copyright (c) 2015-2016, Wojciech Muła, Alfred Klomp,  Daniel Lemire. (Unless otherwise stated in the source code) All rights reserved.
> https://github.com/lemire/fastbase64/blob/master/src/chromiumbase64.c

> Copyright (c) 2005, 2006, Nick Galbreath -- nickg [at] modp [dot] com. All rights reserved.\
> Released under bsd license.  See modp_b64.c for details.

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64_chromium.cpp test_base64_chromium.cpp
```

* base64

> RFC 4648: The Base16, Base32, and Base64 Data Encodings
> https://www.rfc-editor.org/rfc/rfc4648

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64.cpp test_base64.cpp
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