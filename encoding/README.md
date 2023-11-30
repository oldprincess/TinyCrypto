# TinyCrypto--encoding

## str

* base64

> RFC 4648: The Base16, Base32, and Base64 Data Encodings
> https://www.rfc-editor.org/rfc/rfc4648

```
g++ -DTINY_CRYPTO_TEST -o main.exe base64.cpp test_base64.cpp
```

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