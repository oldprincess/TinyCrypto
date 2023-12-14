# TinyCrypto

简单的C++语言密码算法合集，包括各种优化手段的代码。一部分是我自己写的，一部分是从其它密码库中引用的，**如有侵权，请联系我删除（issue）**


## 快速开始

1. `TinyCrypto`库能够嵌入到c++语言的项目中，稍作修改也能够嵌入到c语言的项目

虽然代码的后缀是.cpp，但是我在写的时候并没有用到c++的特性（除了`namespace`），这意味着这些代码稍作修改就可以写成.c结尾的文件。唯一需要修改的地方是命名空间的区域，每个.h和.cpp中的代码都被`namespace tc{...};`包裹，将这个命名空间删去就可以改写成c语言风格的代码。

2. `TinyCrypto`库提供了许多密码算法，算法和算法之间耦合度低，可以很方便地进行裁剪，挑选出需要的算法

在每个子文件夹中都有README文件，README文件说明了每个密码算法的编译方式和参考文献。例如AES算法的查表优化，如果需要使用该算法，只需要进入cipher/aes文件夹，拷贝aes_lut.h和aes_lut.cpp即可。README文件中还说明了编译测试文件的方式，AES查表优化的测试文件是test_aes_lut.cpp，代码被宏定义`TINY_CRYPTO_TEST`包裹，编译时需要加上`-DTINY_CRYPTO_TEST`。

```
cd TinyCrypto/cipher/aes
g++ -DTINY_CRYPTO_TEST -o main.exe aes_lut.cpp test_aes_lut.cpp
```

3. `TinyCrypto`库还支持采用cmake构建动态库

在CMakeLists.txt文件中定义（set）了算法是否启用的标识`ENABLE_<算法类别>_<算法名称>`，可以通过修改文件来决定将哪些算法编译进动态库dll，并提供了导出头文件（*.h）的开关`EXPORT_HEADER`（默认关闭）。

* windows平台

```
mkdir build
cd build
cmake ..
cmake --build . --config=Release
```

## 算法介绍

### 分组密码算法 —— cipher

[link](./docs/cipher.md)

* AES
* Ballet
* DES
* SM4
* uBlock

### 编码算法 —— encoding

[link](./docs/encoding.md)

* Base64
* str

### 哈希算法 —— hash

[link](./docs/hash.md)

* GHash
* MD5
* SHA1
* SHA2
* SM3

### 公钥密码 —— pkc

[link](./docs/pkc.md)

* SM2