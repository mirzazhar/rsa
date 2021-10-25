# RSA (Rivest–Shamir–Adleman)
This package is implemented according to the pseudo-code and mathematical notations of the following algorithms of RSA cryptosystem:
 - Key Generation
 - Encryption Scheme
   - Encryption
   - Decryption
 - Signature Scheme
   - Signature Generation
   - Signature Verification

RSA has [multiplicative homomorphic encryption property](https://dl.acm.org/doi/pdf/10.1145/3214303) and is an early example of Partially Homomorphic Encryption (PHE). Therefore, the multiplication of ciphers results in the product of original numbers.

Moreover, it also supports the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers



## Installation
```sh
go get github.com/Mirzazhar/rsa
```
## Warning
This package is intendedly designed for education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
## Usage & Examples
## LICENSE
MIT License
## References
1. https://en.wikipedia.org/wiki/RSA_(cryptosystem)
2. https://dl.acm.org/doi/10.5555/1721909
3. https://dl.acm.org/doi/pdf/10.1145/3214303
4. https://pkg.go.dev/crypto/rsa
