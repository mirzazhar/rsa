package rsa

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrMessageTooLong = errors.New("rsa: message too long for RSA public key size")
var ErrCipherTooLong = errors.New("rsa: cipher too long for RSA public key size")
var ErrSigTooLong = errors.New("rsa: signature too long for RSA public key size")

// PrivateKey represents RSA private key.
type PrivateKey struct {
	PublicKey
	Phi *big.Int // phi(n), (p-1)*(q-1)
	D   *big.Int // d = e^(-1) mod phi(n)
}

// PublicKey represents RSA public key.
type PublicKey struct {
	N *big.Int // modulus n
	E *big.Int // e
}

// GenerateKey generates RSA private key.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// prime number p
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// prime number q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)

	// l = phi(n) = (p-1) * (q-1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

	// randomly choosing e from phi(n), such that
	// gcd(e,phi(n)) = 1
	e := new(big.Int)
	gcd := new(big.Int)

	for {
		e, err = rand.Prime(rand.Reader, phi.BitLen()-8)
		if err != nil {
			return nil, err
		}
		if e.Cmp(one) == 0 {
			continue
		} else {
			gcd = gcd.GCD(nil, nil, e, phi)
			if gcd.Cmp(one) == 0 {
				break
			}
		}
	}

	// d = e^(-1) mod phi(n)
	d := new(big.Int).ModInverse(e, phi)

	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: e,
		},
		Phi: phi,
		D:   d,
	}, nil
}

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if plain text value is larger than modulus N of Public key.
func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.N) == 1 { //  m < N
		return nil, ErrMessageTooLong
	}

	// c = m^e mod N
	c := new(big.Int).Mod(
		new(big.Int).Exp(m, pub.E, pub.N),
		pub.N,
	)
	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns
// an error if cipher text value is larger than modulus N of Public key.
func (priv *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(priv.N) == 1 { //  c < N
		return nil, ErrCipherTooLong
	}

	// m = c^d  mod N
	m := new(big.Int).Mod(
		new(big.Int).Exp(c, priv.D, priv.N),
		priv.N,
	)
	return m.Bytes(), nil
}

// HomomorphicEncTwo performs homomorphic operation over two chiphers.
// RSA has multiplicative homomorphic property, so resultant cipher
// contains the product of two numbers.
func (pub *PublicKey) HomomorphicEncTwo(ciphertext1, ciphertext2 []byte) ([]byte, error) {
	c1 := new(big.Int).SetBytes(ciphertext1)
	c2 := new(big.Int).SetBytes(ciphertext2)
	if c1.Cmp(pub.N) == 1 && c2.Cmp(pub.N) == 1 { //  c < N
		return nil, ErrCipherTooLong
	}

	// C = c1*c2 mod N
	C := new(big.Int).Mod(
		new(big.Int).Mul(c1, c2),
		pub.N)
	return C.Bytes(), nil
}

// HommorphicEncMultiple performs homomorphic operation over multiple chiphers.
// RSA has multiplicative homomorphic property, so resultant cipher
// contains the product of multiple numbers.
func (pub *PublicKey) HommorphicEncMultiple(ciphertexts ...[]byte) ([]byte, error) {
	C := one // since, c = 1^e mod n is equal to 1

	for i := 0; i < len(ciphertexts); i++ {
		c := new(big.Int).SetBytes(ciphertexts[i])
		if c.Cmp(pub.N) == 1 { //  c < N
			return nil, ErrCipherTooLong
		}

		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, c),
			pub.N)
	}
	return C.Bytes(), nil
}

// Signature generates signature over the given message. It returns signature
// value as a byte array.
func (priv *PrivateKey) Signature(message []byte) []byte {
	hashofm := sha256.Sum256(message)
	m := new(big.Int).SetBytes(hashofm[:])

	// s = m^d mod n
	s := new(big.Int).Mod(
		new(big.Int).Exp(m, priv.D, priv.N),
		priv.N,
	)
	return s.Bytes()
}

// SigVerify verifies signature over the given message and signature value.
// It returns true as a boolean value if signature is verify correctly. Otherwise
// it returns false along with an error message.
func (pub *PublicKey) SigVerify(sig, message []byte) (bool, error) {
	hashofm := sha256.Sum256(message)
	m := new(big.Int).SetBytes(hashofm[:])

	s := new(big.Int).SetBytes(sig)
	if s.Cmp(pub.N) == 1 { //  s < N
		return false, ErrSigTooLong
	}

	// v = s^e mod n
	v := new(big.Int).Mod(
		new(big.Int).Exp(s, pub.E, pub.N),
		pub.N,
	)

	if m.Cmp(v) == 0 {
		return true, nil
	}
	return false, errors.New("signature is not verified")
}
