package rsa

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrMessageTooLong = errors.New("rsa: message too long for RSA public key size")
var ErrCipherTooLong = errors.New("rsa: cipher too long for RSA public key size")
var ErrSigTooLong = errors.New("rsa: signature too long for RSA public key size")

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
