package srp

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

// type Verifier interface {
// 	Verifier(salt []byte, username, password string) *big.Int
// }

// NewVerifier constructs a usable SRP verifier generator.
func NewVerifier(options ...VerifierOption) (*Verifier, error) {
	var verifier = &Verifier{
		grp: &Group{
			// The default group is the 2048-bit group from the rfc.
			Prime: getBigIntFromHex(`
			AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050
			A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 
			E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 
			55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B 
			CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 
			544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6
			AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6 
			94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73`),
			Generator: getBigIntFromHex("2"),
		},
		fHash:    sha256.New,
		computeX: computeXWithoutUsername,
	}

	// Apply options to the Verifier.
	for _, opt := range options {
		var err = opt(verifier)
		if err != nil {
			return nil, err
		}
	}

	return verifier, nil
}

// Verifier generates the SRP verifier.
type Verifier struct {
	grp      *Group
	fHash    func() hash.Hash
	computeX funcX
}

// GenerateVerifier generate the verifier given the salt username, and password.
func (v *Verifier) GenerateVerifier(salt []byte, username, password string) *big.Int {
	var x = v.computeX(v.fHash, salt, username, password)
	return computeVerifier(v.grp.Prime, v.grp.Generator, x)
}

// VerifierOption sets an optional parameter for Verifier.
type VerifierOption func(*Verifier) error

// VerifierHash is the option used to set the hash function.
func VerifierHash(fHash func() hash.Hash) VerifierOption {
	return func(v *Verifier) error {
		if fHash == nil {
			return fmt.Errorf("the hash function must not be nil")
		}

		v.fHash = fHash
		return nil
	}
}

// VerifierGroup is the option used to set the SRP group.
func VerifierGroup(grp *Group) VerifierOption {
	return func(v *Verifier) error {
		if grp.Prime == nil || grp.Generator == nil {
			return fmt.Errorf("the prime and generator must not be nil")
		}

		v.grp = grp
		return nil
	}
}

// VerifierFuncX is the option used to set which function is used to compute
// the SRP X parameter.
func VerifierFuncX(computeX funcX) VerifierOption {
	return func(v *Verifier) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}

		v.computeX = computeX
		return nil
	}
}
