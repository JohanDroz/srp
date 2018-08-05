package srp

import (
	"crypto/sha1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVerifier(t *testing.T) {
	var v, err = NewVerifier()
	assert.Nil(t, err)
	assert.NotNil(t, v)
}

func TestVerifierSetHash(t *testing.T) {
	var v *Verifier
	var err error

	// Test with nil hash function (should return an error).
	v, err = NewVerifier(VerifierHash(nil))
	assert.NotNil(t, err)
	assert.Nil(t, v)

	// Test with valid hash function.
	v, err = NewVerifier(VerifierHash(sha1.New))
	assert.Nil(t, err)
	assert.NotNil(t, v)
}

func TestVerifierSetGroup(t *testing.T) {
	var v *Verifier
	var err error

	// Test with invalid group.
	var invalidGrps = []*Group{
		&Group{Prime: nil, Generator: nil},
		&Group{Prime: nil, Generator: big.NewInt(0)},
		&Group{Prime: big.NewInt(0), Generator: nil},
	}

	for _, invalidGrp := range invalidGrps {
		v, err = NewVerifier(VerifierGroup(invalidGrp))
		assert.NotNil(t, err)
		assert.Nil(t, v)
	}

	// Test with valid groups.
	for _, validGrp := range srpGroups {
		v, err = NewVerifier(VerifierGroup(validGrp))

		assert.Nil(t, err)
		assert.NotNil(t, v)
	}
}

func TestVerifierSetFuncX(t *testing.T) {
	var v *Verifier
	var err error

	// Test with invalid function.
	var invalidComputeXs = []funcX{nil}

	for _, invalidComputeX := range invalidComputeXs {
		v, err = NewVerifier(VerifierHash(sha1.New), VerifierFuncX(invalidComputeX))
		assert.NotNil(t, err)
		assert.Nil(t, v)
	}

	// Test with valid function.
	var validComputeXs = []funcX{computeXWithoutUsername, computeXWithUsername}

	for _, validComputeX := range validComputeXs {
		v, err = NewVerifier(VerifierHash(sha1.New), VerifierFuncX(validComputeX))

		assert.Nil(t, err)
		assert.NotNil(t, v)
	}
}

func TestVerifier(t *testing.T) {
	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var salt []byte
	{
		var s *big.Int
		s = getBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE")
		salt = s.Bytes()
	}

	var grp = &Group{
		Prime:     getBigIntFromHex("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3"),
		Generator: getBigIntFromHex("2"),
	}

	var expectedVerifier = getBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")

	// Generate verifier: the test vector from RFC 5054 uses
	// sha1 and compute x with username (x = H(s|H(I|:|P)))
	var v *Verifier
	{
		var err error
		v, err = NewVerifier(VerifierHash(sha1.New), VerifierGroup(grp), VerifierFuncX(computeXWithUsername))
		assert.Nil(t, err)
	}

	var verifier = v.GenerateVerifier(salt, "alice", "password123")
	assert.Equal(t, expectedVerifier, verifier)
}
