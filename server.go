package srp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/johandroz/srp/storage"
	"github.com/pkg/errors"
)

// // Server is the srp server interface.
// type Server interface {
// 	Step1(userID string, salt []byte, verifier *big.Int) (publicServerValue *big.Int, err error)
// 	Step2(publicClientValue, clientEvidence *big.Int) (serverEvidence *big.Int, err error)
// }

// NewServer constructs a usable SRP client.
func NewServer(backend storage.Backend, options ...ServerOption) (*Server, error) {
	var server = &Server{
		backend:              backend,
		fHash:                sha256.New,
		computeX:             computeXWithoutUsername,
		timeout:              0,
		generatePrivateValue: generatePrivateValue,
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
	}

	// Apply options to the Server.
	for _, opt := range options {
		var err = opt(server)
		if err != nil {
			return nil, err
		}
	}

	return server, nil
}

type Server struct {
	// backend stores the srp data in between round trips
	backend storage.Backend

	grp                  *Group
	computeX             funcX
	fHash                func() hash.Hash
	generatePrivateValue funcPrivateValue
	timeout              time.Duration
	// userID               string   // I
	// salt                 []byte   // s
	// publicClientValue    *big.Int // A
	// publicServerValue    *big.Int // B
	// privateServerValue   *big.Int // b
	// scramblingParam      *big.Int // u
	// multiplier           *big.Int // k
	// sessionKey           *big.Int // S
	// clientEvidence       *big.Int // M1
	// serverEvidence       *big.Int // M2
	// verifier             *big.Int // v
	// noSuchUserIdentity   bool
	//	lastActivity time.Time
	//	state                state
}

// ServerOption sets an optional parameter for Server.
type ServerOption func(*Server) error

// hasTimedOut returns true if the session has timed out, based on the
// timeout configuration and the last activity timestamp.
func (s *Server) hasTimedOut(lastActivity time.Time) bool {
	if s.timeout == 0 {
		return false
	}
	var now = time.Now()

	return now.After(lastActivity.Add(s.timeout))
}

func (s *Server) Step1(userID string, salt []byte, verifier *big.Int) (*big.Int, error) {
	// Validate inputs
	if userID == "" {
		return nil, fmt.Errorf("the user identity must not be empty")
	}

	if salt == nil {
		return nil, fmt.Errorf("the salt must not be nil")
	}

	if verifier == nil {
		return nil, fmt.Errorf("the verifier must not be nil")
	}

	var multiplier = computeMultiplier(s.fHash, s.grp.Prime, s.grp.Generator)
	var privateServerValue *big.Int
	{
		var err error
		privateServerValue, err = s.generatePrivateValue(s.grp.Prime)
		if err != nil {
			return nil, err
		}
	}
	var publicServerValue = computePublicServerValue(s.grp.Prime, s.grp.Generator, multiplier, verifier, privateServerValue)
	var state = step1
	var lastActivity = time.Now()

	// Store data for second SRP round trip.
	var m = map[string]interface{}{
		"state":              state,
		"lastActivity":       lastActivity,
		"publicServerValue":  publicServerValue,
		"privateServerValue": privateServerValue,
	}
	s.backend.Put(context.TODO(), userID, m)

	return publicServerValue, nil
}

func (s *Server) Step2(userID string, salt []byte, verifier, publicClientValue, clientEvidence *big.Int) (*big.Int, error) {
	// Validate inputs
	if userID == "" {
		return nil, fmt.Errorf("the user identity must not be empty")
	}
	if salt == nil {
		return nil, fmt.Errorf("the salt must not be nil")
	}
	if verifier == nil {
		return nil, fmt.Errorf("the verifier must not be nil")
	}
	if clientEvidence == nil {
		return nil, fmt.Errorf("the client evidence message must not be nil")
	}
	if !isValidPublicValue(s.grp.Prime, publicClientValue) {
		return nil, fmt.Errorf("bad client public value")
	}

	// Get data from first step
	var step state
	var lastActivity time.Time
	var publicServerValue *big.Int
	var privateServerValue *big.Int
	{
		var m, err = s.backend.Get(context.TODO(), userID)
		if err != nil {
			return nil, errors.Wrapf(err, "could not get SRP data from backend during step2")
		}

		// state
		{
			var x, ok = m["state"]
			if !ok {
				return nil, fmt.Errorf("could not read 'state' from backend")
			}

			step, ok = x.(state)
			if !ok {
				return nil, fmt.Errorf("type assertion error for 'state'")
			}
		}
		// lastActivity
		{
			var x, ok = m["lastActivity"]
			if !ok {
				return nil, fmt.Errorf("could not read 'lastActivity' from backend")
			}

			lastActivity, ok = x.(time.Time)
			if !ok {
				return nil, fmt.Errorf("type assertion error for 'lastActivity'")
			}
		}
		// publicServerValue
		{
			var x, ok = m["publicServerValue"]
			if !ok {
				return nil, fmt.Errorf("could not read 'publicServerValue' from backend")
			}

			publicServerValue, ok = x.(*big.Int)
			if !ok {
				return nil, fmt.Errorf("type assertion error for 'publicServerValue'")
			}
		}
		// privateServerValue
		{
			var x, ok = m["privateServerValue"]
			if !ok {
				return nil, fmt.Errorf("could not read 'privateServerValue' from backend")
			}

			privateServerValue, ok = x.(*big.Int)
			if !ok {
				return nil, fmt.Errorf("type assertion error for 'privateServerValue'")
			}
		}
	}

	// Check current state
	if step != step1 {
		return nil, fmt.Errorf("state violation: must be in 'step1' state")
	}

	// Check timeout
	if s.hasTimedOut(lastActivity) {
		return nil, fmt.Errorf("srp timeout")
	}

	var scramblingParam = computeScramblingParameter(s.fHash, s.grp.Prime, publicClientValue, publicServerValue)
	var sessionKey = computeServerSessionKey(s.grp.Prime, verifier, scramblingParam, publicClientValue, privateServerValue)

	// Compute the own client evidence message
	var computedM1 = computeClientEvidence(s.fHash, publicClientValue, publicServerValue, sessionKey)

	if computedM1.Cmp(clientEvidence) != 0 {
		return nil, fmt.Errorf("bad client credentials")
	}

	var serverEvidence = computeServerEvidence(s.fHash, publicClientValue, clientEvidence, sessionKey)

	// Delete srp session info
	s.backend.Delete(context.TODO(), userID)

	return serverEvidence, nil
}

// ServerHash is the option used to set the hash function.
func ServerHash(fHash func() hash.Hash) ServerOption {
	return func(s *Server) error {
		if fHash == nil {
			return fmt.Errorf("the hash function must not be nil")
		}

		s.fHash = fHash
		return nil
	}
}

// ServerGroup is the option used to set the SRP group.
func ServerGroup(grp *Group) ServerOption {
	return func(s *Server) error {
		if grp.Prime == nil || grp.Generator == nil {
			return fmt.Errorf("the prime and generator must not be nil")
		}

		s.grp = grp
		return nil
	}
}

// ServerFuncX is the option used to set which function is used to compute
// the SRP X parameter.
func ServerFuncX(computeX funcX) ServerOption {
	return func(s *Server) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}

		s.computeX = computeX
		return nil
	}
}

// ServerTimeout is the option used to set the SRP timeout.
func ServerTimeout(t time.Duration) ServerOption {
	return func(s *Server) error {
		if t < 0 {
			return fmt.Errorf("the timeout must be zero (no timeout) or greater")
		}

		s.timeout = t
		return nil
	}
}

// SetGeneratePrivateValue set the function that generate the private values. It is used in the tests
// to control the values returned (while it is usually random).
func (s *Server) setGeneratePrivateValue(f funcPrivateValue) {
	s.generatePrivateValue = f
}
