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

// // Client is the srp client interface.
// type Client interface {
// 	Step1(userID, password string) error
// 	Step2(salt []byte, publicServerValue *big.Int) (publicClientValue *big.Int, clientEvidence *big.Int, err error)
// 	Step3(serverEvidence *big.Int) error
// }

// NewClient constructs a usable SRP client.
func NewClient(backend storage.Backend, options ...ClientOption) (*Client, error) {
	var client = &Client{
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

	// Apply options to the Client.
	for _, opt := range options {
		var err = opt(client)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// Client is the SRP client.
type Client struct {
	// backend stores the srp data in between round trips
	backend storage.Backend

	grp                  *Group
	computeX             funcX
	fHash                func() hash.Hash
	generatePrivateValue funcPrivateValue
	timeout              time.Duration

	// userID               string
	// password             string
	// salt                 []byte
	// publicClientValue    *big.Int
	// privateClientValue   *big.Int
	// publicServerValue    *big.Int
	// scramblingParam      *big.Int
	// x                    *big.Int
	// multiplier           *big.Int
	// sessionKey           *big.Int
	// clientEvidence       *big.Int
	// serverEvidence       *big.Int
	// lastActivity         time.Time
	// state                state
}

// ClientOption sets an optional parameter for Client.
type ClientOption func(*Client) error

// hasTimedOut returns true if the session has timed out, based on the
// timeout configuration and the last activity timestamp.
func (c *Client) hasTimedOut(lastActivity time.Time) bool {
	if c.timeout == 0 {
		return false
	}
	var now = time.Now()

	return now.After(lastActivity.Add(c.timeout))
}

// Generate random salt s of length numBytes
func (c *Client) generateRandomSalt(numBytes int) ([]byte, error) {
	return generateRandomSalt(numBytes)
}

func (c *Client) Step1(userID, password string) error {
	if userID == "" {
		return fmt.Errorf("the user identity must not be empty")
	}

	if password == "" {
		return fmt.Errorf("the user password must not be empty")
	}

	// Store data for second SRP round trip.
	var m = map[string]interface{}{
		"state":        step1,
		"lastActivity": time.Now(),
		"password":     password,
	}
	c.backend.Put(context.TODO(), userID, m)

	return nil
}

func (c *Client) Step2(userID string, salt []byte, publicServerValue *big.Int) (*big.Int, *big.Int, error) {
	if userID == "" {
		return nil, nil, fmt.Errorf("the user identity must not be empty")
	}

	if salt == nil {
		return nil, nil, fmt.Errorf("the salt must not be nil")
	}

	if !isValidPublicValue(c.grp.Prime, publicServerValue) {
		return nil, nil, fmt.Errorf("bad server public value")
	}

	// Get data from first step
	var step state
	var lastActivity time.Time
	var password string
	{
		var m, err = c.backend.Get(context.TODO(), userID)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "could not get SRP data from backend during step2")
		}

		// state
		{
			var x, ok = m["state"]
			if !ok {
				return nil, nil, fmt.Errorf("could not read 'state' from backend")
			}

			step, ok = x.(state)
			if !ok {
				return nil, nil, fmt.Errorf("type assertion error for 'state'")
			}
		}
		// lastActivity
		{
			var x, ok = m["lastActivity"]
			if !ok {
				return nil, nil, fmt.Errorf("could not read 'lastActivity' from backend")
			}

			lastActivity, ok = x.(time.Time)
			if !ok {
				return nil, nil, fmt.Errorf("type assertion error for 'lastActivity'")
			}
		}
		// password
		{
			var x, ok = m["password"]
			if !ok {
				return nil, nil, fmt.Errorf("could not read 'password' from backend")
			}

			password, ok = x.(string)
			if !ok {
				return nil, nil, fmt.Errorf("type assertion error for 'password'")
			}
		}
	}

	// Check current state
	if step != step1 {
		return nil, nil, fmt.Errorf("state violation: must be in 'step1' state")
	}

	// Check timeout
	if c.hasTimedOut(lastActivity) {
		return nil, nil, fmt.Errorf("session timeout")
	}

	var x = c.computeX(c.fHash, salt, userID, password)
	var privateClientValue *big.Int
	{
		var err error
		privateClientValue, err = c.generatePrivateValue(c.grp.Prime)
		if err != nil {
			return nil, nil, err
		}
	}

	var publicClientValue = computePublicClientValue(c.grp.Prime, c.grp.Generator, privateClientValue)
	var multiplier = computeMultiplier(c.fHash, c.grp.Prime, c.grp.Generator)
	var scramblingParam = computeScramblingParameter(c.fHash, c.grp.Prime, publicClientValue, publicServerValue)
	var sessionKey = computeClientSessionKey(c.grp.Prime, c.grp.Generator, multiplier, x, scramblingParam, privateClientValue, publicServerValue)
	var clientEvidence = computeClientEvidence(c.fHash, publicClientValue, publicServerValue, sessionKey)

	// Store data for second SRP round trip.
	var m = map[string]interface{}{
		"state":             step2,
		"lastActivity":      time.Now(),
		"publicClientValue": publicClientValue,
		"clientEvidence":    clientEvidence,
		"sessionKey":        sessionKey,
	}
	c.backend.Put(context.TODO(), userID, m)

	return publicClientValue, clientEvidence, nil
}

func (c *Client) Step3(userID string, serverEvidence *big.Int) error {
	if userID == "" {
		return fmt.Errorf("the user identity must not be empty")
	}

	// Validate input
	if serverEvidence == nil {
		return fmt.Errorf("the server evidence message must not be nil")
	}

	// Get data from second step
	var step state
	var lastActivity time.Time
	var publicClientValue *big.Int
	var clientEvidence *big.Int
	var sessionKey *big.Int
	{
		var m, err = c.backend.Get(context.TODO(), userID)
		if err != nil {
			return errors.Wrapf(err, "could not get SRP data from backend during step3")
		}

		// state
		{
			var x, ok = m["state"]
			if !ok {
				return fmt.Errorf("could not read 'state' from backend")
			}

			step, ok = x.(state)
			if !ok {
				return fmt.Errorf("type assertion error for 'state'")
			}
		}
		// lastActivity
		{
			var x, ok = m["lastActivity"]
			if !ok {
				return fmt.Errorf("could not read 'lastActivity' from backend")
			}

			lastActivity, ok = x.(time.Time)
			if !ok {
				return fmt.Errorf("type assertion error for 'lastActivity'")
			}
		}
		// publicClientValue
		{
			var x, ok = m["publicClientValue"]
			if !ok {
				return fmt.Errorf("could not read 'publicClientValue' from backend")
			}

			publicClientValue, ok = x.(*big.Int)
			if !ok {
				return fmt.Errorf("type assertion error for 'publicClientValue'")
			}
		}
		// clientEvidence
		{
			var x, ok = m["clientEvidence"]
			if !ok {
				return fmt.Errorf("could not read 'clientEvidence' from backend")
			}

			clientEvidence, ok = x.(*big.Int)
			if !ok {
				return fmt.Errorf("type assertion error for 'clientEvidence'")
			}
		}
		// sessionKey
		{
			var x, ok = m["sessionKey"]
			if !ok {
				return fmt.Errorf("could not read 'sessionKey' from backend")
			}

			sessionKey, ok = x.(*big.Int)
			if !ok {
				return fmt.Errorf("type assertion error for 'sessionKey'")
			}
		}
	}

	// Check current state
	if step != step2 {
		return fmt.Errorf("state violation: must be in 'step2' state")
	}

	// Check timeout
	if c.hasTimedOut(lastActivity) {
		return fmt.Errorf("session timeout")
	}

	// Compute the own server evidence message
	var computedM2 = computeServerEvidence(c.fHash, publicClientValue, clientEvidence, sessionKey)

	if computedM2.Cmp(serverEvidence) != 0 {
		return fmt.Errorf("bad server credentials")
	}

	// Delete srp session info
	c.backend.Delete(context.TODO(), userID)

	return nil
}

// ClientHash is the option used to set the hash function.
func ClientHash(fHash func() hash.Hash) ClientOption {
	return func(c *Client) error {
		if fHash == nil {
			return fmt.Errorf("the hash function must not be nil")
		}

		c.fHash = fHash
		return nil
	}
}

// ClientGroup is the option used to set the SRP group.
func ClientGroup(grp *Group) ClientOption {
	return func(c *Client) error {
		if grp.Prime == nil || grp.Generator == nil {
			return fmt.Errorf("the prime and generator must not be nil")
		}

		c.grp = grp
		return nil
	}
}

// ClientFuncX is the option used to set which function is used to compute
// the SRP X parameter.
func ClientFuncX(computeX funcX) ClientOption {
	return func(c *Client) error {
		if computeX == nil {
			return fmt.Errorf("the compute x function should not be nil")
		}

		c.computeX = computeX
		return nil
	}
}

// ClientTimeout is the option used to set the SRP timeout.
func ClientTimeout(t time.Duration) ClientOption {
	return func(c *Client) error {
		if t < 0 {
			return fmt.Errorf("the timeout must be zero (no timeout) or greater")
		}

		c.timeout = t
		return nil
	}
}

// SetGeneratePrivateValue set the function that generete the private valuec. It is used in the tests
// to control the value returned (while it is usually random).
func (c *Client) setGeneratePrivateValue(f funcPrivateValue) {
	c.generatePrivateValue = f
}
