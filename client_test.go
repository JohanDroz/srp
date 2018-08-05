package srp

import (
	"context"
	"crypto/sha1"
	"math/big"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/johandroz/srp/storage/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c, err = NewClient(mockBackend)
	assert.Nil(t, err)
	assert.NotNil(t, c)
}

func TestClientSetHash(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	var err error

	// Test with nil hash function (should return an error).
	c, err = NewClient(mockBackend, ClientHash(nil))
	assert.NotNil(t, err)
	assert.Nil(t, c)

	// Test with valid hash function.
	c, err = NewClient(mockBackend, ClientHash(sha1.New))
	assert.Nil(t, err)
	assert.NotNil(t, c)
}

func TestClientSetTimeout(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	var err error

	// Test with invalid timeout.
	var invalidTimeouts = []time.Duration{-10 * time.Second, -1 * time.Second}

	for _, invalidTimeout := range invalidTimeouts {
		c, err = NewClient(mockBackend, ClientTimeout(invalidTimeout))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid timeout.
	var validTimeouts = []time.Duration{0, 1 * time.Millisecond, 1 * time.Second}

	for _, validTimeout := range validTimeouts {
		c, err = NewClient(mockBackend, ClientTimeout(validTimeout))
		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestClientSetGroup(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	var err error

	// Test with invalid group.
	var invalidGrps = []*Group{
		&Group{Prime: nil, Generator: nil},
		&Group{Prime: nil, Generator: big.NewInt(0)},
		&Group{Prime: big.NewInt(0), Generator: nil},
	}

	for _, invalidGrp := range invalidGrps {
		c, err = NewClient(mockBackend, ClientGroup(invalidGrp))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid groups.
	for _, validGrp := range srpGroups {
		c, err = NewClient(mockBackend, ClientGroup(validGrp))

		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestClientSetFuncX(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	var err error

	// Test with invalid function.
	var invalidComputeXs = []funcX{nil}

	for _, invalidComputeX := range invalidComputeXs {
		c, err = NewClient(mockBackend, ClientFuncX(invalidComputeX))
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}

	// Test with valid function.
	var validComputeXs = []funcX{computeXWithoutUsername, computeXWithUsername}

	for _, validComputeX := range validComputeXs {
		c, err = NewClient(mockBackend, ClientFuncX(validComputeX))
		assert.Nil(t, err)
		assert.NotNil(t, c)
	}
}

func TestClientUpdateTimeout(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	var err error

	var timeouts = []time.Duration{1 * time.Second, 2 * time.Second, 10 * time.Second}

	for _, timeout := range timeouts {
		c, err = NewClient(mockBackend, ClientTimeout(timeout))
		assert.Nil(t, err)

		// Get current timeout
		assert.Equal(t, timeout, c.timeout)
	}
}

func TestClientHasTimedOut(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c, err = NewClient(mockBackend)
	assert.Nil(t, err)

	// Test with no timeout.
	assert.False(t, c.hasTimedOut(time.Now()))

	// Test with timeout.
	var timeout = 1 * time.Millisecond
	c, err = NewClient(mockBackend, ClientHash(sha1.New), ClientTimeout(timeout))
	assert.Nil(t, err)

	// Sleep to ensure we have a timeout.
	var now = time.Now()
	time.Sleep(2 * timeout)
	assert.True(t, c.hasTimedOut(now))
}

func TestClientStep1(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c, err = NewClient(mockBackend, ClientHash(sha1.New), ClientTimeout(0), ClientFuncX(computeXWithUsername), ClientGroup(srpGroups["rfc-1024"]))
	assert.Nil(t, err)

	// Failure
	{
		var tcase = []struct {
			userID   string
			password string
		}{
			{"", "password123"},
			{"alice", ""},
		}

		for _, tc := range tcase {
			var err = c.Step1(tc.userID, tc.password)
			assert.NotNil(t, err, "bad: case %#v", tc)
		}
	}

	// Success
	{
		var tcase = []struct {
			userID   string
			password string
		}{
			{"alice", "password123"},
		}

		for _, tc := range tcase {
			mockBackend.EXPECT().Put(context.Background(), tc.userID, gomock.Any())
			var err = c.Step1(tc.userID, tc.password)
			assert.Nil(t, err, "bad: case %#v", tc)
		}
	}
}

func TestClientStep2(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c, err = NewClient(mockBackend, ClientHash(sha1.New), ClientTimeout(0), ClientFuncX(computeXWithUsername), ClientGroup(srpGroups["rfc-1024"]))
	assert.Nil(t, err)

	// Set the private client value. Here we match the one in the test vector.
	c.setGeneratePrivateValue(func(n *big.Int) (*big.Int, error) {
		return getBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393"), nil
	})

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"
	var salt = getBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var publicServerValue = getBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")
	var expectedPublicClientValue = getBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")

	// Failure
	{
		var tcase = []struct {
			userID            string
			salt              []byte
			publicServerValue *big.Int

			// If storageCall is true, there is a call to the storage backend that returns
			// storageRep,storageErr
			storageCall bool
			storageRep  map[string]interface{}
			storageErr  error
		}{
			// Invalid state.
			{userID, salt, publicServerValue, true, map[string]interface{}{
				"state":        initial,
				"lastActivity": time.Now(),
				"password":     password,
			}, nil},

			// Invalid salt.
			{userID, nil, publicServerValue, false, nil, nil},

			// Invalid publicServerValue.
			{userID, salt, nil, false, nil, nil},
			{userID, salt, big.NewInt(0), false, nil, nil},
		}

		for _, tc := range tcase {
			if tc.storageCall {
				mockBackend.EXPECT().Get(context.TODO(), tc.userID).Return(tc.storageRep, tc.storageErr).Times(1)
			}
			var publicClientValue, clientEvidence, err = c.Step2(tc.userID, tc.salt, tc.publicServerValue)
			assert.NotNil(t, err, "bad: case %#v", tc)
			assert.Nil(t, publicClientValue, "bad: case %#v", tc)
			assert.Nil(t, clientEvidence, "bad: case %#v", tc)
		}
	}

	// Success
	{
		var tcase = []struct {
			userID                    string
			salt                      []byte
			publicServerValue         *big.Int
			storageRep                map[string]interface{}
			storageErr                error
			expectedPublicClientValue *big.Int
		}{
			{userID, salt, publicServerValue, map[string]interface{}{
				"state":        step1,
				"lastActivity": time.Now(),
				"password":     password,
			}, nil, expectedPublicClientValue},
		}

		for _, tc := range tcase {
			mockBackend.EXPECT().Get(context.TODO(), tc.userID).Return(tc.storageRep, tc.storageErr).Times(1)
			mockBackend.EXPECT().Put(context.TODO(), tc.userID, gomock.Any())

			var publicClientValue, clientEvidence, err = c.Step2(tc.userID, tc.salt, tc.publicServerValue)
			assert.Nil(t, err, "bad: case %#v", tc)
			assert.Equal(t, expectedPublicClientValue, publicClientValue, "bad: case %#v", tc)
			assert.NotNil(t, clientEvidence, "bad: case %#v", tc)
		}
	}
}

func TestClientStep3(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var c *Client
	{
		var err error
		c, err = NewClient(mockBackend, ClientHash(sha1.New), ClientTimeout(0), ClientFuncX(computeXWithUsername), ClientGroup(srpGroups["rfc-1024"]))
		assert.Nil(t, err)
	}

	// Set the private client value. Here we match the one in the test vector.
	c.setGeneratePrivateValue(func(n *big.Int) (*big.Int, error) {
		return getBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393"), nil
	})

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"

	// Failure
	{
		var tcase = []struct {
			userID            string
			publicServerValue *big.Int

			// If storageCall is true, there is a call to the storage backend that returns
			// storageRep,storageErr
			storageCall bool
			storageRep  map[string]interface{}
			storageErr  error
		}{
			// Invalid state.
			{userID, publicServerValue, true, map[string]interface{}{
				"state":             initial,
				"lastActivity":      time.Now(),
				"publicClientValue": publicClientValue,
				"clientEvidence":    clientEvidence,
				"sessionKey":        premasterSecret,
			}, nil},
			{userID, publicServerValue, true, map[string]interface{}{
				"state":             step1,
				"lastActivity":      time.Now(),
				"publicClientValue": publicClientValue,
				"clientEvidence":    clientEvidence,
				"sessionKey":        premasterSecret,
			}, nil},

			// Invalid publicServerValue.
			{userID, nil, false, nil, nil},
		}

		for _, tc := range tcase {
			if tc.storageCall {
				mockBackend.EXPECT().Get(context.TODO(), tc.userID).Return(tc.storageRep, tc.storageErr).Times(1)
			}
			var err = c.Step3(tc.userID, tc.publicServerValue)
			assert.NotNil(t, err, "bad: case %#v", tc)
		}
	}

	// Success
	var (
		storageRep = map[string]interface{}{
			"state":             step2,
			"lastActivity":      time.Now(),
			"publicClientValue": publicClientValue,
			"clientEvidence":    clientEvidence,
			"sessionKey":        premasterSecret,
		}
		storageErr error = nil
	)

	mockBackend.EXPECT().Get(context.TODO(), userID).Return(storageRep, storageErr).Times(1)
	mockBackend.EXPECT().Delete(context.TODO(), userID).Return(nil).Times(1)
	var err = c.Step3(userID, serverEvidence)
	assert.Nil(t, err)
}

/*
func TestSrpAuth(t *testing.T) {
	var logger = log.NewLogfmtLogger(ioutil.Discard)

	var err error

	var verifierGen VerifierGenerator
	{
		var err error
		verifierGen, err = verifierNewVerifierGenerator(logger)
		assert.Nil(t, err)
	}
	var client SRPClient
	{
		var err error
		client = newSrpClient(config, 0, logger)
		assert.Nil(t, err)
	}
	var server ServerSrp
	{
		var err error
		server = newSrpServer(config, 0, logger)
		assert.Nil(t, err)
	}

	// Srp authentication
	var username = "Alice"
	var password = "P@ssw0rd"
	var salt = make([]byte, 10)
	r.Read(salt)
	var s = big.NewInt(0).SetBytes(salt)

	// Generate verifier
	var verifierAlice *big.Int = verifierGen.GenerateVerifier(salt, username, password)

	// Client, step 1
	err = client.Step1(username, password)
	assert.Nil(t, err)

	// Server, step 1
	var B *big.Int
	B, err = server.Step1(username, s, verifierAlice)
	assert.Nil(t, err)

	// Client, step2
	var cc ClientCredentials
	cc, err = client.Step2(s, B)
	assert.Nil(t, err)

	// Server, step2
	var M2 *big.Int
	M2, err = server.Step2(cc.PublicClientValue, cc.ClientEvidence)
	assert.Nil(t, err)

	// Client, step2
	err = client.Step3(M2)
	assert.Nil(t, err)

}
*/
