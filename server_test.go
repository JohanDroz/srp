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

func TestNewServer(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s, err = NewServer(mockBackend)
	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestServerSetHash(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	var err error

	// Test with nil hash function (should return an error).
	s, err = NewServer(mockBackend, ServerHash(nil))
	assert.NotNil(t, err)
	assert.Nil(t, s)

	// Test with valid hash function.
	s, err = NewServer(mockBackend, ServerHash(sha1.New))
	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestServerSetTimeout(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	var err error

	// Test with invalid timeout.
	var invalidTimeouts = []time.Duration{-10 * time.Second, -1 * time.Second}

	for _, invalidTimeout := range invalidTimeouts {
		s, err = NewServer(mockBackend, ServerTimeout(invalidTimeout))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid timeout.
	var validTimeouts = []time.Duration{0, 1 * time.Millisecond, 1 * time.Second}

	for _, validTimeout := range validTimeouts {
		s, err = NewServer(mockBackend, ServerTimeout(validTimeout))
		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}

func TestServerSetGroup(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	var err error

	// Test with invalid group.
	var invalidGrps = []*Group{
		&Group{Prime: nil, Generator: nil},
		&Group{Prime: nil, Generator: big.NewInt(0)},
		&Group{Prime: big.NewInt(0), Generator: nil},
	}

	for _, invalidGrp := range invalidGrps {
		s, err = NewServer(mockBackend, ServerGroup(invalidGrp))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid groups.
	for _, validGrp := range srpGroups {
		s, err = NewServer(mockBackend, ServerGroup(validGrp))

		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}

func TestServerSetFuncX(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	var err error

	// Test with invalid function.
	var invalidComputeXs = []funcX{nil}

	for _, invalidComputeX := range invalidComputeXs {
		s, err = NewServer(mockBackend, ServerFuncX(invalidComputeX))
		assert.NotNil(t, err)
		assert.Nil(t, s)
	}

	// Test with valid function.
	var validComputeXs = []funcX{computeXWithoutUsername, computeXWithUsername}

	for _, validComputeX := range validComputeXs {
		s, err = NewServer(mockBackend, ServerFuncX(validComputeX))
		assert.Nil(t, err)
		assert.NotNil(t, s)
	}
}

func TestServerUpdateTimeout(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	var err error

	var timeouts = []time.Duration{1 * time.Second, 2 * time.Second, 10 * time.Second}

	for _, timeout := range timeouts {
		s, err = NewServer(mockBackend, ServerTimeout(timeout))
		assert.Nil(t, err)

		// Get current timeout
		assert.Equal(t, timeout, s.timeout)
	}
}

func TestServerHasTimedOut(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s, err = NewServer(mockBackend)
	assert.Nil(t, err)

	// Test with no timeout.
	assert.False(t, s.hasTimedOut(time.Now()))

	// Test with timeout.
	var timeout = 1 * time.Millisecond
	s, err = NewServer(mockBackend, ServerHash(sha1.New), ServerTimeout(timeout))
	assert.Nil(t, err)

	// Sleep to ensure we have a timeout.
	var now = time.Now()
	time.Sleep(2 * timeout)
	assert.True(t, s.hasTimedOut(now))
}

func TestServerStep1(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	{
		var err error
		s, err = NewServer(mockBackend, ServerHash(sha1.New), ServerTimeout(0), ServerFuncX(computeXWithUsername), ServerGroup(srpGroups["rfc-1024"]))
		assert.Nil(t, err)
	}

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"
	var salt = getBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var verifier = getBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	var expectedPublicServerValue = getBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")

	// Set the private server value. Here we match the one in the test vector.
	s.setGeneratePrivateValue(func(n *big.Int) (*big.Int, error) {
		return getBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20"), nil
	})

	// Failure
	{
		var tcase = []struct {
			userID   string
			salt     []byte
			verifier *big.Int
		}{
			{"", salt, verifier},
			{userID, nil, verifier},
			{userID, salt, nil},
		}

		for _, tc := range tcase {
			var publicServerValue, err = s.Step1(tc.userID, tc.salt, tc.verifier)
			assert.NotNil(t, err, "bad: case %#v", tc)
			assert.Nil(t, publicServerValue, "bad: case %#v", tc)
		}
	}

	// Success
	mockBackend.EXPECT().Put(context.TODO(), userID, gomock.Any()).Return(nil).Times(1)
	var publicServerValue, err = s.Step1(userID, salt, verifier)
	assert.Nil(t, err)
	assert.Equal(t, expectedPublicServerValue, publicServerValue)
}

func TestServerStep2(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockBackend = mock.NewBackend(mockCtrl)

	var s *Server
	{
		var err error
		s, err = NewServer(mockBackend, ServerHash(sha1.New), ServerTimeout(0), ServerFuncX(computeXWithUsername), ServerGroup(srpGroups["rfc-1024"]))
		assert.Nil(t, err)
	}

	// The test vector come from the RFC 5054 (https://www.ietf.org/rfc/rfc5054.txt)
	var userID = "alice"
	var salt = getBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
	var verifier = getBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	var publicClientValue = getBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")
	var clientEvidence = getBigIntFromHex("B46A7838 46B7E569 FF8F9B44 AB8D88ED EB085A65")
	var expectedServerEvidence = getBigIntFromHex("B0A6AD30 24E79b5C AD04042A BB3A3F59 2D20C17")

	// Set the private server value. Here we match the one in the test vector.
	s.setGeneratePrivateValue(func(n *big.Int) (*big.Int, error) {
		return getBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20"), nil
	})

	// Failure
	{
		var tcase = []struct {
			userID            string
			salt              []byte
			verifier          *big.Int
			publicClientValue *big.Int
			clientEvidence    *big.Int

			// If storageCall is true, there is a call to the storage backend that returns
			// storageRep,storageErr
			storageCall bool
			storageRep  map[string]interface{}
			storageErr  error
		}{
			// Invalid state.
			{userID, salt, verifier, publicClientValue, clientEvidence, true, map[string]interface{}{
				"state":              initial,
				"lastActivity":       time.Now(),
				"publicServerValue":  publicServerValue,
				"privateServerValue": privateServerValue,
			}, nil},

			// Invalid inputs.
			{"", salt, verifier, publicClientValue, clientEvidence, false, nil, nil},
			{userID, nil, verifier, publicClientValue, clientEvidence, false, nil, nil},
			{userID, salt, nil, publicClientValue, clientEvidence, false, nil, nil},
			{userID, salt, verifier, nil, clientEvidence, false, nil, nil},
			{userID, salt, verifier, big.NewInt(0), clientEvidence, false, nil, nil},
			{userID, salt, verifier, publicClientValue, nil, false, nil, nil},
		}

		for _, tc := range tcase {
			if tc.storageCall {
				mockBackend.EXPECT().Get(context.TODO(), tc.userID).Return(tc.storageRep, tc.storageErr).Times(1)
			}
			var serverEvidence, err = s.Step2(tc.userID, tc.salt, tc.verifier, tc.publicClientValue, tc.clientEvidence)
			assert.NotNil(t, err, "bad: case %#v", tc)
			assert.Nil(t, serverEvidence, "bad: case %#v", tc)
		}
	}

	// Success
	var (
		storageRep = map[string]interface{}{
			"state":              step1,
			"lastActivity":       time.Now(),
			"publicServerValue":  publicServerValue,
			"privateServerValue": privateServerValue,
		}
		storageErr error = nil
	)

	mockBackend.EXPECT().Get(context.TODO(), userID).Return(storageRep, storageErr).Times(1)
	mockBackend.EXPECT().Delete(context.TODO(), userID).Return(nil).Times(1)

	var serverEvidence, err = s.Step2(userID, salt, verifier, publicClientValue, clientEvidence)
	assert.Nil(t, err)
	assert.Equal(t, expectedServerEvidence, serverEvidence)
}
