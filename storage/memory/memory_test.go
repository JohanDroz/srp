package memory

import (
	"context"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestNewMemoryBackend(t *testing.T) {
	var b, err = NewMemoryBackend()
	assert.Nil(t, err)
	assert.NotNil(t, b)
}

func TestMemoryBackendPut(t *testing.T) {
	var b *MemoryBackend
	{
		var err error
		b, err = NewMemoryBackend()
		assert.Nil(t, err)
	}

	var (
		key      = "key"
		salt     = make([]byte, 8)
		verifier = big.NewInt(0)
	)
	rand.Read(salt)
	verifier.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(2<<32))

	var val = map[string]interface{}{
		"userID": "alice",
		"salt":   salt,
	}

	var err = b.Put(context.Background(), key, val)
	assert.Nil(t, err)
}

func TestMemoryBackendGet(t *testing.T) {
	var b *MemoryBackend
	{
		var err error
		b, err = NewMemoryBackend()
		assert.Nil(t, err)
	}

	var (
		key      = "key"
		salt     = make([]byte, 8)
		verifier = big.NewInt(0)
	)
	rand.Read(salt)
	verifier.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(2<<32))

	var val = map[string]interface{}{
		"userID": "alice",
		"salt":   salt,
	}

	// Unknown key
	{
		var val, err = b.Get(context.Background(), key)
		assert.NotNil(t, err)
		assert.Nil(t, val)
	}

	// Success
	var err = b.Put(context.Background(), key, val)
	assert.Nil(t, err)
	{
		var v, err = b.Get(context.Background(), key)
		assert.Nil(t, err)
		assert.Equal(t, val, v)
	}
}

func TestMemoryBackendDelete(t *testing.T) {
	var b *MemoryBackend
	{
		var err error
		b, err = NewMemoryBackend()
		assert.Nil(t, err)
	}

	var (
		key      = "key"
		salt     = make([]byte, 8)
		verifier = big.NewInt(0)
	)
	rand.Read(salt)
	verifier.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(2<<32))

	var val = map[string]interface{}{
		"userID": "alice",
		"salt":   salt,
	}

	// Put value
	var err = b.Put(context.Background(), key, val)
	assert.Nil(t, err)
	{
		var v, err = b.Get(context.Background(), key)
		assert.Nil(t, err)
		assert.Equal(t, val, v)
	}

	// Delete value
	{
		var err = b.Delete(context.Background(), key)
		assert.Nil(t, err)
	}

	// Get value, the key should not exist anymore
	{
		var v, err = b.Get(context.Background(), key)
		assert.NotNil(t, err)
		assert.Nil(t, v)
	}
}
