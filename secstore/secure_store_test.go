package secstore

import (
	"github.com/idena-network/idena-go/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecStore_VrfEvaluate(t *testing.T) {
	secStore := NewSecStore()
	key, _ := crypto.GenerateKey()
	secStore.AddKey(crypto.FromECDSA(key))

	index, proof := secStore.VrfEvaluate([]byte{0x1, 0x2})
	index2, proof2 := secStore.VrfEvaluate([]byte{0x1, 0x2})
	require.Equal(t, index, index2)
	require.NotEqual(t, proof, proof2)
}

func TestSecStore_GetBlsPriKey(t *testing.T) {
	seed := []byte("bls-256-for-eth-relay")
	sh := crypto.Hash(seed)
	require.Equal(t, sh[:], blsSeedHash)

	ss := NewSecStore()
	key, _ := crypto.GenerateKey()
	ss.AddKey(crypto.FromECDSA(key))

	k1 := ss.GetBlsPriKey()
	k2 := ss.GetBlsPriKey()
	require.Equal(t, k1.ToHex(), k2.ToHex())
}