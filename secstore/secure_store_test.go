package secstore

import (
	"github.com/idena-network/idena-go/common"
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

	for i := 0; i < 100; i++ {
		ss := NewSecStore()
		key, _ := crypto.GenerateKey()
		ss.AddKey(crypto.FromECDSA(key))

		k1 := ss.GetBlsPriKey()
		k2 := ss.GetBlsPriKey()
		require.Equal(t, k1.ToHex(), k2.ToHex())
	}
}

func TestSecStore_GetBlsPriKey1(t *testing.T) {
	secStore := NewSecStore()
	key, _ := crypto.HexToECDSA("2dedd85746f99b685cffe420b7d96c5062ae80ff25d48731d03ee8fc4ed1fae0")
	secStore.AddKey(crypto.FromECDSA(key))
	require.Equal(t, secStore.GetAddress(), common.HexToAddress("0xd611254eE6b8b225bd685cFb8933882CCd447675"))
	require.Equal(t, secStore.GetBlsPriKey().ToHex(), "0x1ae6558a584ecf9b566b263222d44e6c485ba0bc0e68798e331d68518c222bcc")
}