package relay

import (
	"bytes"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/core/state"
	"github.com/idena-network/idena-go/crypto"
	"math/big"
	"sort"
)

const (
	// todo: to be confirmed
	ActiveHeight = 4444444
)

// update identity indexes for relay
func UpdateRelayState(height uint64, s *state.IdentityStateDB, prev *state.RelayState) *state.RelayState {
	if height < ActiveHeight {
		return prev
	}
	oldPop, oldIds, addIds, rmIds := s.GetUpdatesForRelay()
	addSorted := getOrderedObjectsKeys(addIds)
	sort.Slice(rmIds, func(i, j int) bool {
		return rmIds[i] < rmIds[j]
	})
	hasFill := 0
	// fill rm slots with new ids
	for ; hasFill < len(rmIds) && hasFill < len(addSorted); hasFill++ {
		s.SetIndex(addSorted[hasFill], rmIds[hasFill])
	}
	// append remain new ids
	for i := uint32(oldPop); hasFill < len(addSorted); hasFill++ {
		// i should add first because the Index starts from 1
		i++
		s.SetIndex(addSorted[hasFill], i)
	}
	// rollback tail ids to fill rm slots
	for tailIndex, rmLast := uint32(oldPop), len(rmIds)-1; hasFill < rmLast; hasFill++ {
		for ; tailIndex == rmIds[rmLast] && hasFill < rmLast; tailIndex-- {
			rmLast--
		}
		if tailIndex > rmIds[hasFill] {
			s.SetIndex(oldIds[tailIndex], rmIds[hasFill])
			tailIndex--
		} else {
			break
		}
	}
	// set rm flags
	rmFlags := state.NewBitArray(oldPop)
	for _, idx := range rmIds {
		rmFlags.SetIndex(int(idx-1), true)
	}
	rs := new(state.RelayState)
	rs.Root = calcRoot(height, prev.Root, rmFlags, addSorted, addIds)
	return rs
}

func calcRoot(height uint64, prev []byte, rmFlags *state.BitArray, addSorted []common.Address, addIds map[common.Address]state.ApprovedIdentity) []byte {
	if len(prev) == 0 {
		prev = make([]byte, common.HashLength)
	}
	hIds := common.Hash{}
	for _, addr := range addSorted {
		h := append(hIds[:], addr[:]...)
		h = append(h, addIds[addr].Pk1...)
		hIds = crypto.Keccak256Hash(h)
	}
	h := append(prev, BigToBytes(big.NewInt(int64(height)), 32)...)
	h = append(h, hIds[:]...)
	h = append(h, crypto.Keccak256(rmFlags.Bytes())...)
	return crypto.Keccak256(h)
}

func getOrderedObjectsKeys(objects map[common.Address]state.ApprovedIdentity) []common.Address {
	keys := make([]common.Address, 0, len(objects))
	for k := range objects {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].Bytes(), keys[j].Bytes()) == 1
	})

	return keys
}

// convert big int to byte array (big endian)
// `minLen` is the minimum length of the array
func BigToBytes(bi *big.Int, minLen int) []byte {
	b := bi.Bytes()
	if minLen <= len(b) {
		return b
	}
	m := make([]byte, minLen)
	copy(m[minLen-len(b):], b)
	return m
}
