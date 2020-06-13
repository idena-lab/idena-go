package relay

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/core/state"
	"github.com/stretchr/testify/require"
	db "github.com/tendermint/tm-db"
	rand2 "math/rand"
	"testing"
)

type mockId struct {
	addr common.Address
	pk1  []byte
	pk2  []byte
}

func randId() *mockId {
	rid := &mockId{
		addr: common.Address{},
		pk1:  make([]byte, 32*2),
		pk2:  make([]byte, 32*4),
	}
	_, _ = rand.Read(rid.addr[:])
	_, _ = rand.Read(rid.pk1)
	_, _ = rand.Read(rid.pk2)
	return rid
}

func rmAndAdd(isDb *state.IdentityStateDB, allIds []*mockId, rmCount, addCount int) (remainIds, rmIds, addIds []*mockId) {
	rmIds = make([]*mockId, rmCount)
	for i := 0; i < rmCount; i++ {
		pos := rand2.Intn(len(allIds))
		isDb.Remove(allIds[pos].addr)
		rmIds[i] = allIds[pos]
		allIds[pos] = allIds[len(allIds)-1]
		allIds = allIds[:len(allIds)-1]
	}
	addIds = make([]*mockId, addCount)
	for i := 0; i < addCount; i++ {
		rid := randId()
		addIds[i] = rid
		allIds = append(allIds, rid)
		isDb.Add(rid.addr)
		isDb.SetBlsKeys(rid.addr, rid.pk1, rid.pk2)
	}
	remainIds = allIds
	return
}

func checkId(t *testing.T, isDb *state.IdentityStateDB, ids []*mockId, approved, hasIndex bool) {
	for _, rid := range ids {
		require.Equal(t, isDb.IsApproved(rid.addr), approved)
		if hasIndex {
			require.True(t, isDb.GetIndex(rid.addr) > 0)
		} else {
			require.True(t, isDb.GetIndex(rid.addr) == 0)
		}
	}
}

func TestUpdateRelayState(t *testing.T) {
	isDb := state.NewLazyIdentityState(db.NewMemDB())
	allIds := make([]*mockId, 0, 10000)

	height := uint64(ActiveHeight) - 1
	remainCount := 4444
	allIds, rmIds, addIds := rmAndAdd(isDb, allIds, 0, remainCount)
	rs := UpdateRelayState(height, isDb, new(state.RelayState))
	isDb.Commit(true)
	require.True(t, rs.Empty())
	require.Len(t, allIds, remainCount)
	require.Len(t, rmIds, 0)
	require.Len(t, addIds, remainCount)

	height++
	prev := rs
	rmCount, addCount := 333, 1111
	allIds, rmIds, addIds = rmAndAdd(isDb, allIds, rmCount, addCount)
	rs = UpdateRelayState(height, isDb, prev)
	isDb.Commit(true)
	remainCount = remainCount + addCount - rmCount
	require.Len(t, allIds, remainCount)
	require.Len(t, rmIds, rmCount)
	require.Len(t, addIds, addCount)
	require.True(t, rs.Population == uint32(remainCount))
	require.True(t, rs.NeedSign())
	require.Len(t, rs.Signature, 0)
	t.Log(hex.EncodeToString(rs.Root))

	height++
	prev = rs
	rmCount, addCount = 555, 333
	allIds, rmIds, addIds = rmAndAdd(isDb, allIds, rmCount, addCount)
	rs = UpdateRelayState(height, isDb, prev)
	remainCount = remainCount + addCount - rmCount
	require.Len(t, allIds, remainCount)
	require.Len(t, rmIds, rmCount)
	require.Len(t, addIds, addCount)
	require.True(t, rs.Population == uint32(remainCount))
	require.True(t, rs.NeedSign())
	require.Len(t, rs.Signature, 0)
	t.Log(hex.EncodeToString(rs.Root))
}

