package state

import (
	"crypto/rand"
	"github.com/idena-network/idena-go/common"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tm-db"
	rand2 "math/rand"
	"testing"
)

func getRandAddr() common.Address {
	bytes := make([]byte, 20)
	rand.Read(bytes)
	return common.BytesToAddress(bytes)
}

func TestIdentityStateDB_AddDiff(t *testing.T) {

	database := db.NewMemDB()
	database2 := db.NewMemDB()

	stateDb := NewLazyIdentityState(database)
	stateDb2 := NewLazyIdentityState(database2)

	diffs := make([]*IdentityStateDiff, 0)

	forDeleteAddrs := make([]common.Address, 0, 10)

	for i := 0; i < 100; i++ {

		for _, delAddr := range forDeleteAddrs {
			stateDb.Remove(delAddr)
		}

		forDeleteAddrs = make([]common.Address, 0, 10)

		for j := 0; j < 50; j++ {
			addr := getRandAddr()
			if j < 10 {
				forDeleteAddrs = append(forDeleteAddrs, addr)
			}
			stateDb.Add(addr)
		}

		diffs = append(diffs, stateDb.Precommit(true))
		stateDb.Commit(true)
	}

	i := int64(1)
	for _, d := range diffs {
		stateDb2.AddDiff(uint64(i), d)
		stateDb2.CommitTree(i)
		i++
	}

	require.Equal(t, stateDb.Root(), stateDb2.Root())
}

func TestIdentityStateDB_CreatePreliminaryCopy(t *testing.T) {
	stateDb := createStateDb()

	preliminary, err := stateDb.CreatePreliminaryCopy(100)
	require.NoError(t, err)
	require.Equal(t, preliminary.original, stateDb.original)

	require.Equal(t, stateDb.Root(), preliminary.Root())

	preliminary.Add(getRandAddr())
	_, _, _, err = preliminary.Commit(true)
	require.NoError(t, err)

	require.Error(t, stateDb.Load(101))

	preliminaryPrefix := loadIdentityPrefix(preliminary.original, true)
	prefix := loadIdentityPrefix(stateDb.original, false)

	require.NotNil(t, preliminaryPrefix)
	require.NotNil(t, prefix)

	require.NotEqual(t, preliminaryPrefix, prefix)

	preliminary.DropPreliminary()

	it, _ := preliminary.db.Iterator(nil, nil)
	defer it.Close()
	require.False(t, it.Valid())

	require.True(t, stateDb.HasVersion(100))

	preliminaryPrefix = loadIdentityPrefix(preliminary.original, true)
	prefix = loadIdentityPrefix(stateDb.original, false)

	require.Len(t, preliminaryPrefix, 0)
	require.NotNil(t, prefix)
}

func createStateDb() *IdentityStateDB {

	database := db.NewMemDB()
	stateDb := NewLazyIdentityState(database)

	for i := 0; i < 100; i++ {
		for j := 0; j < 50; j++ {
			addr := getRandAddr()
			stateDb.Add(addr)
		}
		stateDb.Commit(true)
	}
	return stateDb
}

func TestIdentityStateDB_SwitchToPreliminary(t *testing.T) {
	stateDb := createStateDb()
	database := stateDb.db
	preliminary, _ := stateDb.CreatePreliminaryCopy(100)
	for i := 0; i < 50; i++ {
		preliminary.Add(getRandAddr())
		preliminary.Commit(true)
	}

	root := preliminary.Root()

	prevVreliminaryPrefix := loadIdentityPrefix(preliminary.original, true)

	batch, dropDb, err := stateDb.SwitchToPreliminary(150)
	require.NoError(t, err)
	batch.WriteSync()
	common.ClearDb(dropDb)
	preliminaryPrefix := loadIdentityPrefix(preliminary.original, true)
	prefix := loadIdentityPrefix(stateDb.original, false)

	require.Len(t, preliminaryPrefix, 0)
	require.NotNil(t, prefix)
	require.Equal(t, prevVreliminaryPrefix, prefix)

	it, _ := database.Iterator(nil, nil)
	defer it.Close()
	require.False(t, it.Valid())

	require.Equal(t, root, stateDb.Root())
}

func TestStateDB_Precommit(t *testing.T) {
	stateDb := createStateDb()
	addr := common.Address{0x1}
	addr2 := common.Address{0x2}
	stateDb.Add(addr)
	stateDb.Add(addr2)
	diff := stateDb.Precommit(true)
	require.Len(t, diff.Values, 2)
	require.Equal(t, addr, diff.Values[1].Address)
	require.Equal(t, addr2, diff.Values[0].Address)
	require.False(t, diff.Values[1].Deleted)
	require.False(t, diff.Values[0].Deleted)

	stateDb.Commit(true)

	addr3 := common.Address{0x3}
	stateDb.Add(addr3)
	stateDb.Remove(addr2)

	diff = stateDb.Precommit(true)
	require.Len(t, diff.Values, 2)
	require.Equal(t, addr2, diff.Values[1].Address)
	require.Equal(t, addr3, diff.Values[0].Address)
	require.True(t, diff.Values[1].Deleted)
	require.False(t, diff.Values[0].Deleted)
}

type relayId struct {
	addr common.Address
	pk1  []byte
	pk2  []byte
}

func randRelayId() *relayId {
	rid := &relayId{
		addr: common.Address{},
		pk1:  make([]byte, 32*2),
		pk2:  make([]byte, 32*4),
	}
	_, _ = rand.Read(rid.addr[:])
	_, _ = rand.Read(rid.pk1)
	_, _ = rand.Read(rid.pk2)
	return rid
}

func TestIdentityStateDB_GetUpdatesForRelay(t *testing.T) {
	isDb := NewLazyIdentityState(db.NewMemDB())
	allIds := make([]*relayId, 0, 10000)
	rmAndAdd := func(rmCount, addCount int) (rmIds, addIds []*relayId) {
		rmIds = make([]*relayId, rmCount)
		for i := 0; i < rmCount; i++ {
			pos := rand2.Intn(len(allIds))
			isDb.Remove(allIds[pos].addr)
			rmIds[i] = allIds[pos]
			allIds[pos] = allIds[len(allIds)-1]
			allIds = allIds[:len(allIds)-1]
		}
		addIds = make([]*relayId, addCount)
		for i := 0; i < addCount; i++ {
			rid := randRelayId()
			addIds[i] = rid
			allIds = append(allIds, rid)
			isDb.Add(rid.addr)
			isDb.SetBlsKeys(rid.addr, rid.pk1, rid.pk2)
		}
		return
	}
	checkIds := func(ids []*relayId, approved bool) {
		for _, rid := range ids {
			require.Equal(t, isDb.IsApproved(rid.addr), approved)
		}
	}
	initCount := 2000
	// init
	rmIds, addIds := rmAndAdd(0, initCount)
	isDb.Commit(true)
	require.Len(t, rmIds, 0)
	require.Len(t, addIds, initCount)
	require.Len(t, allIds, initCount)
	// checkIds(addIds, true)

	// add and remove
	rmCount, addCount := 222, 444
	remain := initCount + addCount - rmCount
	rmIds, addIds = rmAndAdd(rmCount, addCount)
	oldIds, addRelay, rmRelay := isDb.GetUpdatesForRelay()
	isDb.Commit(true)
	require.Len(t, rmIds, rmCount)
	require.Len(t, addIds, addCount)
	require.Len(t, allIds, remain)
	require.Len(t, oldIds, 0)
	require.Len(t, addRelay, remain)
	require.Len(t, rmRelay, 0)
	checkIds(rmIds, false)
	checkIds(addIds, true)
}
