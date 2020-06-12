package relay

import (
	"bytes"
	"github.com/idena-network/idena-go/blockchain/types"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/eventbus"
	"github.com/idena-network/idena-go/core/appstate"
	"github.com/idena-network/idena-go/core/state"
	"github.com/idena-network/idena-go/crypto"
	"github.com/idena-network/idena-go/crypto/bls"
	"github.com/idena-network/idena-go/database"
	"github.com/idena-network/idena-go/events"
	"github.com/idena-network/idena-go/secstore"
	dbm "github.com/tendermint/tm-db"
	"math/big"
	"sort"
	"sync"
	"time"
)

const (
	// todo: to be confirmed
	ActiveHeight      = 4444444
	MultiSigThreshold = 2 / 3
)

type StateManager struct {
	repo     *database.Repo
	secStore *secstore.SecStore
	appState *appstate.AppState
	bus      eventbus.Bus
	pending  []uint64
	cache    *collectingCache
	mu       sync.Mutex
}

type collectingCache struct {
	height uint64
	state  *state.RelayState
	keys   []*bls.PubKey2
	sigs   [][]byte
}

func NewStateManager(db dbm.DB, secStore *secstore.SecStore, appState *appstate.AppState, bus eventbus.Bus) *StateManager {
	sm := &StateManager{
		repo:     database.NewRepo(db),
		secStore: secStore,
		appState: appState,
		pending:  make([]uint64, 0),
	}
	go sm.loop()
	return sm
}

func (sm *StateManager) addPending(height uint64, rs *state.RelayState) {
	if !rs.NeedSign() || rs.SignRate() > MultiSigThreshold {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.cache != nil && sm.cache.height == height {
		// state changed, recollect
		if bytes.Equal(sm.cache.state.Root, rs.Root) {
			return
		} else {
			sm.cache = nil
		}
	}
	i := sort.Search(len(sm.pending), func(i int) bool {
		return sm.pending[i] >= height
	})
	if i < len(sm.pending) && sm.pending[i] == height {
		return
	}
	sm.pending = append(sm.pending, 0)
	copy(sm.pending[i+1:], sm.pending[i:])
	sm.pending[i] = height
}

// save relay state and try to collect signatures
func (sm *StateManager) WriteRelayState(height uint64, rs *state.RelayState) {
	if rs.Empty() {
		return
	}
	if rs.NeedSign() {
		if prevState, err := sm.appState.IdentityState.Readonly(height - 1); err == nil {
			myIndex := prevState.GetIndex(sm.secStore.GetAddress())
			if myIndex > 0 && !rs.SignFlags.Contains(myIndex-1) {
				if len(rs.Signature) == 0 {
					rs.Signature = sm.secStore.GetBlsPriKey().Sign(rs.Root).Marshal()
				} else {
					as, _ := bls.NewSignature(rs.Signature)
					as = bls.AggregateSignatures(as, sm.secStore.GetBlsPriKey().Sign(rs.Root))
					rs.Signature = as.Marshal()
				}
				rs.SignFlags.Add(myIndex - 1)
			}
		} else {
			// todo: add logs
		}
	}
	b, _ := rs.ToBytes()
	sm.repo.WriteRelayState(height, b)
	go sm.addPending(height, rs)
}

func (sm *StateManager) GetRelayState(height uint64) *state.RelayState {
	data := sm.repo.ReadRelayState(height)
	if data == nil {
		return nil
	}
	rs := new(state.RelayState)
	rs.FromBytes(data)
	return rs
}

// collect signatures
func (sm *StateManager) loop() {
	collectTimer := time.NewTimer(time.Second * 3)

	for {
		select {
		case <-collectTimer.C:
		}
		c := sm.prepareCollect()
		if c != nil {
			req := &types.CollectSigReq{
				Height:    c.height,
				Root:      c.state.Root,
				Collected: c.state.SignFlags.Bytes(),
			}
			sm.bus.Publish(&events.RelayCollectEvent{Req: req})
		}
	}
}

func (sm *StateManager) prepareCollect() *collectingCache {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.cache != nil && sm.cache.state.SignRate() <= MultiSigThreshold {
		return sm.cache
	}
	sm.cache = nil
	next := 0
	for ; next < len(sm.pending); next++ {
		height := sm.pending[next]
		rs := sm.GetRelayState(height)
		if rs.NeedSign() && rs.SignRate() <= MultiSigThreshold {
			// reset cache
			prevState, err := sm.appState.IdentityState.Readonly(height)
			if err != nil {
				// todo: add logs
				continue
			}
			sm.cache = &collectingCache{
				height: height,
				state:  rs,
				keys:   sm.loadKeys(prevState),
				sigs:   make([][]byte, rs.Population),
			}
			// cache my signature
			myIndex := prevState.GetIndex(sm.secStore.GetAddress())
			if myIndex > 0 && !rs.SignFlags.Contains(myIndex-1) {
				sm.cache.sigs[myIndex] = sm.secStore.GetBlsPriKey().Sign(rs.Root).Marshal()
			}
			break
		}
	}
	sm.pending = sm.pending[next:]
	return sm.cache
}

func (sm *StateManager) loadKeys(prevState *state.IdentityStateDB) []*bls.PubKey2 {
	indexes := make([]uint32, 0)
	pubkeys := make([]*bls.PubKey2, 0)
	prevState.IterateIdentities(func(key []byte, value []byte) bool {
		if key == nil {
			return true
		}
		var data state.ApprovedIdentity
		if err := data.FromBytes(value); err != nil {
			return false
		}
		if data.Index > 0 {
			indexes = append(indexes, data.Index)
			pk2, _ := bls.NewPubKey2(data.Pk2)
			pubkeys = append(pubkeys, pk2)
		}
		return false
	})
	sort.Slice(pubkeys, func(i, j int) bool {
		return indexes[i] < indexes[j]
	})
	return pubkeys
}

func (sm *StateManager) OnRequest(req *types.CollectSigReq) (*types.RelaySigBatch, *types.RelaySigAgg, error) {
	// todo:
	return nil, nil, nil
}

func (sm *StateManager) MergeSigBatch(batch *types.RelaySigBatch) error {
	// todo:
	return nil
}

func (sm *StateManager) AddySigAgg(agg *types.RelaySigAgg) error {
	// todo:
	return nil
}

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
	// build rs
	rs := new(state.RelayState)
	rs.Root = calcRoot(height, prev.Root, rmFlags, addSorted, addIds)
	rs.Signature = nil
	rs.Population = uint32(oldPop + len(addIds) - len(rmIds))
	rs.SignFlags = common.NewBitmap(rs.Population)
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
