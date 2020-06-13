package relay

import (
	"bytes"
	"errors"
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
	MathBatchSize     = 300
)

type StateManager struct {
	repo     *database.Repo
	secStore *secstore.SecStore
	appState *appstate.AppState
	bus      eventbus.Bus
	pending  []uint64
	cache    *collectingCache
	mu       sync.RWMutex
}

type collectingCache struct {
	height uint64
	state  *state.RelayState
	keys   []*bls.PubKey2
	sigs   map[uint32][]byte // map real index (from 0) to signature
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
		if bytes.Equal(sm.cache.state.Root, rs.Root) {
			return
		} else {
			// state changed, recollect
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
			prevState, err := sm.appState.IdentityState.Readonly(height - 1)
			if err != nil {
				// todo: add logs
				continue
			}
			sm.cache = &collectingCache{
				height: height,
				state:  rs,
				keys:   sm.loadKeys(prevState),
				sigs:   make(map[uint32][]byte, 0),
			}
			// cache my signature
			myIndex := prevState.GetIndex(sm.secStore.GetAddress())
			if myIndex > 0 && !rs.SignFlags.Contains(myIndex-1) {
				sm.cache.sigs[myIndex-1] = sm.secStore.GetBlsPriKey().Sign(rs.Root).Marshal()
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

func (sm *StateManager) ProvideState(req *types.CollectSigReq) (*types.RelaySigBatch, *types.RelaySigAgg) {
	c := sm.cache
	if c == nil || c.height != req.Height {
		// send aggregated signatures
		rs := sm.GetRelayState(req.Height)
		if !rs.NeedSign() || !bytes.Equal(rs.Root, req.Root) {
			return nil, nil
		}
		return nil, &types.RelaySigAgg{
			Height:    req.Height,
			Root:      rs.Root,
			Signature: rs.Signature,
			Flags:     rs.SignFlags.Bytes(),
		}
	}
	// todo: send aggregated sig if request sigs is subset of local sigs
	// send batch signatures
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	c = sm.cache
	if c == nil || c.height != req.Height {
		return nil, nil
	}
	batch := &types.RelaySigBatch{
		Height:     req.Height,
		Signatures: make([][]byte, 0),
		Indexes:    make([]uint32, 0),
	}
	exFlags := common.NewBitmap(c.state.Population)
	exFlags.Read(req.Collected)
	count := 0
	for id, sig := range c.sigs {
		if !exFlags.Contains(id) {
			batch.Signatures = append(batch.Signatures, sig)
			batch.Indexes = append(batch.Indexes, id)
			count++
			if count >= MathBatchSize {
				break
			}
		}
	}
	if count > 0 {
		return batch, nil
	} else {
		return nil, nil
	}
}

func (sm *StateManager) MergeSigBatch(batch *types.RelaySigBatch) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	c := sm.cache
	merged, err := doMergeSigBatch(c, batch)
	if err != nil {
		return err
	}
	if merged {
		// save to repo
		b, _ := c.state.ToBytes()
		sm.repo.WriteRelayState(c.height, b)
	}
	return nil
}

// merge batch to cache
func doMergeSigBatch(c *collectingCache, batch *types.RelaySigBatch) (bool, error) {
	count := len(batch.Indexes)
	if count == 0 {
		return false, nil
	}
	if c == nil || c.height != batch.Height {
		// todo: consider merging to aggregated signatures in repo
		return false, nil
	}
	if !bytes.Equal(batch.Root, c.state.Root) {
		return false, nil
	}
	// collect new signatures
	inPub := make([]*bls.PubKey2, 0, count)
	inSig := make([]*bls.Signature, 0, count)
	inIdx := make([]uint32, 0, count)
	for i, idx := range batch.Indexes {
		if idx >= c.state.Population {
			// same root should have same state
			return false, errors.New("invalid index")
		}
		if c.state.SignFlags.Contains(idx) {
			continue
		}
		sig, _ := bls.NewSignature(batch.Signatures[i])
		if sig == nil {
			return false, errors.New("invalid signature")
		}
		inPub = append(inPub, c.keys[idx])
		inSig = append(inSig, sig)
		inIdx = append(inIdx, idx)
	}
	if len(inPub) == 0 {
		return false, nil
	}
	// verify signatures
	aggPub := bls.AggregatePubKeys2(inPub)
	aggSig := bls.AggregateSignatures(inSig...)
	if !bls.Verify(c.state.Root, aggSig, aggPub) {
		return false, errors.New("verify bls signature failed")
	}
	// merge it
	for i, idx := range inIdx {
		c.state.SignFlags.Add(idx)
		c.sigs[idx] = inSig[i].Marshal()
	}
	if len(c.state.Signature) == 0 {
		c.state.Signature = aggSig.Marshal()
	} else {
		sig, _ := bls.NewSignature(c.state.Signature)
		c.state.Signature = bls.AggregateSignatures(sig, aggSig).Marshal()
	}
	return true, nil
}

func (sm *StateManager) AddSigAgg(agg *types.RelaySigAgg) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	c := sm.cache
	added, err := doAddSig(c, agg)
	if err != nil {
		return err
	}
	if added {
		// save to repo
		b, _ := c.state.ToBytes()
		sm.repo.WriteRelayState(c.height, b)
	}
	return nil
}

func doAddSig(c *collectingCache, agg *types.RelaySigAgg) (bool, error) {
	aggSig, err := bls.NewSignature(agg.Signature)
	if err != nil {
		return false, errors.New("invalid signature")
	}
	if aggSig == nil {
		return false, nil
	}
	if c == nil || c.height != agg.Height {
		// todo: consider merging to aggregated signatures in repo
		return false, nil
	}
	if !bytes.Equal(agg.Root, c.state.Root) {
		return false, nil
	}
	// count sigs
	aggFlags := common.NewBitmap(c.state.Population)
	aggFlags.Read(agg.Flags)
	aggIdx := aggFlags.ToArray()
	localIdx := c.state.SignFlags.ToArray()
	toMergeIdx := make([]uint32, 0)
	for _, idx := range localIdx {
		if len(c.sigs[idx]) > 0 && !aggFlags.Contains(idx) {
			toMergeIdx = append(toMergeIdx, idx)
		}
	}
	mergedCount := len(aggIdx) + len(toMergeIdx)
	if (float64(mergedCount) / float64(c.state.Population)) <= MultiSigThreshold {
		// skip adding if local sigs is not subset of incoming + cached sigs
		for _, idx := range localIdx {
			if len(c.sigs[idx]) == 0 && !aggFlags.Contains(idx) {
				return false, nil
			}
		}
	} else if len(localIdx) >= mergedCount {
		return false, nil
	}
	// verify agg sigs
	pubs := make([]*bls.PubKey2, len(aggIdx))
	for i, idx := range aggIdx {
		if idx >= c.state.Population {
			// same root should have same state
			return false, errors.New("invalid index")
		}
		pubs[i] = c.keys[idx]
	}
	aggPub := bls.AggregatePubKeys2(pubs)
	if !bls.Verify(c.state.Root, aggSig, aggPub) {
		return false, errors.New("verify bls signature failed")
	}
	// merge cache to agg and replace state
	if len(toMergeIdx) > 0 {
		mergeSigs := make([]*bls.Signature, len(toMergeIdx)+1)
		for i, idx := range toMergeIdx {
			mergeSigs[i], _ = bls.NewSignature(c.sigs[idx])
			aggFlags.Add(idx)
		}
		mergeSigs[len(toMergeIdx)] = aggSig
		aggSig = bls.AggregateSignatures(mergeSigs...)
	}
	c.state.Signature = aggSig.Marshal()
	c.state.SignFlags = aggFlags
	return true, nil
}

func (sm *StateManager) GenerateInitData(height uint64) (root []byte, ids []common.Address, pk1s []*bls.PubKey1) {
	rs := sm.GetRelayState(height)
	if rs.Empty() {
		return
	}
	root = rs.Root
	ids = make([]common.Address, rs.Population)
	pk1s = make([]*bls.PubKey1, rs.Population)
	newState, _ := sm.appState.IdentityState.Readonly(height)
	newState.IterateIdentities(func(key []byte, value []byte) bool {
		if key == nil {
			return true
		}
		var data state.ApprovedIdentity
		if err := data.FromBytes(value); err != nil {
			return false
		}
		if data.Approved && data.Index > 0 {
			idx := data.Index - 1
			addr := common.Address{}
			addr.SetBytes(key[1:])
			ids[idx] = addr
			pk1s[idx], _ = bls.NewPubKey1(data.Pk1)
		}
		return false
	})
	return
}

func (sm *StateManager) GenerateUpdateData(height uint64, rs *state.RelayState) (addIds []common.Address, addPk1s []*bls.PubKey1, rmFlags *state.BitArray, rmCount uint32, apk2 *bls.PubKey2) {
	if !rs.NeedSign() {
		return
	}
	oldState, _ := sm.appState.IdentityState.Readonly(height - 1)
	oldPop := sm.GetRelayState(height - 1).Population
	// load old state
	oldPk2s := make([]*bls.PubKey2, oldPop)
	oldIds := make(map[common.Address]uint32, 0)
	oldState.IterateIdentities(func(key []byte, value []byte) bool {
		if key == nil {
			return true
		}
		var data state.ApprovedIdentity
		if err := data.FromBytes(value); err != nil {
			return false
		}
		if data.Approved && data.Index > 0 {
			addr := common.Address{}
			addr.SetBytes(key[1:])
			oldIds[addr] = data.Index
			pk2, _ := bls.NewPubKey2(data.Pk2)
			oldPk2s[data.Index-1] = pk2
		}
		return false
	})
	// load new state and record diff
	newState, _ := sm.appState.IdentityState.Readonly(height)
	newIds := make(map[common.Address]uint32, 0)
	addIdMap := make(map[common.Address]state.ApprovedIdentity, 0)
	newState.IterateIdentities(func(key []byte, value []byte) bool {
		if key == nil {
			return true
		}
		var data state.ApprovedIdentity
		if err := data.FromBytes(value); err != nil {
			return false
		}
		if data.Approved && data.Index > 0 {
			addr := common.Address{}
			addr.SetBytes(key[1:])
			newIds[addr] = data.Index
			if oldIds[addr] == 0 {
				addIdMap[addr] = data
			}
		}
		return false
	})
	addIds = getOrderedObjectsKeys(addIdMap)
	addPk1s = make([]*bls.PubKey1, len(addIds))
	for i, addr := range addIds {
		addPk1s[i], _ = bls.NewPubKey1(addIdMap[addr].Pk1)
	}
	// get removed info
	rmFlags = state.NewBitArray(int(oldPop))
	for addr, idx := range oldIds {
		if newIds[addr] == 0 {
			rmFlags.SetIndex(int(idx-1), true)
			rmCount++
		}
	}
	// calc apk2
	if rs.SignFlags != nil {
		signers := rs.SignFlags.ToArray()
		pk2s := make([]*bls.PubKey2, len(signers))
		for i, idx := range signers {
			pk2s[i] = oldPk2s[idx-1]
		}
		apk2 = bls.AggregatePubKeys2(pk2s)
	}
	return
}

// update identity indexes for relay
func UpdateRelayState(height uint64, s *state.IdentityStateDB, prev *state.RelayState) *state.RelayState {
	if height < ActiveHeight {
		return prev
	}
	oldPop, oldRoot := 0, []byte(nil)
	if !prev.Empty() {
		oldPop = int(prev.Population)
		oldRoot = prev.Root
	}
	oldIds, addIds, rmIds := s.GetUpdatesForRelay()
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
	rs.Root = calcRoot(height, oldRoot, rmFlags, addSorted, addIds)
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
