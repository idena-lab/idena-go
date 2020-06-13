package state

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/database"
	"github.com/idena-network/idena-go/log"
	models "github.com/idena-network/idena-go/protobuf"
	"github.com/pkg/errors"
	dbm "github.com/tendermint/tm-db"
	"strconv"
	"sync"
)

type IdentityStateDB struct {
	db       dbm.DB
	original dbm.DB
	tree     Tree

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateIdentities      map[common.Address]*stateApprovedIdentity
	stateIdentitiesDirty map[common.Address]struct{}

	log  log.Logger
	lock sync.Mutex
}

func NewLazyIdentityState(db dbm.DB) *IdentityStateDB {
	pdb := dbm.NewPrefixDB(db, loadIdentityPrefix(db, false))
	tree := NewMutableTreeWithOpts(pdb, dbm.NewMemDB(), DefaultTreeKeepEvery, DefaultTreeKeepRecent)
	return &IdentityStateDB{
		db:                   pdb,
		original:             db,
		tree:                 tree,
		stateIdentities:      make(map[common.Address]*stateApprovedIdentity),
		stateIdentitiesDirty: make(map[common.Address]struct{}),
		log:                  log.New(),
	}
}

func (s *IdentityStateDB) ForCheckWithOverwrite(height uint64) (*IdentityStateDB, error) {
	db := database.NewBackedMemDb(s.db)
	tree := NewMutableTreeWithOpts(db, database.NewBackedMemDb(s.tree.RecentDb()), s.tree.KeepEvery(), s.tree.KeepRecent())
	if _, err := tree.LoadVersionForOverwriting(int64(height)); err != nil {
		return nil, err
	}

	return &IdentityStateDB{
		db:                   db,
		original:             s.original,
		tree:                 tree,
		stateIdentities:      make(map[common.Address]*stateApprovedIdentity),
		stateIdentitiesDirty: make(map[common.Address]struct{}),
		log:                  log.New(),
	}, nil
}

func (s *IdentityStateDB) ForCheck(height uint64) (*IdentityStateDB, error) {
	db := database.NewBackedMemDb(s.db)
	tree := NewMutableTreeWithOpts(db, database.NewBackedMemDb(s.tree.RecentDb()), s.tree.KeepEvery(), s.tree.KeepRecent())
	if _, err := tree.LoadVersion(int64(height)); err != nil {
		return nil, err
	}

	return &IdentityStateDB{
		db:                   db,
		original:             s.original,
		tree:                 tree,
		stateIdentities:      make(map[common.Address]*stateApprovedIdentity),
		stateIdentitiesDirty: make(map[common.Address]struct{}),
		log:                  log.New(),
	}, nil
}

func (s *IdentityStateDB) Readonly(height uint64) (*IdentityStateDB, error) {
	tree := NewMutableTreeWithOpts(s.db, s.tree.RecentDb(), s.tree.KeepEvery(), s.tree.KeepRecent())
	if _, err := tree.LazyLoad(int64(height)); err != nil {
		return nil, err
	}

	return &IdentityStateDB{
		db:                   s.db,
		original:             s.original,
		tree:                 tree,
		stateIdentities:      make(map[common.Address]*stateApprovedIdentity),
		stateIdentitiesDirty: make(map[common.Address]struct{}),
		log:                  log.New(),
	}, nil
}

func (s *IdentityStateDB) LoadPreliminary(height uint64) (*IdentityStateDB, error) {
	pdb := dbm.NewPrefixDB(s.original, loadIdentityPrefix(s.original, true))
	tree := NewMutableTree(pdb)
	version, err := tree.Load()
	if err != nil {
		return nil, err
	}
	if version != int64(height) {
		loaded := false
		versions := tree.AvailableVersions()

		for i := len(versions) - 1; i >= 0; i-- {
			if versions[i] <= int(height) {
				if _, err := tree.LoadVersion(int64(versions[i])); err != nil {
					return nil, err
				}
				loaded = true
				break
			}
		}
		if !loaded {
			return nil, errors.New("tree version is not found")
		}
	}

	return &IdentityStateDB{
		db:                   pdb,
		original:             s.original,
		tree:                 tree,
		stateIdentities:      make(map[common.Address]*stateApprovedIdentity),
		stateIdentitiesDirty: make(map[common.Address]struct{}),
		log:                  log.New(),
	}, nil
}

func (s *IdentityStateDB) Load(height uint64) error {
	_, err := s.tree.LoadVersion(int64(height))
	return err
}

func (s *IdentityStateDB) Add(identity common.Address) {
	s.GetOrNewIdentityObject(identity).SetState(true)
}

func (s *IdentityStateDB) Remove(identity common.Address) {
	s.GetOrNewIdentityObject(identity).SetState(false)
}

// Commit writes the state to the underlying in-memory trie database.
func (s *IdentityStateDB) Commit(deleteEmptyObjects bool) (root []byte, version int64, diff *IdentityStateDiff, err error) {
	diff = s.Precommit(deleteEmptyObjects)
	hash, version, err := s.CommitTree(s.tree.Version() + 1)
	return hash, version, diff, err
}

func (s *IdentityStateDB) CommitTree(newVersion int64) (root []byte, version int64, err error) {
	hash, version, err := s.tree.SaveVersionAt(newVersion)
	if version > MaxSavedStatesCount {

		versions := s.tree.AvailableVersions()

		for i := 0; i < len(versions)-MaxSavedStatesCount; i++ {
			if s.tree.ExistVersion(int64(versions[i])) {
				err = s.tree.DeleteVersion(int64(versions[i]))
				if err != nil {
					panic(err)
				}
			}
		}

	}

	s.Clear()
	return hash, version, err
}

func (s *IdentityStateDB) Precommit(deleteEmptyObjects bool) *IdentityStateDiff {
	// Commit identity objects to the trie.
	diff := new(IdentityStateDiff)
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, addr := range getOrderedObjectsKeys(s.stateIdentitiesDirty) {
		stateObject := s.stateIdentities[addr]
		if deleteEmptyObjects && stateObject.empty() {
			s.deleteStateIdentityObject(stateObject)
			diff.Values = append(diff.Values, &IdentityStateDiffValue{
				Address: addr,
				Deleted: true,
			})
		} else {
			encoded := s.updateStateIdentityObject(stateObject)
			diff.Values = append(diff.Values, &IdentityStateDiffValue{
				Address: addr,
				Deleted: false,
				Value:   encoded,
			})
		}
		delete(s.stateIdentitiesDirty, addr)
	}
	return diff
}

// get changed identities for relay
// must be called before Precommit
func (s *IdentityStateDB) GetUpdatesForRelay() (map[uint32]common.Address, map[common.Address]ApprovedIdentity, []uint32) {
	addIds := make(map[common.Address]ApprovedIdentity, 0)
	oldIds := make(map[uint32]common.Address)
	s.IterateIdentities(func(key []byte, value []byte) bool {
		if key == nil {
			return true
		}
		addr := common.Address{}
		addr.SetBytes(key[1:])
		var data ApprovedIdentity
		if err := data.FromBytes(value); err != nil {
			return false
		}
		if data.Approved && data.Index == 0 {
			addIds[addr] = data
		} else {
			oldIds[data.Index] = addr
		}
		return false
	})
	s.lock.Lock()
	defer s.lock.Unlock()
	rmIds := make([]uint32, 0)
	for addr, _ := range s.stateIdentitiesDirty {
		stateObject := s.stateIdentities[addr]
		index := stateObject.Index()
		if stateObject.empty() {
			delete(addIds, addr)
			if index > 0 {
				rmIds = append(rmIds, index)
			}
		} else if index == 0 {
			addIds[addr] = stateObject.data
		}
	}
	return oldIds, addIds, rmIds
}

func (s *IdentityStateDB) Reset() {
	s.Clear()
	s.tree.Rollback()
}

func (s *IdentityStateDB) Clear() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.stateIdentities = make(map[common.Address]*stateApprovedIdentity)
	s.stateIdentitiesDirty = make(map[common.Address]struct{})
}

// Retrieve a state object or create a new state object if nil
func (s *IdentityStateDB) GetOrNewIdentityObject(addr common.Address) *stateApprovedIdentity {
	stateObject := s.getStateIdentity(addr)
	if stateObject == nil || stateObject.deleted {
		stateObject, _ = s.createIdentity(addr)
	}
	return stateObject
}

func (s *IdentityStateDB) createIdentity(addr common.Address) (newobj, prev *stateApprovedIdentity) {
	prev = s.getStateIdentity(addr)
	newobj = newApprovedIdentityObject(addr, ApprovedIdentity{}, s.MarkStateIdentityObjectDirty)
	newobj.touch()
	s.setStateIdentityObject(newobj)
	return newobj, prev
}

// Retrieve a state account given my the address. Returns nil if not found.
func (s *IdentityStateDB) getStateIdentity(addr common.Address) (stateObject *stateApprovedIdentity) {
	// Prefer 'live' objects.
	s.lock.Lock()
	if obj := s.stateIdentities[addr]; obj != nil {
		s.lock.Unlock()
		if obj.deleted {
			return nil
		}
		return obj
	}
	s.lock.Unlock()

	// Load the object from the database.
	_, enc := s.tree.Get(append(identityPrefix, addr[:]...))
	if len(enc) == 0 {
		return nil
	}
	var data ApprovedIdentity
	if err := data.FromBytes(enc); err != nil {
		s.log.Error("Failed to decode state identity object", "addr", addr, "err", err)
		return nil
	}
	// Insert into the live set.
	obj := newApprovedIdentityObject(addr, data, s.MarkStateIdentityObjectDirty)
	s.setStateIdentityObject(obj)
	return obj
}

func (s *IdentityStateDB) setStateIdentityObject(object *stateApprovedIdentity) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.stateIdentities[object.Address()] = object
}

// MarkStateAccountObjectDirty adds the specified object to the dirty map to avoid costly
// state object cache iteration to find a handful of modified ones.
func (s *IdentityStateDB) MarkStateIdentityObjectDirty(addr common.Address) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.stateIdentitiesDirty[addr] = struct{}{}
}

// updateStateAccountObject writes the given object to the trie.
func (s *IdentityStateDB) updateStateIdentityObject(stateObject *stateApprovedIdentity) (encoded []byte) {
	addr := stateObject.Address()
	data, err := stateObject.data.ToBytes()
	if err != nil {
		panic(fmt.Errorf("can't encode approved identity object at %x: %v", addr[:], err))
	}

	s.tree.Set(append(identityPrefix, addr[:]...), data)
	return data
}

func (s *IdentityStateDB) updateStateIdentityObjectRaw(stateObject *stateApprovedIdentity, value []byte) {
	addr := stateObject.Address()
	s.tree.Set(append(identityPrefix, addr[:]...), value)
}

// deleteStateAccountObject removes the given object from the state trie.
func (s *IdentityStateDB) deleteStateIdentityObject(stateObject *stateApprovedIdentity) {
	stateObject.deleted = true
	addr := stateObject.Address()

	s.tree.Remove(append(identityPrefix, addr[:]...))
}

func (s *IdentityStateDB) Root() common.Hash {
	return s.tree.WorkingHash()
}

func (s *IdentityStateDB) IsApproved(addr common.Address) bool {
	stateObject := s.getStateIdentity(addr)
	if stateObject != nil {
		return stateObject.data.Approved
	}
	return false
}

func (s *IdentityStateDB) IsOnline(addr common.Address) bool {
	stateObject := s.getStateIdentity(addr)
	if stateObject != nil {
		return stateObject.data.Online
	}
	return false
}

func (s *IdentityStateDB) GetIndex(addr common.Address) uint32 {
	stateObject := s.getStateIdentity(addr)
	if stateObject != nil {
		return stateObject.data.Index
	}
	return 0
}

func (s *IdentityStateDB) SetOnline(addr common.Address, online bool) {
	s.GetOrNewIdentityObject(addr).SetOnline(online)
}

func (s *IdentityStateDB) SetIndex(addr common.Address, index uint32) {
	s.GetOrNewIdentityObject(addr).SetIndex(index)
}

func (s *IdentityStateDB) SetBlsKeys(addr common.Address, pk1, pk2 []byte) {
	s.GetOrNewIdentityObject(addr).SetBlsKeys(pk1, pk2)
}

func (s *IdentityStateDB) ResetTo(height uint64) error {
	s.Clear()
	_, err := s.tree.LoadVersionForOverwriting(int64(height))
	return err
}

func (s *IdentityStateDB) HasVersion(height uint64) bool {
	return s.tree.ExistVersion(int64(height))
}
func (s *IdentityStateDB) IterateIdentities(fn func(key []byte, value []byte) bool) bool {
	return s.tree.GetImmutable().IterateRange(nil, nil, true, fn)
}

func (s *IdentityStateDB) Version() uint64 {
	return uint64(s.tree.Version())
}

func (s *IdentityStateDB) AddDiff(height uint64, diff *IdentityStateDiff) {
	if diff.Empty() {
		return
	}

	s.tree.SetVirtualVersion(int64(height) - 1)

	for _, v := range diff.Values {
		stateObject := s.GetOrNewIdentityObject(v.Address)
		if v.Deleted {
			s.deleteStateIdentityObject(stateObject)
		} else {
			s.updateStateIdentityObjectRaw(stateObject, v.Value)
		}
	}
}

func (s *IdentityStateDB) SaveForcedVersion(height uint64) error {
	if s.tree.Version() == int64(height) {
		return nil
	}
	s.tree.SetVirtualVersion(int64(height) - 1)
	_, _, err := s.CommitTree(int64(height))
	return err
}

func (s *IdentityStateDB) SwitchToPreliminary(height uint64) (batch dbm.Batch, dropDb dbm.DB, err error) {

	prefix := loadIdentityPrefix(s.original, true)
	if prefix == nil {
		return nil, nil, errors.New("preliminary prefix is not found")
	}
	pdb := dbm.NewPrefixDB(s.original, prefix)
	tree := NewMutableTree(pdb)
	if _, err := tree.LoadVersion(int64(height)); err != nil {
		return nil, nil, err
	}

	batch = s.original.NewBatch()
	setIdentityPrefix(batch, prefix, false)
	setIdentityPrefix(batch, nil, true)
	dropDb = s.db

	s.db = pdb
	s.tree = tree
	return batch, dropDb, nil
}

func (s *IdentityStateDB) DropPreliminary() {
	pdb := dbm.NewPrefixDB(s.original, loadIdentityPrefix(s.original, true))
	common.ClearDb(pdb)
	b := s.original.NewBatch()
	setIdentityPrefix(b, nil, true)
	b.WriteSync()
}

func (s *IdentityStateDB) CreatePreliminaryCopy(height uint64) (*IdentityStateDB, error) {
	preliminaryPrefix := identityStatePrefix(height + 1)
	pdb := dbm.NewPrefixDB(s.original, preliminaryPrefix)

	if err := common.Copy(s.db, pdb); err != nil {
		return nil, err
	}

	b := s.original.NewBatch()
	setIdentityPrefix(b, preliminaryPrefix, true)
	if err := b.WriteSync(); err != nil {
		return nil, err
	}
	return s.LoadPreliminary(height)
}

func (s *IdentityStateDB) SetPredefinedIdentities(state *models.ProtoPredefinedState) {
	for _, identity := range state.ApprovedIdentities {
		stateObj := s.GetOrNewIdentityObject(common.BytesToAddress(identity.Address))
		stateObj.data.Online = false
		stateObj.data.Approved = identity.Approved
		stateObj.data.Index = identity.Index
		stateObj.data.Pk1 = identity.Pk1
		stateObj.data.Pk2 = identity.Pk2
		stateObj.touch()
	}
}

func (s *IdentityStateDB) FlushToDisk() error {
	return common.Copy(s.tree.RecentDb(), s.db)
}

func (s *IdentityStateDB) SwitchTree(keepEvery, keepRecent int64) error {
	version := s.tree.Version()
	s.tree = NewMutableTreeWithOpts(s.db, s.tree.RecentDb(), keepEvery, keepRecent)
	if _, err := s.tree.LoadVersion(version); err != nil {
		return err
	}
	s.Clear()
	return nil
}

type IdentityStateDiffValue struct {
	Address common.Address
	Deleted bool
	Value   []byte
}

type IdentityStateDiff struct {
	Values []*IdentityStateDiffValue
}

func (diff *IdentityStateDiff) Empty() bool {
	return diff == nil || len(diff.Values) == 0
}

func (diff *IdentityStateDiff) ToProto() *models.ProtoIdentityStateDiff {
	protoDiff := new(models.ProtoIdentityStateDiff)
	for _, item := range diff.Values {
		protoDiff.Values = append(protoDiff.Values, &models.ProtoIdentityStateDiff_IdentityStateDiffValue{
			Address: item.Address[:],
			Deleted: item.Deleted,
			Value:   item.Value,
		})
	}
	return protoDiff
}

func (diff *IdentityStateDiff) ToBytes() ([]byte, error) {
	return proto.Marshal(diff.ToProto())
}

func (diff *IdentityStateDiff) FromProto(protoDiff *models.ProtoIdentityStateDiff) *IdentityStateDiff {
	for _, item := range protoDiff.Values {
		diff.Values = append(diff.Values, &IdentityStateDiffValue{
			Address: common.BytesToAddress(item.Address),
			Deleted: item.Deleted,
			Value:   item.Value,
		})
	}
	return diff
}

func (diff *IdentityStateDiff) FromBytes(data []byte) error {
	protoDiff := new(models.ProtoIdentityStateDiff)
	if err := proto.Unmarshal(data, protoDiff); err != nil {
		return err
	}
	diff.FromProto(protoDiff)
	return nil
}

type RelayState struct {
	Root       []byte
	Signature  []byte
	Population uint32
	SignFlags  *common.Bitmap // nil means need no sign
}

func (relay *RelayState) SignRate() float64 {
	if relay.SignFlags == nil {
		return 0
	}
	return float64(len(relay.SignFlags.ToArray())) / float64(relay.Population)
}

func (relay *RelayState) Empty() bool {
	return relay == nil || len(relay.Root) == 0
}

func (relay *RelayState) NeedSign() bool {
	return !relay.Empty() && relay.SignFlags != nil
}

func (relay *RelayState) ToProto() *models.ProtoRelayState {
	pr := new(models.ProtoRelayState)
	pr.Root = relay.Root
	pr.Signature = relay.Signature
	pr.Population = relay.Population
	if relay.SignFlags == nil {
		pr.SignFlags = []byte{}
	} else {
		pr.SignFlags = relay.SignFlags.Bytes()
	}
	return pr
}

func (relay *RelayState) ToBytes() ([]byte, error) {
	return proto.Marshal(relay.ToProto())
}

func (relay *RelayState) FromProto(pr *models.ProtoRelayState) *RelayState {
	relay.Root = pr.Root
	relay.Signature = pr.Signature
	relay.Population = pr.Population
	if len(pr.SignFlags) == 0 {
		relay.SignFlags = nil
	} else {
		relay.SignFlags = common.NewBitmap(pr.Population)
		relay.SignFlags.Read(pr.SignFlags)
	}
	return relay
}

func (relay *RelayState) FromBytes(data []byte) error {
	pr := new(models.ProtoRelayState)
	if err := proto.Unmarshal(data, pr); err != nil {
		return err
	}
	relay.FromProto(pr)
	return nil
}

func identityStatePrefix(height uint64) []byte {
	return []byte("aid-" + strconv.FormatUint(height, 16))
}

func loadIdentityPrefix(db dbm.DB, preliminary bool) []byte {
	key := currentIdentityStateDbPrefixKey
	if preliminary {
		key = preliminaryIdentityStateDbPrefixKey
	}
	p, _ := db.Get(key)
	if p == nil {
		p = identityStatePrefix(0)
		b := db.NewBatch()
		setIdentityPrefix(b, p, preliminary)
		b.WriteSync()
		return p
	}
	return p
}

func setIdentityPrefix(batch dbm.Batch, prefix []byte, preliminary bool) {
	key := currentIdentityStateDbPrefixKey
	if preliminary {
		key = preliminaryIdentityStateDbPrefixKey
	}
	batch.Set(key, prefix)
}
