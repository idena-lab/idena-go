package bls

import (
	"crypto/rand"
	"github.com/idena-network/idena-go/crypto/bn256"
	"github.com/idena-network/idena-go/crypto/sha3"
	"io"
	"math/big"
)

var (
	zero  = big.NewInt(0)
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
)

// private key
type PriKey struct {
	sk big.Int
}

// public key on G1
type PubKey1 struct {
	pk bn256.G1
}

// public key on G2
type PubKey2 struct {
	pk bn256.G2
}

// signature on G1
type Signature struct {
	s bn256.G1
}

// create private key from `k`
// if k is nil, a new random private key will created
func NewPriKey(k *big.Int) (*PriKey, error) {
	var err error
	if k == nil {
		if k, _, err = bn256.RandomG1(rand.Reader); err != nil {
			return nil, err
		}
	}
	sk := &PriKey{sk: *k}
	return sk, nil
}

func GenerateFromSeed(rand io.Reader) (*PriKey, error) {
	k, _, err := bn256.RandomG1(rand)
	if err != nil {
		return nil, err
	}
	return &PriKey{sk: *k}, nil
}

// return public key on G1
func (k *PriKey) GetPub1() *PubKey1 {
	pk := new(bn256.G1).ScalarBaseMult(&k.sk)
	return &PubKey1{*pk}
}

// return public key on G2
func (k *PriKey) GetPub2() *PubKey2 {
	pk := new(bn256.G2).ScalarBaseMult(&k.sk)
	return &PubKey2{*pk}
}

// Sign signs a message (m) with the private key
//   s = sk * H(m)
// the signature is on G1
func (k *PriKey) Sign(m []byte) *Signature {
	hm := HashToG1(m)
	sig := Signature{}
	sig.s.ScalarMult(hm, &k.sk)
	return &sig
}

func (k *PriKey) ToInt() *big.Int {
	return new(big.Int).Set(&k.sk)
}

func (k *PriKey) ToHex() string {
	return BigToHex32(&k.sk)
}

func (k *PriKey) String() string {
	return k.ToHex()
}

func NewPubKey1(m []byte) (*PubKey1, error) {
	pk1 := new(PubKey1)
	if _, err := pk1.pk.Unmarshal(m); err != nil {
		return nil, err
	}
	return pk1, nil
}

func (p *PubKey1) GetPoint() *bn256.G1 {
	return new(bn256.G1).Set(&p.pk)
}

func (p *PubKey1) Marshal() []byte {
	return p.pk.Marshal()
}

func (p *PubKey1) Unmarshal(m []byte) error {
	_, err := p.pk.Unmarshal(m)
	return err
}

func (p *PubKey1) ToHex() [2]string {
	return PointToHex1(&p.pk)
}

func (p *PubKey1) Add(other *PubKey1) *PubKey1 {
	return &PubKey1{pk: *new(bn256.G1).Add(&p.pk, &other.pk)}
}

func NewPubKey2(m []byte) (*PubKey2, error) {
	pk2 := new(PubKey2)
	if _, err := pk2.pk.Unmarshal(m); err != nil {
		return nil, err
	}
	return pk2, nil
}

func (p *PubKey2) GetPoint() *bn256.G2 {
	return new(bn256.G2).Set(&p.pk)
}

func (p *PubKey2) Marshal() []byte {
	return p.pk.Marshal()
}

func (p *PubKey2) ToHex() [4]string {
	return PointToHex2(&p.pk)
}

func (p *PubKey2) Add(other *PubKey2) *PubKey2 {
	return &PubKey2{pk: *new(bn256.G2).Add(&p.pk, &other.pk)}
}

func NewSignature(m []byte) (*Signature, error) {
	if len(m) == 0 {
		return nil, nil
	}
	s := new(Signature)
	if _, err := s.s.Unmarshal(m); err != nil {
		return nil, err
	}
	return s, nil
}


func (s *Signature) GetPoint() *bn256.G1 {
	return new(bn256.G1).Set(&s.s)
}

func (s *Signature) ToHex() [2]string {
	return PointToHex1(&s.s)
}

func (s *Signature) Marshal() []byte {
	if s == nil {
		return nil
	}
	return s.s.Marshal()
}

// Check whether pk1 and pk2 are generated by the same private key
func CheckPubKeyPair(pk1 *PubKey1, pk2 *PubKey2) bool {
	a := []*bn256.G1{&pk1.pk, P1Neg}
	b := []*bn256.G2{P2, &pk2.pk}
	return bn256.PairingCheck(a, b)
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Verify checks the signature (s) of a message (m) with the public key (pk)
//   e(H(m), pk) ?== e(s, g2)
func Verify(m []byte, s *Signature, pk *PubKey2) bool {
	hm := new(bn256.G1).Neg(HashToG1(m))
	a := make([]*bn256.G1, 2)
	b := make([]*bn256.G2, 2)
	a[0], b[0] = hm, &pk.pk
	a[1], b[1] = s.GetPoint(), P2
	return bn256.PairingCheck(a, b)
}

func NewSignatureFromBigInt(x, y *big.Int) (*Signature, error) {
	s, err := BuildG1(x, y)
	if err != nil {
		return nil, err
	}
	return &Signature{s: *s}, nil
}

func AggregatePubKeys1(keys []*PubKey1) *PubKey1 {
	points := make([]*bn256.G1, len(keys))
	for i := 0; i < len(keys); i++ {
		points[i] = &keys[i].pk
	}
	p := aggregatePoints1(points)
	return &PubKey1{pk: *p}
}

func AggregatePubKeys2(keys []*PubKey2) *PubKey2 {
	points := make([]*bn256.G2, len(keys))
	for i := 0; i < len(keys); i++ {
		points[i] = &keys[i].pk
	}
	p := aggregatePoints2(points)
	return &PubKey2{pk: *p}
}

func AggregateSignatures(signs ...*Signature) *Signature {
	points := make([]*bn256.G1, len(signs))
	for i := 0; i < len(signs); i++ {
		points[i] = &signs[i].s
	}
	p := aggregatePoints1(points)
	return &Signature{s: *p}
}
