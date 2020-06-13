package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/hexutil"
	"github.com/idena-network/idena-go/core/state"
	"github.com/stretchr/testify/require"
	db "github.com/tendermint/tm-db"
	"testing"
)

func randPk2Bytes() []byte {
	pk2 := make([]byte, 32*4)
	_, _ = rand.Read(pk2)
	return pk2
}

func TestUpdateRelayStateWithData(t *testing.T) {
	data := &rstTestData{}
	_ = json.Unmarshal([]byte(rstJson), data)
	isDb := state.NewLazyIdentityState(db.NewMemDB())

	require.True(t, data.Init.Height > ActiveHeight)

	// init
	for i, sa := range data.Init.Identities {
		addr := common.HexToAddress(sa)
		isDb.Add(addr)
		pk1x, _ := hexutil.Decode(data.Init.PubKeys[i][0])
		pk1y, _ := hexutil.Decode(data.Init.PubKeys[i][1])
		pk1 := append(pk1x[:], pk1y...)
		isDb.SetBlsKeys(addr, pk1, randPk2Bytes())
	}
	rs := UpdateRelayState(data.Init.Height, isDb, new(state.RelayState))
	isDb.Commit(true)
	checkState(t, isDb, rs, data.Init.Checks)

	// updates
	for _, up := range data.Updates {
		// remove old
		rmFlags := state.NewBitArray(int(rs.Population))
		rmBytes, _ := hexutil.Decode(up.RemoveFlags)
		for i := 0; i < int(rs.Population); i++ {
			if (rmBytes[i/8] & (1 << (i % 8))) != 0 {
				rmFlags.SetIndex(i, true)
			}
		}
		isDb.IterateIdentities(func(key []byte, value []byte) bool {
			if key == nil {
				return true
			}
			var data state.ApprovedIdentity
			if err := data.FromBytes(value); err != nil {
				return false
			}
			if data.Index > 0 && rmFlags.GetIndex(int(data.Index-1)) {
				addr := common.Address{}
				addr.SetBytes(key[1:])
				isDb.Remove(addr)
			}
			return false
		})
		// add new
		for i, sa := range up.NewIdentities {
			addr := common.HexToAddress(sa)
			isDb.Add(addr)
			pk1x, _ := hexutil.Decode(up.NewPubKeys[i][0])
			pk1y, _ := hexutil.Decode(up.NewPubKeys[i][1])
			pk1 := append(pk1x[:], pk1y...)
			isDb.SetBlsKeys(addr, pk1, randPk2Bytes())
		}
		rs = UpdateRelayState(up.Height, isDb, rs)
		isDb.Commit(true)
		checkState(t, isDb, rs, up.Checks)
	}
}

func checkState(t *testing.T, isDb *state.IdentityStateDB, rs *state.RelayState, check *rstCheck) {
	// t.Log(rs.Population, check)
	require.True(t, rs.NeedSign())
	require.True(t, rs.Population == check.Population)
	root, _ := hexutil.Decode(check.StateRoot)
	require.True(t, bytes.Equal(rs.Root, root))

	// compare ids
	require.True(t, isDb.GetIndex(check.FirstId.Address) == 1)
	require.True(t, isDb.GetIndex(check.LastId.Address) == rs.Population)
	require.True(t, isDb.GetIndex(check.MiddleId.Address) == rs.Population/2+1)

	// compare pk1s
	for _, rid := range []*rstId{check.FirstId, check.LastId, check.MiddleId} {
		sId := isDb.GetOrNewIdentityObject(rid.Address)
		pk1x, _ := hexutil.Decode(rid.PubKey[0])
		pk1y, _ := hexutil.Decode(rid.PubKey[1])
		pk1 := append(pk1x[:], pk1y...)
		require.Equal(t, sId.GetPk1(), pk1)
	}
}

type rstId struct {
	Address common.Address `json:"address"`
	PubKey  [2]string      `json:"pubKey"`
}

type rstCheck struct {
	Valid      bool   `json:"valid"`
	Height     uint64 `json:"height"`
	Population uint32 `json:"population"`
	StateRoot  string `json:"root"`
	FirstId    *rstId `json:"firstId"`
	LastId     *rstId `json:"lastId"`
	MiddleId   *rstId `json:"middleId"`
}

type rstInit struct {
	Comment string `json:"comment"`
	Height  uint64 `json:"height"`
	// new identities' addresses
	Identities []string `json:"identities"`
	// new identities' public keys (G1)
	PubKeys [][2]string `json:"pubKeys"`
	// check conditions
	Checks *rstCheck `json:"checks"`
}

type rstUpdate struct {
	Comment string `json:"comment"`
	Height  uint64 `json:"height"`
	// new identities' addresses
	NewIdentities []string `json:"newIdentities"`
	// new identities' public keys (G1)
	NewPubKeys [][2]string `json:"newPubKeys"`
	// flags of remove identities
	RemoveFlags string `json:"removeFlags"`
	RemoveCount int    `json:"removeCount"`
	// flags of signers
	SignFlags string `json:"signFlags"`
	// aggregated signature
	Signature [2]string `json:"signature"`
	// aggregated public keys of signers
	Apk2 [4]string `json:"apk2"`
	// check conditions
	Checks *rstCheck `json:"checks"`
}

type rstTestData struct {
	Init    *rstInit     `json:"init"`
	Updates []*rstUpdate `json:"updates"`
}

var rstJson = `
{
  "init": {
    "comment": "epcoch(12345678): init with 20 identities",
    "height": 12345678,
    "identities": [
      "0xEea5f4f74391f445D15aFd4294040374F6924B98",
      "0xD1e91E00167939cb6694D2c422ACd208A0072939",
      "0xcd0668d2d6C52f5054e2d0836Bf84C7174cb7476",
      "0xCBf8713f8d962d7C8d019192c24224E2cafCcae3",
      "0xb37C5821b6d95526A41A9504680B4e7c8B763a1b",
      "0xA61fB586B14323a6bC8f9E7DF1D929333ff99393",
      "0xA1786f9ffF094279Db1944ebD7A19D0f7BBACbe0",
      "0x95aF5a25367951baa2FF6cD471c483f15fb90BAd",
      "0x8eBEA89c0B4b373970115E82ed6F4125c8Fa7311",
      "0x7F01f1F573981659A44ff17a4C7215A3B539eB1e",
      "0x5849C6077DbB5722f5717A289A266f9764798199",
      "0x52FDfc072182654f163F5F0f9A621D729566c74D",
      "0x487F6999Eb9d18A44784045D87F3C67Cf22746E9",
      "0x3Bea6F5B3Af6De0374366C4719e43a1B067D89bC",
      "0x364cc3DBD968B0F7172ED85794Bb358b0C3b525D",
      "0x255aa5B7d44bec40f84C892b9Bffd43629b0223B",
      "0x21119c160F0702448615bBDA08313f6A8Eb668D2",
      "0x1D49D4955C8486216325253FeC738DD7A9e28BF9",
      "0x10037c4D7Bbb0407D1e2c64981855ad8681d0d86",
      "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b"
    ],
    "pubKeys": [
      [
        "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
        "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
      ],
      [
        "0x0e8e3bfcd440154d082a8277c12388de58558eaeba4c4d2bb677609d84d90262",
        "0x0be2b1e820cc64e955d64e41ebf5dd494fed63ed39fd2d4f9a662a1f8f87c90c"
      ],
      [
        "0x029b031af5c4ba2fbf0bb6b8f630217b29ddd307809a3a729160b5bfc0ce662c",
        "0x252e4eeb7c040f63d70af4e2ac4f1d344157e28a472c9569e69dfa3069d67927"
      ],
      [
        "0x0c189e823c6ef04ba34bbd3a6af5f4cb52ef595417f62f04e210b840cb867ff6",
        "0x0769f24ac657f4655b580721f27d4205891800efe9ba4b101b2f8cb7da37433d"
      ],
      [
        "0x1cbb82d0d0bd7fcd11b7e33a1f329193151bdd47922b84a72738c0c4db437ff0",
        "0x0d2940b14e54011392b18a838d19f92c63b43e721ff29c8a330c5a88eb870e9a"
      ],
      [
        "0x24b8a16bd1dbfaaf905289313b7415a806360ea19c33cc72b562331fd24e3b38",
        "0x198042e298d425d6ab1523a6d178723712f1b306ce4cf4877699bfd97a3d21b8"
      ],
      [
        "0x27e30fac534dd87a751c483a6933af8207c1186fe75907c130f6e174c5cf28e4",
        "0x1e9572acaed76d442a1143fbced5cb419c5d3ed562b7de41669a6db5dcaa323a"
      ],
      [
        "0x110fe492083ea46899ac6e7356cbad27e7e1fe2ded90d04afa0460fe7089f893",
        "0x09f13dfb97ff1517636e41ef9b6bad075f982308f64bbee0abfb83be77653581"
      ],
      [
        "0x11c95b19365137e3ce2f95d03f4a33ebba58b1bd739bfda382f155adb53f561f",
        "0x08a83ee2a5d250613687c68cb0b1cbeb8765b576f6735aa654761789e1e01320"
      ],
      [
        "0x0774ea004d23d51c1e94a6741af2ba9bc13163b0e25eda3ba60e5ae36183ce44",
        "0x125936e607005372dd416d929024c7811ff7f5281ae67164d100037b4d7c1866"
      ],
      [
        "0x13829176ec03336781ed2da9a48790eb2db7d775672e28bec8a35c01c36ed73a",
        "0x2a23171826ce08db29d9869a81cfe01c445be238704472362a1d4a5c7c90c95b"
      ],
      [
        "0x27048d1d7f25b409930bfc37b0bf663555cefc083dd7004af2b7e5202b0e3b87",
        "0x1a7b7598849e3b4a263648a039ecc55f1b81bf705461a9722be748e3d90a8b1b"
      ],
      [
        "0x2fe01d907359cef679aa1dd32f92fad90c0089b9b45e4ceaf5ff67f56e5f753a",
        "0x2a923999cacf6e3625d04237a559fb5c240aa9221059c7d3933fed1dee0d6405"
      ],
      [
        "0x167eef7818cdadf08c38eaee2152af59510b594a601c93fdedbca87cec0162d1",
        "0x00c72dbf6669f9ce185ac98a5217558637a1aa3f91358ade422fc262a8a70a10"
      ],
      [
        "0x1e28f93bd6bcfe3b4b45f6b40f2cb3d3fac1825b45a3ccfb62303badb8220024",
        "0x0392b560864052071111ea630cb07708fcfcdcf12786e53ef50123df57d6f909"
      ],
      [
        "0x28235790313e0ad4dbeb1305fc9b513c1b4f63ea6db8b627b421c11ced9a9759",
        "0x001db993024b9ffa3d4b1a1fcae26d70c7265048fc2929d85ebf73d3267b1744"
      ],
      [
        "0x02ef9862a2904c5ace3c8f1d6700eb90829ff0ba6d865a036a8b2669228cc683",
        "0x035c5f146b963acd3a167995e7d5b9a85dbf633b437061b798e2ec5563fc075f"
      ],
      [
        "0x250b2ff47ca495912c02958bfe36fb72a1f9a6247d13b70e3f0da5f3bd3cf8ed",
        "0x1cf627148a085ff5ed935f834a497439c046d942ae17071e99118bb487ac965b"
      ],
      [
        "0x26f70e5c56c2810b181dc8526305bb67a218345cf3110e6e40b887bb26abdc36",
        "0x0fc77ab2cf3d60a25f251a72fc003824afdca1cea649e43b22659f02d42763e7"
      ],
      [
        "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
        "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
      ]
    ],
    "checks": {
      "valid": true,
      "height": 12345678,
      "population": 20,
      "root": "0x5adc64f3d0c163438fef7c2c3fef16b7fb9efc5cf4fa59e70bacadb23c95a432",
      "firstId": {
        "address": "0xEea5f4f74391f445D15aFd4294040374F6924B98",
        "pubKey": [
          "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
          "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
        ]
      },
      "lastId": {
        "address": "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b",
        "pubKey": [
          "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
          "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
        ]
      },
      "middleId": {
        "address": "0x5849C6077DbB5722f5717A289A266f9764798199",
        "pubKey": [
          "0x13829176ec03336781ed2da9a48790eb2db7d775672e28bec8a35c01c36ed73a",
          "0x2a23171826ce08db29d9869a81cfe01c445be238704472362a1d4a5c7c90c95b"
        ]
      }
    }
  },
  "updates": [
    {
      "comment": "height(12345679): 20 identities -0 +0 by 16 signers(80.00%)",
      "height": 12345679,
      "newIdentities": [],
      "newPubKeys": [],
      "removeFlags": "0x000000",
      "removeCount": 0,
      "signFlags": "0xfd770d",
      "signature": [
        "0x0aba35bad47a695cf121f11f04af073ffea34d9c6381a22b098888c9f69ea23b",
        "0x2e1743e813268d21990cdabd85c83d2ddd9c7fba9bdb74d9525d619563bbc90f"
      ],
      "apk2": [
        "0x1c9d0234f10675ad8fc710ccbffc7ffcd4a8132e38bb467d1541cd603f8dcea3",
        "0x28d002c680e3f71ea2b0e3bab6cd747a5db9dce0f20f2a2c14cce5026b80e015",
        "0x0069e79dd6a08cbecc25e707bb053c33c2f0d7866d9995008603f547eed2b83d",
        "0x18d21bdc4e6e2f2d0f698e9d576a01d9ba2109a344885c11343ca60b40519c9a"
      ],
      "checks": {
        "valid": true,
        "height": 12345679,
        "population": 20,
        "root": "0xb1a992e694ccfd34f771003e7c62a36500adf578fa616df5ea6c0faf423bdf08",
        "firstId": {
          "address": "0xEea5f4f74391f445D15aFd4294040374F6924B98",
          "pubKey": [
            "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
            "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
          ]
        },
        "lastId": {
          "address": "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b",
          "pubKey": [
            "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
            "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
          ]
        },
        "middleId": {
          "address": "0x5849C6077DbB5722f5717A289A266f9764798199",
          "pubKey": [
            "0x13829176ec03336781ed2da9a48790eb2db7d775672e28bec8a35c01c36ed73a",
            "0x2a23171826ce08db29d9869a81cfe01c445be238704472362a1d4a5c7c90c95b"
          ]
        }
      }
    },
    {
      "comment": "height(12345680): 20 identities -4 +0 by 18 signers(90.00%)",
      "height": 12345680,
      "newIdentities": [],
      "newPubKeys": [],
      "removeFlags": "0x08800c",
      "removeCount": 4,
      "signFlags": "0xdffe0f",
      "signature": [
        "0x099aa3abad5d0622a9fe98c5120d84e9754027a366c53c7e99764f17a3ec3240",
        "0x13d692be0a8dbcd741e2f40df0c2f2cb7d435afa2048556ad853e776a65de6a7"
      ],
      "apk2": [
        "0x2eda6b61786c335505ede28c49de0789d6cdf0df616577d59121fb0b5a51b0c8",
        "0x2adddf6a4cea3b433ef120c6ccfff0d8a571a91565ae16e79627dbf24fc6fe75",
        "0x29cd34e5ad8b725fd04c5e34b32af6874d640f37e44ae431157c783872f97e4b",
        "0x078d4f4da74835cefea49dd69b3ccea0f80c74d5c1bbc4c18ca51aa35df929c4"
      ],
      "checks": {
        "valid": true,
        "height": 12345680,
        "population": 16,
        "root": "0xa4e2366da22d09d171889bcad24691b7fe23c876c34cc461fd95c4feed9dcbe2",
        "firstId": {
          "address": "0xEea5f4f74391f445D15aFd4294040374F6924B98",
          "pubKey": [
            "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
            "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
          ]
        },
        "lastId": {
          "address": "0x21119c160F0702448615bBDA08313f6A8Eb668D2",
          "pubKey": [
            "0x02ef9862a2904c5ace3c8f1d6700eb90829ff0ba6d865a036a8b2669228cc683",
            "0x035c5f146b963acd3a167995e7d5b9a85dbf633b437061b798e2ec5563fc075f"
          ]
        },
        "middleId": {
          "address": "0x8eBEA89c0B4b373970115E82ed6F4125c8Fa7311",
          "pubKey": [
            "0x11c95b19365137e3ce2f95d03f4a33ebba58b1bd739bfda382f155adb53f561f",
            "0x08a83ee2a5d250613687c68cb0b1cbeb8765b576f6735aa654761789e1e01320"
          ]
        }
      }
    },
    {
      "comment": "height(12345681): 16 identities -0 +5 by 15 signers(93.75%)",
      "height": 12345681,
      "newIdentities": [
        "0xe4d7DefA922D0C796503E1cE221725f50caf1fbF",
        "0xA4B44ed4bcE964ED47f74AA594468CEd323cb76f",
        "0x255aa5B7d44bec40f84C892b9Bffd43629b0223B",
        "0x0d3fac476C9fB03fC9228fBaE88fd580663A0454",
        "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b"
      ],
      "newPubKeys": [
        [
          "0x1135c0858df03729b06cc7497e39a2afd2ed8effd247fd8563eb11f5c91b588e",
          "0x127de6e56075c6bbbef4b0b24838ec77067edf861acd0d7bfa6a4e777abcf251"
        ],
        [
          "0x2eeac016eddf27b96037063dcd50cb28661abef05a2d589b652403e4dec9a7aa",
          "0x27dcd024e85f58b7f2bdd3bd693fc5be28b45cf5296e5668c05367964ee981c8"
        ],
        [
          "0x28235790313e0ad4dbeb1305fc9b513c1b4f63ea6db8b627b421c11ced9a9759",
          "0x001db993024b9ffa3d4b1a1fcae26d70c7265048fc2929d85ebf73d3267b1744"
        ],
        [
          "0x21304363d33ccb1788888e229b8a3f123a86859d3892cfa698a820e805dda944",
          "0x02b01e6eeb3dd4d344843b34295d781d16cdb4e2b0ec4cbe9559ad47e46c6630"
        ],
        [
          "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
          "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
        ]
      ],
      "removeFlags": "0x0000",
      "removeCount": 0,
      "signFlags": "0xefff",
      "signature": [
        "0x1ad166c47c47fc2485ea187fd9678ff791e955e6601bf1a057cfda8978706aee",
        "0x080e8daa00b3ff2aa7b6c48b8a24f39baa1c09d69eb58182a7d47ba49d5a5ee2"
      ],
      "apk2": [
        "0x26a27d46d844f6b1eebe4c24010f7a850db92998ec6a6666f3906a352d80cb8d",
        "0x0fa54b54baa1c3842e86351d76917d79bb454e08a566a303053efabcececdc93",
        "0x1467c0ec282e89a367fbc6a3db46af1678e1a05922376b7cbb509538602e4c87",
        "0x04f202b1307f4eddb2ee02e250299fd04480b53ea643cef6aa3849d3b3838b88"
      ],
      "checks": {
        "valid": true,
        "height": 12345681,
        "population": 21,
        "root": "0x7d8112c4baa8ebf8d97001e18909766f1d4105ab61f2b7941788fa57d63530af",
        "firstId": {
          "address": "0xEea5f4f74391f445D15aFd4294040374F6924B98",
          "pubKey": [
            "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
            "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
          ]
        },
        "lastId": {
          "address": "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b",
          "pubKey": [
            "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
            "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
          ]
        },
        "middleId": {
          "address": "0x5849C6077DbB5722f5717A289A266f9764798199",
          "pubKey": [
            "0x13829176ec03336781ed2da9a48790eb2db7d775672e28bec8a35c01c36ed73a",
            "0x2a23171826ce08db29d9869a81cfe01c445be238704472362a1d4a5c7c90c95b"
          ]
        }
      }
    },
    {
      "comment": "height(12345682): 21 identities -8 +9 by 19 signers(90.48%)",
      "height": 12345682,
      "newIdentities": [
        "0xE50Be1a6Dc1D5768e8537988FDDce562e9B948c9",
        "0xe15A4F0A8b19F53784c19e9BeaC03c875a27dB02",
        "0xDE5eF9F9DCf08dfcbD02B80809398585928a0F7D",
        "0xB68312207F0A3b584C62316492b49753b5D5027C",
        "0x90bafccCbec6177536401D9A2b7F512B54Bfc9D0",
        "0x4c56d0800a8691332088A805BD55c446e25eB075",
        "0x18BbA3E933e5C400CdE5E60c5EaD6FC7AE77ba1D",
        "0x152Dc1aF42eA3d1676c1BDd19AB8e2925c6daEe4",
        "0x10037c4D7Bbb0407D1e2c64981855ad8681d0d86"
      ],
      "newPubKeys": [
        [
          "0x2f527b9debd5d33c012427ddd5cdf64752c98e0afe4c918ead7d60398eb7400c",
          "0x091d6bfa593025b232d5137296feaaaf8ec613575a548c9e3878acb7eb7d9a8d"
        ],
        [
          "0x0ea7b2f5a66945050feff0bcb60b19273e85f2dc5f9f2fe64e066c047a4eb6ab",
          "0x0149cf4359b7eb90686e7984924fa1dda69d963cf4b96fa277e0f9948a9e358e"
        ],
        [
          "0x14be6c54a6ad8a9d2124651c41dee459eb728fbe78156e7c6abde2413e4be08b",
          "0x08a230791dc9f24dce1d38549b217ea926d0a1d4957c7c786170bb0c61bdec00"
        ],
        [
          "0x07aa9642c5dcf542d63103284b04355b8030491a1afe012bd7c3d162aac9a546",
          "0x2b3f5f930a2275e1ac30d0cf0c063075101bf5f86a3266e2c672e45a32ce4271"
        ],
        [
          "0x0def83f7020d7a18927ac01fbd4a15bcd22385683ef52ee1a1d59c0692b2ac3e",
          "0x0e035b7544eb441da769f133b89871240c0cded142795ea5098c9756afd3cea2"
        ],
        [
          "0x1e2863ac1b722f710cc88b6ba02869316dab69f6be25d4430dad6dd1e3e9a9c8",
          "0x04ffc657fe33b23325e18ed17563d8b957e17d28a611ec05ae3fbddeaba75023"
        ],
        [
          "0x0c323f541d0efd35b1aaa24f5451f9f7d1c91cd786db79a79963de39941e2721",
          "0x21b8b85e2fd0561d4d99a8dc15754c88da356157337e36bdeeee918c31ff8ede"
        ],
        [
          "0x2a0c733e870fc0391b2eef7366393cffb9755fa95999a333cae81920d877cd8d",
          "0x261f3e32bde81278a96ab8b60ffa230706efb89419aae3f311c6544d0f34d6e9"
        ],
        [
          "0x26f70e5c56c2810b181dc8526305bb67a218345cf3110e6e40b887bb26abdc36",
          "0x0fc77ab2cf3d60a25f251a72fc003824afdca1cea649e43b22659f02d42763e7"
        ]
      ],
      "removeFlags": "0x035017",
      "removeCount": 8,
      "signFlags": "0xffff16",
      "signature": [
        "0x269fc0fd24e5784751bf6aef9f218d25f9f529c3811af72d1e4992a2313656ef",
        "0x21b388ed074c7709fbbd82f05513a8997d291b1ba046bf03de911a2e565c2ba3"
      ],
      "apk2": [
        "0x218a363a462956cd32b0f5cbd1cf132e62cf64f182e480d4f0d9f3012644b942",
        "0x2119fa8d2a38a9a2e0b8d9069ddb08254961eabfdd2ca46f98cb01902e320b9f",
        "0x0f31725568f94001a402fcc8fc78cb7061d7bfc9b5f1065821ca0ff376cf446f",
        "0x116e9956f781a0f56f5fb8783157d30e4eff690b0be5235ed9f5fcd94b76a1fd"
      ],
      "checks": {
        "valid": true,
        "height": 12345682,
        "population": 22,
        "root": "0xe942aeee63e06981d613bc50c42ec2e8d1216592c361161eb104ee17c11b8cf3",
        "firstId": {
          "address": "0xE50Be1a6Dc1D5768e8537988FDDce562e9B948c9",
          "pubKey": [
            "0x2f527b9debd5d33c012427ddd5cdf64752c98e0afe4c918ead7d60398eb7400c",
            "0x091d6bfa593025b232d5137296feaaaf8ec613575a548c9e3878acb7eb7d9a8d"
          ]
        },
        "lastId": {
          "address": "0x10037c4D7Bbb0407D1e2c64981855ad8681d0d86",
          "pubKey": [
            "0x26f70e5c56c2810b181dc8526305bb67a218345cf3110e6e40b887bb26abdc36",
            "0x0fc77ab2cf3d60a25f251a72fc003824afdca1cea649e43b22659f02d42763e7"
          ]
        },
        "middleId": {
          "address": "0x52FDfc072182654f163F5F0f9A621D729566c74D",
          "pubKey": [
            "0x27048d1d7f25b409930bfc37b0bf663555cefc083dd7004af2b7e5202b0e3b87",
            "0x1a7b7598849e3b4a263648a039ecc55f1b81bf705461a9722be748e3d90a8b1b"
          ]
        }
      }
    },
    {
      "comment": "height(12345683): 22 identities -11 +20 by 22 signers(100.00%)",
      "height": 12345683,
      "newIdentities": [
        "0xEea5f4f74391f445D15aFd4294040374F6924B98",
        "0xe831b10b7Bf5b15c47A53dbf8e7dcaFc9e138647",
        "0xCBf8713f8d962d7C8d019192c24224E2cafCcae3",
        "0xc5e5dE1D2c68192348EC1189FB2e36973cEF09Ff",
        "0xc50e73a32eAF936401e2506Bd8b82C30d346BC4B",
        "0xaaba160Cd640fF73495fe4a05CE1202Ca7287eD3",
        "0xa8F9980630F34ce001c0aB7ac65e502d39b216CB",
        "0xa6a04c5c37c7Ca35036F11732ce8BC27B4886861",
        "0xA4B44ed4bcE964ED47f74AA594468CEd323cb76f",
        "0x9B642221db44A69497B8Ad99408fe1e037C68bF7",
        "0x663138d6d342B051b5df410637cF7aEE9B0C8C10",
        "0x37F9296566557fAb885B039F30e706F0Cd5961e1",
        "0x364cc3DBD968B0F7172ED85794Bb358b0C3b525D",
        "0x2Fa319F245A8657Ec122eAF4ad5425c249Ee160e",
        "0x259B188a4b21c86fbc23d728b45347eadA650af2",
        "0x255aa5B7d44bec40f84C892b9Bffd43629b0223B",
        "0x1FC73c82a491BFABd7a19DF50fdc78A55DbBc2fD",
        "0x14BE23922801F6EaEE41409158b45F2dEC82D17c",
        "0x0Bf5059875921E668A5bDf2c7FC4844592d2572b",
        "0x05ae21F97425254543d94D115900b90Ae703b97D"
      ],
      "newPubKeys": [
        [
          "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
          "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
        ],
        [
          "0x22f0b4966d1f992dae47cf4a27e3011fdc41bf362aa5601f23b16e96c2384dae",
          "0x147f274cbba6b3d024553fbce157ddcd3131fd695a476452e8cd9b2baf9e3c23"
        ],
        [
          "0x0c189e823c6ef04ba34bbd3a6af5f4cb52ef595417f62f04e210b840cb867ff6",
          "0x0769f24ac657f4655b580721f27d4205891800efe9ba4b101b2f8cb7da37433d"
        ],
        [
          "0x093f6f4d9d2875d0a65ae700c35939b5ec99953ecf7342ee107e24e9d046165d",
          "0x1666655a04ede47a7ba45674f3e711f348bb86ac3e94cab6441a4aa72fd38d7e"
        ],
        [
          "0x0e149b04b7c4418be7929783ee75042ebaa03c724b1ae734a7123fb60f4df0be",
          "0x18672eb41b2d9cff94df653d4d7c5fc69628bafcf085d1774afbf408810a97fd"
        ],
        [
          "0x0f966fc71074836c4a151be9aa27d0502190d6ac32e64dfb350be270bb59c1d7",
          "0x27dc25b149253f22c05e5077dcf16b5833d05d2f1f5fcc8ff72f607eba1cc951"
        ],
        [
          "0x1b16b1b1cc23293dab85b9d7380f20ba0f5b75a5d921cb4f092d8865c7bf07d0",
          "0x29b6750fe7126ba402fb51a15a6ddc2bdbb7de7d92eae60201ddffcaa21114d5"
        ],
        [
          "0x17779be8b811d818ef38689d60dfb0148c76ca039b2fc0fde9d7421c8f354342",
          "0x2f363a50b41fc3484081d08c8fccad4b32f0020e05b3221cf2b2b1c60f962734"
        ],
        [
          "0x2eeac016eddf27b96037063dcd50cb28661abef05a2d589b652403e4dec9a7aa",
          "0x27dcd024e85f58b7f2bdd3bd693fc5be28b45cf5296e5668c05367964ee981c8"
        ],
        [
          "0x1d72f0fcb3b4f47573c2c894e5be0f1157eabba313dfa05f5aa4af5b75d16916",
          "0x2e0069bc9b4d7d97e6a119b1532fa953f466aa0577fa23b22e7ad93d9227ee49"
        ],
        [
          "0x1e666d2114f921257eecb0e5da1254aa38b368502a000dddca0b0c819a6b326e",
          "0x042d5be3d6bfb9c19ca8d8478cd403b594f4505a6ff63f7540af9e4ab2755da7"
        ],
        [
          "0x0a64d9f67f43ed916eb8d424f87e99c683a2010f303ffdfe03c2f173065665ec",
          "0x218c3f17a9590553d4db18dcd8263b149268a2c49ea3ecb5f919f3bcd18dacbf"
        ],
        [
          "0x1e28f93bd6bcfe3b4b45f6b40f2cb3d3fac1825b45a3ccfb62303badb8220024",
          "0x0392b560864052071111ea630cb07708fcfcdcf12786e53ef50123df57d6f909"
        ],
        [
          "0x0c1a82155b62b51b06cd2c563f89e6e4bc945cd75841b97e99e6b00a05f125f1",
          "0x232cd6e7dd175cbba42da4a6c7fe98549d2c6802116abf3e665175da4a86ff6b"
        ],
        [
          "0x16a76f0f34cb8d335d05416dfb9779e938a524f4f699fb1413185de803260f6b",
          "0x0e6902b06034f75831e4a2f7781ac597b94ef0789b64202972c1b73ba6b33f61"
        ],
        [
          "0x28235790313e0ad4dbeb1305fc9b513c1b4f63ea6db8b627b421c11ced9a9759",
          "0x001db993024b9ffa3d4b1a1fcae26d70c7265048fc2929d85ebf73d3267b1744"
        ],
        [
          "0x1187176e79873b48a3f33c3756d6e1e5e7726ca82efd45333de1da21496c2acb",
          "0x0dd617c01feea4239d618e2f331ce0809eb46df0fb8dd1fd74c5682e7473c992"
        ],
        [
          "0x0ad5a7aa45a9b16a6096bf95a1113e32bf1a0131b4ff3b78554f3d7046a0d99d",
          "0x10298e1ae197327a194aadef35c94b327e5f94397a2c391e09d22c9870a71270"
        ],
        [
          "0x28dca196287685eb83a4316939574acd62c7ce1c40b36ae303ff0d2edaa3b12c",
          "0x15afd1f0af5ecaf33f81fed94c16929a068b0ab3480f6686a03fc56f5d3a2037"
        ],
        [
          "0x1471580e28163344af0a8ae767c99bbfbb9bd13b748066729a06865fc4670481",
          "0x2b5190205cdcf7f9245577947d479b007862c7d4163c03e4c320e741fda4d6c2"
        ]
      ],
      "removeFlags": "0x132d2b",
      "removeCount": 11,
      "signFlags": "0xffff3f",
      "signature": [
        "0x289c83c967011f7cdeb315d1d29f94fb7c301efdaf65691323a0dc00c36b4a33",
        "0x2a986eb37287a0dcc4bc56fdbea365e22cd17943a6e15a2938820148d4d8bbf5"
      ],
      "apk2": [
        "0x1d5139348335257376a8e7fa05cdac29ae5158f4257b07d5a81e15ea536c361e",
        "0x0d882eaf39649db28855cf3fd59c819b503f3980e70d2555f01dc3cba0b14741",
        "0x2e90f764fbb387352388232f6659869c22cd87a4019d12e20f5b115c1190a982",
        "0x25740a2a6983e5bb884808ada1be9fd69a19a2b67db26169349b50413651dada"
      ],
      "checks": {
        "valid": true,
        "height": 12345683,
        "population": 31,
        "root": "0x4086a8633f02ef9656539e40a24df4bf5e8f2b1ecc5063950748460b7a8447ac",
        "firstId": {
          "address": "0xEea5f4f74391f445D15aFd4294040374F6924B98",
          "pubKey": [
            "0x23a974b2cccec1793a77694dd6e93a8960788102a1e5660f8ce6814dce145913",
            "0x02412af5522359fd57b045b4a36f5e45836e94b0edf4541775b5d07de7bced12"
          ]
        },
        "lastId": {
          "address": "0x05ae21F97425254543d94D115900b90Ae703b97D",
          "pubKey": [
            "0x1471580e28163344af0a8ae767c99bbfbb9bd13b748066729a06865fc4670481",
            "0x2b5190205cdcf7f9245577947d479b007862c7d4163c03e4c320e741fda4d6c2"
          ]
        },
        "middleId": {
          "address": "0x21119c160F0702448615bBDA08313f6A8Eb668D2",
          "pubKey": [
            "0x02ef9862a2904c5ace3c8f1d6700eb90829ff0ba6d865a036a8b2669228cc683",
            "0x035c5f146b963acd3a167995e7d5b9a85dbf633b437061b798e2ec5563fc075f"
          ]
        }
      }
    }
  ]
}
`
