// Golden vectors for `mesh/capability` — generated from fixed seeds by
// the fluxor harness test `mesh_capability`; do not edit by hand.
//
// Each vector is a chain (hex), the demand it is checked against, the
// clock, and the verdict: `expect` 0 is granted, anything else is the
// `Refusal` byte. Verify every vector with `ROOT_KEY` as the only root.
// A consumer that links the contract runs these to prove it wired the
// verifier the way the contract means.

/// Seed of the root key the vectors are signed under.
pub const ROOT_SEED: [u8; 32] = [0x11; 32];
/// The root public key: the one root every vector is verified with.
pub const ROOT_KEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
/// The object every vector's grant names.
pub const OBJECT: [u8; 16] = [0x0b; 16];
/// Unix seconds every vector's clock reads.
pub const CLOCK_NOW: u64 = 1800000000;

/// One vector.
pub struct Vector {
    pub name: &'static str,
    pub chain: &'static str,
    pub demand_object: [u8; 16],
    pub demand_permissions: u16,
    /// `(now, uncertainty)`; `None` is no trusted clock.
    pub clock: Option<(u64, u64)>,
    pub expect: u8,
}

pub const VECTORS: &[Vector] = &[
    Vector {
        name: "root_signed_leaf",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000300006b49c3f06b49e01010ba682cac92e7486c1542d39991b61fae796499600037babf1b45b0cd65882d97fbf2986cd2fe9ef00b09d72da056e870ba80fe99f0131d2d7ca0d04d2114a3cb8c2a04d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 0,
    },
    Vector {
        name: "one_delegation",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e0101325b8507a78f16b0ad4c978b3bac5129256b56217dbe69025a24faedfc98d576f16644f953c8f33b4893c7c73ebc5dedfb27dcaa64ec91f97c6e471eacd421621507502a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898002500006b49b5e06b49ee2010ba682c999b3757ca5fd2919f1cad61ea80e7fcab885b1c4f64a460e3e8418bbb670ef0b332a1b91964b6ae35ea0932661ab3c227892f0d1bc47c3e63a997b5c582cf09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 0,
    },
    Vector {
        name: "two_delegations",
        chain: "00030b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000400006b49cfa86b49d4586c8f86074ad779a8bd540792048868c326c3c6f56f5b619d5a0dfd82fa03fb38f51f1d754ac45ef8c79b4c9998fcd1f24f8efcdca0fedadac63db0e73db314b810b8ac0017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce6c8f8607dbe87077a62a2990ce07d94a002500006b49c3f06b49e0101325b850ce484316f79d88708dde373beae6f623d7434e8fc13f49d995bbc2884d0341eca1c071a9af52d795edd7d5f180725ed0eeb9113bad8119368b9d1f0b401df007a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898003500006b49b5e06b49ee2010ba682c2c16d5a9a2a3443a7406932d91eadd511ac4416e24b77c2ff7ac261d44ee9f943ab5c6c8057d1581ce35e45597bc399a861b27fc4df48e21970e7d81f1fe0409d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0004,
        clock: Some((1800000000, 0)),
        expect: 0,
    },
    Vector {
        name: "within_uncertainty",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49d19c6b49d26410ba682c27d18cd53815f63384fb989d5342106e39cc999d26c7a8cb5c039304dff2804740ca00d5d59facdc9df670b523c14b5822e3aeaedfb589eee108b2100e533e0ed04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 99)),
        expect: 0,
    },
    Vector {
        name: "truncated",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 1,
    },
    Vector {
        name: "zero_links",
        chain: "0000",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 1,
    },
    Vector {
        name: "too_long",
        chain: "00090b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 2,
    },
    Vector {
        name: "reserved_flag",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100016b49c3f06b49e01010ba682cfa99ae9299925abe78df05cc9e3b41e96da4abe8f2be8a5f9e62c7ee649a3bd5ef6dc781018f35cee665b5c44d251ac439acea11d7773e93b3be690b72e0ef01d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 3,
    },
    Vector {
        name: "reserved_permission",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b004100006b49c3f06b49e01010ba682c8a63a946b3bbcb611882ee73beb0fa7d56f2d3ae24862acb4962e7323941d7fdfca07119cc0feff41f4ceb000334b23ce5b230dc426eaefa9dcf148607e23b09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 3,
    },
    Vector {
        name: "inverted_window",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49e0106b49c3f010ba682c8a26f30a0d93e69d07e223705363be84f0803dcd2bc7ebf688bb09bfe93943cb046ef02d46a38a96f6d61d7082f535bd6d3fe5b95ec04229ff377aa060a9f408d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 4,
    },
    Vector {
        name: "key_id_mismatch",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01011ba682ca41b9831970263ad987d2af4804ef0070c75305c7982d03acb6c3af275eaa9b4178a4c0068e4a8ab05d187e309f00bbb1e1926c04a18da4cc4b6a9e7a7e6c70bd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 5,
    },
    Vector {
        name: "unknown_root",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e010b1470588cf81bacd5f9146ce9f064aace0ef41fe7da0151dd911afec1828e1daa57954e33c92a35ffff7d91723cde3a028a495060a23dee0b2368ae085356a839c4dd40ad759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 6,
    },
    Vector {
        name: "key_binding",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e0101325b8507a78f16b0ad4c978b3bac5129256b56217dbe69025a24faedfc98d576f16644f953c8f33b4893c7c73ebc5dedfb27dcaa64ec91f97c6e471eacd421621507502a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f06c8f8607dbe87077a62a2990ce07d94a002500006b49b5e06b49ee2010ba682c5cda07cf4ca8855054f5575db92aa3f8f86d582be294a4e264a2ea5c18abbbccdd8e0f2829ff3f03623ce22c66074b48a67e3e468903cbeff0f19cf163227304d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 7,
    },
    Vector {
        name: "not_delegable",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e0101325b8507a78f16b0ad4c978b3bac5129256b56217dbe69025a24faedfc98d576f16644f953c8f33b4893c7c73ebc5dedfb27dcaa64ec91f97c6e471eacd421621507502a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898000500006b49b5e06b49ee2010ba682c36a7ef973646d60cebc764c7c58b3d871ed26418c4f8d880573dee574da913ab459c2d6680cf53402de3435c8b8616dfded51de72120ea3f2f922104c6f85208d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 8,
    },
    Vector {
        name: "permission_widened",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b001100006b49c3f06b49e0101325b8504654364571326d6bac5a1c93cf7455630a87f477d95a52aea421c1711c280b722323a5a494542342c321642c89341e11a2dd13558fb1ef96bc7640356212bb03a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898002500006b49b5e06b49ee2010ba682c999b3757ca5fd2919f1cad61ea80e7fcab885b1c4f64a460e3e8418bbb670ef0b332a1b91964b6ae35ea0932661ab3c227892f0d1bc47c3e63a997b5c582cf09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 9,
    },
    Vector {
        name: "window_widened",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49f5281325b8508a3e64761c484de54209ecc1d6134435529cc336bbc51bf97e54b7e509315be9cefe75ee49259544e64ea92e31e3616b122af75bf6f7168311d3fbba8432800ea09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898002500006b49b5e06b49ee2010ba682c999b3757ca5fd2919f1cad61ea80e7fcab885b1c4f64a460e3e8418bbb670ef0b332a1b91964b6ae35ea0932661ab3c227892f0d1bc47c3e63a997b5c582cf09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 10,
    },
    Vector {
        name: "leaf_signature",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf2e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 11,
    },
    Vector {
        name: "undomained_signature",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c4a490418298a01ba5c051a29339237ab8b6951fff6784c4c13d5966c12849821803a204eab90363b0b68f63df67a637459a9291a037163eb428b751059460900d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 11,
    },
    Vector {
        name: "trailing_byte",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873700",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 1,
    },
    Vector {
        name: "delegation_signature",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e0101325b8507a78f16b0ad4c978b3bac5129256b56217dbe69025a24faedfc98d576f16644f953c8f33b4893c7c73ebc5dedfb27dcaa64ec91f97c6e471eacd421621507502a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898002500006b49b5e06b49ee2010ba682c999b3757ca5fd2919f1cad61ea80e7fcab885b1c4f64a460e3e8418bbb670ef0b332a1b91964b6ae35ea0932661ab3c227892f0d1bc47c3e63a996b5c582cf09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 11,
    },
    Vector {
        name: "no_trusted_clock",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: None,
        expect: 12,
    },
    Vector {
        name: "not_yet_valid",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49d23c6b49e01010ba682cab60ff9f89e1c952252fb3fee7124fa2b66c5bfa3d8bc464480e47ccabd5fe2af642d1399682c4ea24d934a255fedc05d92d88b48307ef58fd8db885c3f5de09d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 13,
    },
    Vector {
        name: "expired",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49d1c410ba682c0ac5dc222de4db0f22ddc7aec967c10530ef29b2a8ecdf97c6111ea6481ed687d928449e73dd89cc6bd8ba5c582a29ccfa3dab1b40350da0cd7da914c5064606d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 14,
    },
    Vector {
        name: "uncertainty_spent",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49d1f66b49e01010ba682c64d80dcfeee27bd096a9163d1ef8c16a1ae1ef4cd42c75881f455f610e85ef33bbbe76b1a1f2d8fb43ee7e727f656358efd0a6a17e895148a2a7753b6f2f2e05d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 30)),
        expect: 13,
    },
    Vector {
        name: "chain_expired",
        chain: "00020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49d1881325b850b5d8ade09e273586c4c65e3646d07a52a6c04266e43f75ab980fe358fef36f2b9b06beeb6ab9bf7f8982a926c7aad13797060e9280836d06aaf31be6a823400ca09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f01325b850c2871916eae203f0efc3c898002500006b49b5e06b49d1c410ba682c458331d17888b6bd792d2a299a4f0d66ac6ce2eede186a5af9a94f2539cde2988b884fe190784987b0baf07f841e8803047ebf746f4b2acd76d314a974c0ee07d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 14,
    },
    Vector {
        name: "object_mismatch",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0xee; 16],
        demand_permissions: 0x0001,
        clock: Some((1800000000, 0)),
        expect: 15,
    },
    Vector {
        name: "permission_denied",
        chain: "00010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000100006b49c3f06b49e01010ba682c5e0f8227980a641bf3e10ab0b89ff14bfe67570bc05f6745babada7d1128889e82c729d177e123564b3cdad36a335b16e3ee33c09f4d4aeac512eb68dc05b904d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        demand_object: [0x0b; 16],
        demand_permissions: 0x0004,
        clock: Some((1800000000, 0)),
        expect: 16,
    },
];
