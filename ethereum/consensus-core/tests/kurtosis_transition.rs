use alloy::primitives::B256;
use helios_consensus_core::consensus_spec::{ConsensusSpec, MainnetConsensusSpec};
use helios_consensus_core::errors::ConsensusError;
use helios_consensus_core::types::{Bootstrap, FinalityUpdate, Forks, LightClientStore};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, verify_bootstrap, verify_finality_update,
};
use serde_json::Value;

/// `C0` anchor block root (slot 64) the captured bootstrap is checked against.
const ANCHOR: &str = include_str!("../testdata/fulu-gloas-transition/anchor.txt");
/// Captured `light_client/bootstrap` response for `C0`, still in the Fulu wire format.
const BOOTSTRAP: &str = include_str!("../testdata/fulu-gloas-transition/bootstrap.json");
/// Captured `config/spec` response: `FULU_FORK_EPOCH = 0`, `GLOAS_FORK_EPOCH = 8`.
const CONFIG: &str = include_str!("../testdata/fulu-gloas-transition/config.json");
const GENESIS: &str = include_str!("../testdata/fulu-gloas-transition/genesis.json");
/// `light_client/finality_update` signed at slot 225: finalizes slot 160, Fulu shape.
const PRE_FINALITY: &str = include_str!("../testdata/fulu-gloas-transition/pre-finality.json");
/// `light_client/finality_update` signed at slot 257: finalizes slot 192, Gloas shape.
const POST_FINALITY: &str = include_str!("../testdata/fulu-gloas-transition/post-finality.json");

/// The captured Fulu to Gloas transition of one Kurtosis chain, as beacon API responses.
struct Fixtures {
    bootstrap: Bootstrap<MainnetConsensusSpec>,
    pre_finality: FinalityUpdate<MainnetConsensusSpec>,
    post_finality: FinalityUpdate<MainnetConsensusSpec>,
    genesis_root: B256,
    checkpoint: B256,
    forks: Forks,
}

/// Unwraps the `data` envelope of a captured beacon node API response.
fn data(document: &str) -> Value {
    serde_json::from_str::<Value>(document).unwrap()["data"].clone()
}

/// True when the public API reported the typed BLS signature failure.
fn is_invalid_signature<T: std::fmt::Debug>(result: Result<T, eyre::Report>) -> bool {
    let error = result.unwrap_err();
    let typed = error.downcast_ref::<ConsensusError>();

    matches!(typed, Some(ConsensusError::InvalidSignature))
}

impl Fixtures {
    fn load() -> Self {
        let config = data(CONFIG);
        let mut forks = Forks::default();
        for (name, fork) in [
            ("GENESIS", &mut forks.genesis),
            ("ALTAIR", &mut forks.altair),
            ("BELLATRIX", &mut forks.bellatrix),
            ("CAPELLA", &mut forks.capella),
            ("DENEB", &mut forks.deneb),
            ("ELECTRA", &mut forks.electra),
            ("FULU", &mut forks.fulu),
            ("GLOAS", &mut forks.gloas),
        ] {
            let epoch = config[format!("{name}_FORK_EPOCH")].as_str().unwrap_or("0");
            let version = config[format!("{name}_FORK_VERSION")].as_str().unwrap();
            fork.epoch = epoch.parse().unwrap();
            fork.fork_version = version.parse().unwrap();
        }

        let genesis = data(GENESIS);
        let root = genesis["genesis_validators_root"].as_str().unwrap();

        Self {
            bootstrap: serde_json::from_value(data(BOOTSTRAP)).unwrap(),
            pre_finality: serde_json::from_value(data(PRE_FINALITY)).unwrap(),
            post_finality: serde_json::from_value(data(POST_FINALITY)).unwrap(),
            genesis_root: root.parse().unwrap(),
            checkpoint: ANCHOR.trim().parse().unwrap(),
            forks,
        }
    }
}

#[test]
fn verifies_and_applies_the_captured_fulu_to_gloas_transition() {
    let fixtures = Fixtures::load();
    let genesis_root = fixtures.genesis_root;
    let forks = &fixtures.forks;
    let pre_update = &fixtures.pre_finality;
    let post_update = &fixtures.post_finality;
    let pre_signature_slot = *pre_update.signature_slot();
    let post_signature_slot = *post_update.signature_slot();

    verify_bootstrap(&fixtures.bootstrap, fixtures.checkpoint, forks).unwrap();

    // `C0` is the Fulu anchor; both updates below advance finality strictly past it.
    let mut store = LightClientStore::default();
    apply_bootstrap(&mut store, &fixtures.bootstrap);
    assert_eq!(store.finalized_header.beacon().slot, 64);

    verify_finality_update(pre_update, pre_signature_slot, &store, genesis_root, forks).unwrap();
    assert!(apply_finality_update(&mut store, pre_update).is_some());
    assert_eq!(store.finalized_header.beacon().slot, 160);

    verify_finality_update(
        post_update,
        post_signature_slot,
        &store,
        genesis_root,
        forks,
    )
    .unwrap();
    assert!(apply_finality_update(&mut store, post_update).is_some());
    assert_eq!(store.finalized_header.beacon().slot, 192);

    let gloas_slot = forks.gloas.epoch * MainnetConsensusSpec::slots_per_epoch();
    assert_eq!(forks.gloas.epoch, 8);

    assert!(pre_update.finalized_header().beacon().slot < gloas_slot);
    assert!(pre_update.finalized_header().execution().is_ok());

    // The post-fork update attests at Gloas epoch 8 but still finalizes a Fulu slot, so
    // it verifies only through the upgraded header representation, the normalized
    // branches it carries, and the Gloas signing domain.
    assert!(post_update.attested_header().beacon().slot >= gloas_slot);
    assert!(post_update.attested_header().execution_block_hash().is_ok());
    assert!(post_update.finalized_header().beacon().slot < gloas_slot);
    assert!(post_update
        .finalized_header()
        .execution_block_hash()
        .is_ok());
}

#[test]
fn rejects_the_post_fork_update_with_the_wrong_gloas_domain_or_genesis() {
    let fixtures = Fixtures::load();
    let genesis_root = fixtures.genesis_root;
    let pre_update = &fixtures.pre_finality;
    let post_update = &fixtures.post_finality;
    let pre_signature_slot = *pre_update.signature_slot();
    let post_signature_slot = *post_update.signature_slot();

    let mut forks = fixtures.forks.clone();
    forks.gloas.fork_version = "0x80000039".parse().unwrap();
    assert_eq!(forks.gloas.epoch, fixtures.forks.gloas.epoch);

    let mut store = LightClientStore::default();
    apply_bootstrap(&mut store, &fixtures.bootstrap);
    assert!(apply_finality_update(&mut store, pre_update).is_some());

    // Only the Gloas fork version moved, so the Fulu-domain update still verifies.
    verify_finality_update(pre_update, pre_signature_slot, &store, genesis_root, &forks).unwrap();

    let wrong_domain = verify_finality_update(
        post_update,
        post_signature_slot,
        &store,
        genesis_root,
        &forks,
    );
    assert!(is_invalid_signature(wrong_domain));

    let wrong_genesis = verify_finality_update(
        post_update,
        post_signature_slot,
        &store,
        B256::ZERO,
        &fixtures.forks,
    );
    assert!(is_invalid_signature(wrong_genesis));
}
