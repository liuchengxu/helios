use alloy::primitives::B256;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::{Bootstrap, FinalityUpdate, Forks, LightClientStore};
use helios_consensus_core::{apply_bootstrap, verify_bootstrap, verify_finality_update};
use serde_json::Value;

#[test]
fn verifies_captured_kurtosis_gloas_update_and_rejects_wrong_genesis() {
    let bootstrap: Value =
        serde_json::from_str(include_str!("../testdata/gloas-captured/bootstrap.json")).unwrap();
    let finality: Value =
        serde_json::from_str(include_str!("../testdata/gloas-captured/finality.json")).unwrap();
    let genesis: Value =
        serde_json::from_str(include_str!("../testdata/gloas-captured/genesis.json")).unwrap();
    let config: Value =
        serde_json::from_str(include_str!("../testdata/gloas-captured/config.json")).unwrap();
    let bootstrap: Bootstrap<MainnetConsensusSpec> =
        serde_json::from_value(bootstrap["data"].clone()).unwrap();
    let update: FinalityUpdate<MainnetConsensusSpec> =
        serde_json::from_value(finality["data"].clone()).unwrap();
    let current_slot: u64 = finality["data"]["signature_slot"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let genesis_root: B256 = genesis["data"]["genesis_validators_root"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let checkpoint: B256 = include_str!("../testdata/gloas-captured/anchor.txt")
        .trim()
        .parse()
        .unwrap();
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
        fork.epoch = config["data"][format!("{name}_FORK_EPOCH")]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap();
        fork.fork_version = config["data"][format!("{name}_FORK_VERSION")]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
    }
    verify_bootstrap(&bootstrap, checkpoint, &forks).unwrap();
    let mut store = LightClientStore::default();
    apply_bootstrap(&mut store, &bootstrap);
    verify_finality_update(&update, current_slot, &store, genesis_root, &forks).unwrap();
    assert!(verify_finality_update(&update, current_slot, &store, B256::ZERO, &forks).is_err());
}
