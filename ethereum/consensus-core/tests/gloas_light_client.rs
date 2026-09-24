//! Gloas:EIP7732 light client wire shape and header validation.
//!
//! The pinned spec (consensus-specs `756f49c`) ships no runtime Gloas light client
//! vector in this repository, so the fixtures below are derived from the spec's
//! generalized indices and the consensus branch fold. They pin the wire shape, the
//! fork-selected indices, the strict header validation, and the pre-fork upgrade shape
//! the fork document produces (`UpgradedBootstrap`). They are not a substitute for a
//! fixture captured from a live Gloas client.

use alloy::primitives::{fixed_bytes, B256};
use helios_consensus_core::consensus_spec::{ConsensusSpec, MinimalConsensusSpec};
use helios_consensus_core::errors::ConsensusError;
use helios_consensus_core::types::{
    Bootstrap, FinalityUpdate, Fork, Forks, LightClientHeader, SyncCommittee, Update,
};
use helios_consensus_core::{get_lc_execution_root, verify_bootstrap};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

/// `EXECUTION_BLOCK_HASH_GINDEX_GLOAS` from the pinned sync protocol.
const EXECUTION_GINDEX: usize = 2_856;
/// `CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS` from the pinned sync protocol.
const COMMITTEE_GINDEX: usize = 2_945;
/// `CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA`, the pre-Gloas committee index.
const ELECTRA_COMMITTEE_GINDEX: usize = 86;
/// `EXECUTION_BLOCK_HASH_GINDEX_DENEB`, the pre-Gloas execution index at Deneb and Fulu.
const DENEB_EXECUTION_GINDEX: usize = 812;
/// `get_generalized_index(deneb.ExecutionPayloadHeader, 'block_hash')`.
const DENEB_PAYLOAD_BLOCK_HASH_GINDEX: usize = 44;
/// `EXECUTION_PAYLOAD_GINDEX`, `get_generalized_index(capella.BeaconBlockBody,
/// 'execution_payload')`.
const EXECUTION_PAYLOAD_GINDEX: usize = 25;

/// Independent re-implementation of the consensus branch fold, used to build
/// self-consistent fixtures.
fn fold(leaf: B256, branch: &[B256], gindex: usize) -> B256 {
    let mut index = gindex;
    let mut node = leaf;
    for sibling in branch {
        node = if index & 1 == 0 {
            hash_pair(node, *sibling)
        } else {
            hash_pair(*sibling, node)
        };
        index >>= 1;
    }
    node
}

fn hash_pair(left: B256, right: B256) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    B256::from_slice(hasher.finalize().as_slice())
}

fn hex(value: B256) -> String {
    format!("{value:#x}")
}

fn zero_hex(bytes: usize) -> String {
    format!("0x{}", "00".repeat(bytes))
}

fn hexes(nodes: &[B256]) -> Value {
    Value::Array(nodes.iter().map(|node| Value::String(hex(*node))).collect())
}

/// A non-zero node that no fixture branch contains.
fn bad_node() -> Value {
    Value::String(hex(B256::with_last_byte(0xfe)))
}

/// Eleven distinct non-zero branch nodes.
fn eleven_nodes(offset: u8) -> Vec<B256> {
    (0..11u8)
        .map(|i| B256::with_last_byte(offset + i + 1))
        .collect()
}

/// `count` distinct non-zero branch nodes.
fn nodes(offset: u8, count: usize) -> Vec<B256> {
    (0..count as u8)
        .map(|i| B256::with_last_byte(offset + i + 1))
        .collect()
}

fn test_forks(gloas_epoch: u64) -> Forks {
    Forks {
        genesis: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("00000001"),
        },
        altair: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("01000001"),
        },
        bellatrix: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("02000001"),
        },
        capella: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("03000001"),
        },
        deneb: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("04000001"),
        },
        electra: Fork {
            epoch: 2,
            fork_version: fixed_bytes!("05000001"),
        },
        fulu: Fork {
            epoch: 3,
            fork_version: fixed_bytes!("06000001"),
        },
        gloas: Fork {
            epoch: gloas_epoch,
            fork_version: fixed_bytes!("07000001"),
        },
    }
}

fn gloas_slot(forks: &Forks) -> u64 {
    forks.gloas.epoch * MinimalConsensusSpec::slots_per_epoch()
}

fn sync_committee_json() -> Value {
    let size = MinimalConsensusSpec::sync_committee_size() as usize;
    json!({
        "pubkeys": vec![zero_hex(48); size],
        "aggregate_pubkey": zero_hex(48),
    })
}

fn sync_committee_root() -> B256 {
    let committee: SyncCommittee<MinimalConsensusSpec> =
        serde_json::from_value(sync_committee_json()).unwrap();
    committee.tree_hash_root()
}

fn sync_aggregate_json() -> Value {
    json!({
        "sync_committee_bits": "0x00000000",
        "sync_committee_signature": zero_hex(96),
    })
}

fn beacon_header_json(slot: u64, state_root: B256, body_root: B256) -> Value {
    json!({
        "slot": slot.to_string(),
        "proposer_index": "0",
        "parent_root": hex(B256::ZERO),
        "state_root": hex(state_root),
        "body_root": hex(body_root),
    })
}

fn gloas_header_json(
    slot: u64,
    state_root: B256,
    body_root: B256,
    execution_block_hash: B256,
    execution_branch: &[B256],
) -> Value {
    json!({
        "beacon": beacon_header_json(slot, state_root, body_root),
        "execution_block_hash": hex(execution_block_hash),
        "execution_branch": hexes(execution_branch),
    })
}

/// A pre-Gloas header: beacon + execution payload header + 4-node branch.
fn pre_gloas_header_json(slot: u64, execution_branch: &[B256]) -> Value {
    json!({
        "beacon": beacon_header_json(slot, B256::ZERO, B256::ZERO),
        "execution": {
            "parent_hash": hex(B256::ZERO),
            "fee_recipient": zero_hex(20),
            "state_root": hex(B256::ZERO),
            "receipts_root": hex(B256::ZERO),
            "logs_bloom": zero_hex(256),
            "prev_randao": hex(B256::ZERO),
            "block_number": "0",
            "gas_limit": "0",
            "gas_used": "0",
            "timestamp": "0",
            "extra_data": "0x00",
            "base_fee_per_gas": "0",
            "block_hash": hex(B256::ZERO),
            "transactions_root": hex(B256::ZERO),
            "withdrawals_root": hex(B256::ZERO),
            "blob_gas_used": "0",
            "excess_blob_gas": "0"
        },
        "execution_branch": hexes(execution_branch)
    })
}

/// A self-consistent Gloas bootstrap: the committee branch proves the committee
/// into `state_root` at `CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS`, and the execution
/// branch proves `execution_block_hash` into `body_root`.
struct GloasBootstrap {
    header: Value,
    committee: Value,
    committee_branch: Vec<B256>,
}

impl GloasBootstrap {
    fn valid(forks: &Forks) -> Self {
        let committee_branch = eleven_nodes(0x10);
        let state_root = fold(sync_committee_root(), &committee_branch, COMMITTEE_GINDEX);

        let execution_block_hash = B256::with_last_byte(0xaa);
        let execution_branch = eleven_nodes(0x30);
        let body_root = fold(execution_block_hash, &execution_branch, EXECUTION_GINDEX);

        let header = gloas_header_json(
            gloas_slot(forks),
            state_root,
            body_root,
            execution_block_hash,
            &execution_branch,
        );

        Self {
            header,
            committee: sync_committee_json(),
            committee_branch,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "header": self.header.clone(),
            "current_sync_committee": self.committee.clone(),
            "current_sync_committee_branch": hexes(&self.committee_branch),
        })
    }
}

/// A Gloas-format bootstrap whose header was upgraded from Fulu. Both branches are the
/// normalized upgrade of the Electra shapes: the proof is kept and the front is padded
/// with zeros up to the Gloas branch length.
struct UpgradedBootstrap {
    header: Value,
    committee: Value,
    committee_branch: Vec<B256>,
    payload_root: B256,
}

impl UpgradedBootstrap {
    fn valid(forks: &Forks) -> Self {
        // `current_sync_committee`: an Electra proof (gindex 86, depth 6) padded with five
        // zero nodes to the 11-node Gloas branch.
        let committee_proof = nodes(0x10, 6);
        let state_root = fold(
            sync_committee_root(),
            &committee_proof,
            ELECTRA_COMMITTEE_GINDEX,
        );
        let mut committee_branch = vec![B256::ZERO; 11 - committee_proof.len()];
        committee_branch.extend(committee_proof);

        // Execution block hash: block hash -> payload header (gindex 44, depth 5), then
        // payload header -> body (gindex 25, depth 4), padded with two zero nodes.
        let execution_block_hash = B256::with_last_byte(0xaa);
        let payload_proof = nodes(0x40, 5);
        let payload_root = fold(
            execution_block_hash,
            &payload_proof,
            DENEB_PAYLOAD_BLOCK_HASH_GINDEX,
        );
        let body_proof = nodes(0x60, 4);
        let body_root = fold(payload_root, &body_proof, EXECUTION_PAYLOAD_GINDEX);
        let mut execution_branch = vec![B256::ZERO; 11 - payload_proof.len() - body_proof.len()];
        execution_branch.extend(payload_proof);
        execution_branch.extend(body_proof);

        let header = gloas_header_json(
            forks.fulu.epoch * MinimalConsensusSpec::slots_per_epoch(),
            state_root,
            body_root,
            execution_block_hash,
            &execution_branch,
        );

        Self {
            header,
            committee: sync_committee_json(),
            committee_branch,
            payload_root,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "header": self.header.clone(),
            "current_sync_committee": self.committee.clone(),
            "current_sync_committee_branch": hexes(&self.committee_branch),
        })
    }
}

fn parse_bootstrap(value: Value) -> Bootstrap<MinimalConsensusSpec> {
    serde_json::from_value(value).expect("bootstrap must decode")
}

fn expect_consensus_error(result: Result<(), eyre::Report>, expected: ConsensusError) {
    let error = result.expect_err("verification must fail");
    let actual = error.downcast_ref::<ConsensusError>().unwrap();

    assert_eq!(
        std::mem::discriminant(actual),
        std::mem::discriminant(&expected),
        "unexpected consensus error: {actual}"
    );
}

#[test]
fn gloas_bootstrap_verifies_with_the_pinned_gindices() {
    let forks = test_forks(4);
    let fixture = GloasBootstrap::valid(&forks);
    let bootstrap = parse_bootstrap(fixture.to_json());

    assert!(matches!(&bootstrap, Bootstrap::Gloas(_)));
    assert_eq!(bootstrap.current_sync_committee_branch().len(), 11);

    let header = bootstrap.header();
    assert_eq!(header.execution_branch_gloas().unwrap().len(), 11);
    assert!(header.execution().is_err());
    assert!(header.execution_block_hash().is_ok());

    let checkpoint = header.beacon().tree_hash_root();
    verify_bootstrap(&bootstrap, checkpoint, &forks).expect("gloas bootstrap must verify");
}

#[test]
fn gloas_bootstrap_rejects_a_malformed_execution_branch() {
    let forks = test_forks(4);

    let mut fixture = GloasBootstrap::valid(&forks);
    fixture.header["execution_branch"][0] = bad_node();
    let bootstrap = parse_bootstrap(fixture.to_json());
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidExecutionPayloadProof,
    );

    // A wrong execution block hash cannot be proven into the same body root.
    let mut fixture = GloasBootstrap::valid(&forks);
    fixture.header["execution_block_hash"] = bad_node();
    let bootstrap = parse_bootstrap(fixture.to_json());
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidExecutionPayloadProof,
    );
}

#[test]
fn gloas_bootstrap_rejects_a_malformed_committee_branch() {
    let forks = test_forks(4);

    let mut fixture = GloasBootstrap::valid(&forks);
    fixture.committee_branch[0] = B256::with_last_byte(0xfe);
    let bootstrap = parse_bootstrap(fixture.to_json());
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidCurrentSyncCommitteeProof,
    );
}

#[test]
fn gloas_bootstrap_accepts_an_upgraded_pre_fork_header() {
    let forks = test_forks(4);
    let fixture = UpgradedBootstrap::valid(&forks);
    let payload_root = fixture.payload_root;
    let bootstrap = parse_bootstrap(fixture.to_json());

    assert!(matches!(&bootstrap, Bootstrap::Gloas(_)));
    let header = bootstrap.header();
    assert_eq!(
        header.beacon().slot,
        forks.fulu.epoch * MinimalConsensusSpec::slots_per_epoch()
    );
    assert_eq!(bootstrap.current_sync_committee_branch().len(), 11);

    // The Gloas-format header and the Gloas-length committee branch must both stay
    // valid for the pre-Gloas slot they were upgraded from.
    let checkpoint = header.beacon().tree_hash_root();
    verify_bootstrap(&bootstrap, checkpoint, &forks)
        .expect("an upgraded pre-fork bootstrap must verify");

    // The execution payload header root is recovered from the normalized branch.
    assert_eq!(
        get_lc_execution_root::<MinimalConsensusSpec>(header, &forks),
        payload_root
    );
}

#[test]
fn gloas_bootstrap_rejects_an_unpadded_pre_fork_header() {
    let forks = test_forks(4);

    // The Gloas-gindex (2856) branch of this fixture cannot prove a pre-Gloas slot: the
    // first two nodes are not the zero padding the Electra->Gloas upgrade writes, so the
    // slot's own gindex (812) rejects it.
    let mut fixture = GloasBootstrap::valid(&forks);
    let slot = gloas_slot(&forks) - 1;
    assert_eq!(
        slot / MinimalConsensusSpec::slots_per_epoch(),
        forks.fulu.epoch
    );
    assert_eq!(DENEB_EXECUTION_GINDEX, 812);
    fixture.header["beacon"]["slot"] = Value::String(slot.to_string());
    let bootstrap = parse_bootstrap(fixture.to_json());
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidExecutionPayloadProof,
    );
}

#[test]
fn gloas_bootstrap_rejects_a_legacy_header_after_the_fork() {
    let forks = test_forks(4);

    // A pre-Gloas header representation cannot be used once the fork is active.
    let mut fixture = GloasBootstrap::valid(&forks);
    let pre_gloas_branch = [B256::ZERO; 4];
    fixture.header = pre_gloas_header_json(gloas_slot(&forks), &pre_gloas_branch);
    let bootstrap = parse_bootstrap(fixture.to_json());
    assert!(bootstrap.header().execution().is_ok());
    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidExecutionPayloadProof,
    );
}

#[test]
fn gloas_bootstrap_rejects_a_mismatched_committee_branch_length() {
    let forks = test_forks(4);

    // The Gloas committee branch is 11 nodes; a 6-node branch is the Electra shape.
    // The Gloas header still selects the Gloas route, which the shorter branch
    // cannot prove.
    let mut fixture = GloasBootstrap::valid(&forks);
    fixture.committee_branch.truncate(6);
    let bootstrap = parse_bootstrap(fixture.to_json());
    assert!(matches!(&bootstrap, Bootstrap::Electra(_)));
    assert_eq!(bootstrap.current_sync_committee_branch().len(), 6);

    let checkpoint = bootstrap.header().beacon().tree_hash_root();
    expect_consensus_error(
        verify_bootstrap(&bootstrap, checkpoint, &forks),
        ConsensusError::InvalidCurrentSyncCommitteeProof,
    );
}

#[test]
fn gloas_wire_shapes_pin_the_branch_lengths() {
    let forks = test_forks(4);
    let execution_branch = eleven_nodes(0x30);
    let execution_block_hash = B256::with_last_byte(0xaa);
    let body_root = fold(execution_block_hash, &execution_branch, EXECUTION_GINDEX);
    let header = gloas_header_json(
        gloas_slot(&forks),
        B256::ZERO,
        body_root,
        execution_block_hash,
        &execution_branch,
    );

    // LightClientHeader: 11-node execution branch, no execution payload header.
    let parsed: LightClientHeader = serde_json::from_value(header.clone()).unwrap();
    assert!(matches!(&parsed, LightClientHeader::Gloas(_)));
    assert_eq!(parsed.execution_branch_gloas().unwrap().len(), 11);

    // A 10-node execution branch matches no light client header variant.
    let mut short = header.clone();
    short["execution_branch"] = hexes(&[B256::ZERO; 10]);
    assert!(serde_json::from_value::<LightClientHeader>(short).is_err());

    // FinalityUpdate: 9-node finality branch (6 pre-Electra, 7 in Electra).
    let wire = json!({
        "attested_header": header.clone(),
        "finalized_header": header.clone(),
        "finality_branch": hexes(&[B256::with_last_byte(0x40); 9]),
        "sync_aggregate": sync_aggregate_json(),
        "signature_slot": "1",
    });
    let parsed: FinalityUpdate<MinimalConsensusSpec> = serde_json::from_value(wire).unwrap();
    assert!(matches!(&parsed, FinalityUpdate::Gloas(_)));
    assert_eq!(parsed.finality_branch().len(), 9);

    // Update: 11-node next sync committee branch and 9-node finality branch.
    let wire = json!({
        "attested_header": header.clone(),
        "next_sync_committee": sync_committee_json(),
        "next_sync_committee_branch": hexes(&[B256::with_last_byte(0x50); 11]),
        "finalized_header": header.clone(),
        "finality_branch": hexes(&[B256::with_last_byte(0x40); 9]),
        "sync_aggregate": sync_aggregate_json(),
        "signature_slot": "1",
    });
    let parsed: Update<MinimalConsensusSpec> = serde_json::from_value(wire.clone()).unwrap();
    assert!(matches!(&parsed, Update::Gloas(_)));
    assert_eq!(parsed.next_sync_committee_branch().len(), 11);
    assert_eq!(parsed.finality_branch().len(), 9);

    // Pre-Gloas branch lengths still select the Electra variant.
    let mut short = wire;
    short["next_sync_committee_branch"] = hexes(&[B256::ZERO; 6]);
    short["finality_branch"] = hexes(&[B256::ZERO; 7]);
    let parsed: Update<MinimalConsensusSpec> = serde_json::from_value(short).unwrap();
    assert!(matches!(&parsed, Update::Electra(_)));
    assert_eq!(parsed.next_sync_committee_branch().len(), 6);
    assert_eq!(parsed.finality_branch().len(), 7);
}

#[test]
fn pre_gloas_wire_shape_is_unchanged() {
    // Fulu shares the Electra light client header, so the frozen shape still
    // carries an execution payload header and a 4-node branch.
    let branch = [B256::ZERO; 4];
    let header: LightClientHeader =
        serde_json::from_value(pre_gloas_header_json(0, &branch)).unwrap();
    assert!(header.execution().is_ok());
    assert!(header.execution_branch().is_ok());
    assert!(header.execution_block_hash().is_err());
    assert!(header.execution_branch_gloas().is_err());

    let bootstrap = json!({
        "header": pre_gloas_header_json(0, &branch),
        "current_sync_committee": sync_committee_json(),
        "current_sync_committee_branch": hexes(&[B256::ZERO; 6]),
    });
    let bootstrap = parse_bootstrap(bootstrap);
    assert!(matches!(&bootstrap, Bootstrap::Electra(_)));
    assert_eq!(bootstrap.current_sync_committee_branch().len(), 6);
}
