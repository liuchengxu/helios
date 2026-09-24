//! Canonical SSZ decoding of the Gloas light client containers.
//!
//! The Gloas `LightClientHeader` is a fixed-size container (`beacon`,
//! `execution_block_hash`, an 11-node `execution_branch`), so the enclosing containers
//! inline it. The bytes below are built field by field in spec order from the captured
//! Gloas JSON fixtures, independently of the decoder under test.

use alloy::primitives::B256;
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use helios_consensus_core::types::{
    Bootstrap, FinalityUpdate, LightClientHeader, OptimisticUpdate, SyncAggregate, SyncCommittee,
    Update, UpdateGloas,
};
use serde_json::Value;
use ssz::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash::TreeHash;

type Spec = MainnetConsensusSpec;

/// `BeaconBlockHeader` (112) + `execution_block_hash` (32) + 11 branch nodes.
const GLOAS_HEADER_SSZ_LEN: usize = 112 + 32 + 11 * 32;

const CAPTURED_BOOTSTRAP: &str = include_str!("../testdata/gloas-captured/bootstrap.json");
const CAPTURED_FINALITY: &str = include_str!("../testdata/gloas-captured/finality.json");
const TRANSITION_POST_FINALITY: &str =
    include_str!("../testdata/fulu-gloas-transition/post-finality.json");
const TRANSITION_PRE_FINALITY: &str =
    include_str!("../testdata/fulu-gloas-transition/pre-finality.json");

fn data(fixture: &str) -> Value {
    let value: Value = serde_json::from_str(fixture).unwrap();
    value["data"].clone()
}

fn gloas_header_ssz(header: &LightClientHeader) -> Vec<u8> {
    let LightClientHeader::Gloas(header) = header else {
        panic!("fixture header must be Gloas-format");
    };

    let mut bytes = header.beacon.as_ssz_bytes();
    bytes.extend_from_slice(header.execution_block_hash.as_slice());
    for node in header.execution_branch.iter() {
        bytes.extend_from_slice(node.as_slice());
    }
    assert_eq!(bytes.len(), GLOAS_HEADER_SSZ_LEN);
    bytes
}

fn branch_ssz(branch: &[B256]) -> Vec<u8> {
    branch.iter().flat_map(|node| node.0).collect()
}

fn assert_same_aggregate(decoded: &SyncAggregate<Spec>, expected: &SyncAggregate<Spec>) {
    assert_eq!(decoded.as_ssz_bytes(), expected.as_ssz_bytes());
}

fn assert_same_committee(decoded: &SyncCommittee<Spec>, expected: &SyncCommittee<Spec>) {
    assert_eq!(decoded.tree_hash_root(), expected.tree_hash_root());
    assert_eq!(decoded, expected);
}

#[test]
fn canonical_gloas_bootstrap_ssz_decodes() {
    let expected: Bootstrap<Spec> = serde_json::from_value(data(CAPTURED_BOOTSTRAP)).unwrap();
    assert!(matches!(expected, Bootstrap::Gloas(_)));

    let mut bytes = gloas_header_ssz(expected.header());
    bytes.extend(expected.current_sync_committee().as_ssz_bytes());
    bytes.extend(branch_ssz(expected.current_sync_committee_branch()));
    // A fixed-size container: slot 64 leads the bytes, not an offset.
    assert_eq!(&bytes[..8], &64u64.to_le_bytes());

    let decoded = Bootstrap::<Spec>::from_ssz_bytes(&bytes).expect("canonical Gloas bootstrap");

    assert!(matches!(decoded, Bootstrap::Gloas(_)));
    assert_eq!(decoded.header(), expected.header());
    assert_eq!(decoded.header().beacon().slot, 64);
    assert_same_committee(
        decoded.current_sync_committee(),
        expected.current_sync_committee(),
    );
    assert_eq!(
        decoded.current_sync_committee_branch(),
        expected.current_sync_committee_branch()
    );
}

fn finality_update_ssz(update: &FinalityUpdate<Spec>) -> Vec<u8> {
    let mut bytes = gloas_header_ssz(update.attested_header());
    bytes.extend(gloas_header_ssz(update.finalized_header()));
    bytes.extend(branch_ssz(update.finality_branch()));
    bytes.extend(update.sync_aggregate().as_ssz_bytes());
    bytes.extend(update.signature_slot().as_ssz_bytes());
    bytes
}

fn assert_finality_update_decodes(fixture: &str) {
    let expected: FinalityUpdate<Spec> = serde_json::from_value(data(fixture)).unwrap();
    assert!(matches!(expected, FinalityUpdate::Gloas(_)));

    let bytes = finality_update_ssz(&expected);
    let decoded =
        FinalityUpdate::<Spec>::from_ssz_bytes(&bytes).expect("canonical Gloas finality update");

    assert!(matches!(decoded, FinalityUpdate::Gloas(_)));
    assert_eq!(decoded.attested_header(), expected.attested_header());
    assert_eq!(decoded.finalized_header(), expected.finalized_header());
    assert_eq!(decoded.finality_branch(), expected.finality_branch());
    assert_same_aggregate(decoded.sync_aggregate(), expected.sync_aggregate());
    assert_eq!(decoded.signature_slot(), expected.signature_slot());
}

#[test]
fn canonical_gloas_finality_update_ssz_decodes() {
    assert_finality_update_decodes(CAPTURED_FINALITY);
    assert_finality_update_decodes(TRANSITION_POST_FINALITY);
}

/// No Gloas `LightClientUpdate` fixture is captured, so this one is assembled from the
/// captured bootstrap and finality update. Its values need not verify.
#[test]
fn canonical_gloas_update_ssz_decodes() {
    let bootstrap: Bootstrap<Spec> = serde_json::from_value(data(CAPTURED_BOOTSTRAP)).unwrap();
    let finality: FinalityUpdate<Spec> = serde_json::from_value(data(CAPTURED_FINALITY)).unwrap();

    let expected = UpdateGloas::<Spec> {
        attested_header: finality.attested_header().clone(),
        next_sync_committee: bootstrap.current_sync_committee().clone(),
        next_sync_committee_branch: FixedVector::from(
            bootstrap.current_sync_committee_branch().to_vec(),
        ),
        finalized_header: finality.finalized_header().clone(),
        finality_branch: FixedVector::from(finality.finality_branch().to_vec()),
        sync_aggregate: finality.sync_aggregate().clone(),
        signature_slot: *finality.signature_slot(),
    };

    let mut bytes = gloas_header_ssz(&expected.attested_header);
    bytes.extend(expected.next_sync_committee.as_ssz_bytes());
    bytes.extend(branch_ssz(&expected.next_sync_committee_branch));
    bytes.extend(gloas_header_ssz(&expected.finalized_header));
    bytes.extend(branch_ssz(&expected.finality_branch));
    bytes.extend(expected.sync_aggregate.as_ssz_bytes());
    bytes.extend(expected.signature_slot.as_ssz_bytes());

    let decoded = Update::<Spec>::from_ssz_bytes(&bytes).expect("canonical Gloas update");

    assert!(matches!(decoded, Update::Gloas(_)));
    assert_eq!(decoded.attested_header(), &expected.attested_header);
    assert_same_committee(decoded.next_sync_committee(), &expected.next_sync_committee);
    assert_eq!(
        decoded.next_sync_committee_branch(),
        &expected.next_sync_committee_branch[..]
    );
    assert_eq!(decoded.finalized_header(), &expected.finalized_header);
    assert_eq!(decoded.finality_branch(), &expected.finality_branch[..]);
    assert_same_aggregate(decoded.sync_aggregate(), &expected.sync_aggregate);
    assert_eq!(*decoded.signature_slot(), expected.signature_slot);
}

#[test]
fn canonical_gloas_optimistic_update_ssz_decodes() {
    let finality: FinalityUpdate<Spec> = serde_json::from_value(data(CAPTURED_FINALITY)).unwrap();

    let mut bytes = gloas_header_ssz(finality.attested_header());
    bytes.extend(finality.sync_aggregate().as_ssz_bytes());
    bytes.extend(finality.signature_slot().as_ssz_bytes());

    let decoded =
        OptimisticUpdate::<Spec>::from_ssz_bytes(&bytes).expect("canonical Gloas optimistic");

    assert!(matches!(
        decoded.attested_header,
        LightClientHeader::Gloas(_)
    ));
    assert_eq!(&decoded.attested_header, finality.attested_header());
    assert_same_aggregate(&decoded.sync_aggregate, finality.sync_aggregate());
    assert_eq!(decoded.signature_slot, *finality.signature_slot());
}

/// A pre-Gloas optimistic update keeps the variable-size header layout.
#[test]
fn pre_gloas_optimistic_update_ssz_still_decodes() {
    let finality: FinalityUpdate<Spec> =
        serde_json::from_value(data(TRANSITION_PRE_FINALITY)).unwrap();
    let header = finality.attested_header();
    let execution = header
        .execution()
        .expect("Fulu header carries the payload header");
    let branch = header
        .execution_branch()
        .expect("Fulu header carries a 4-node branch");

    // Fixed part: header offset, sync aggregate, signature slot. Then the header:
    // beacon, payload header offset, branch, payload header.
    let aggregate = finality.sync_aggregate().as_ssz_bytes();
    let header_offset = u32::try_from(4 + aggregate.len() + 8).unwrap();
    let mut bytes = header_offset.as_ssz_bytes();
    bytes.extend(aggregate);
    bytes.extend(finality.signature_slot().as_ssz_bytes());
    bytes.extend(header.beacon().as_ssz_bytes());
    bytes.extend(u32::try_from(112 + 4 + 4 * 32).unwrap().as_ssz_bytes());
    bytes.extend(branch_ssz(branch));
    bytes.extend(execution.as_ssz_bytes());

    let decoded =
        OptimisticUpdate::<Spec>::from_ssz_bytes(&bytes).expect("pre-Gloas optimistic update");

    assert_eq!(&decoded.attested_header, header);
    assert_same_aggregate(&decoded.sync_aggregate, finality.sync_aggregate());
    assert_eq!(decoded.signature_slot, *finality.signature_slot());
}
