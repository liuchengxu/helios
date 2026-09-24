use alloy::primitives::B256;
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

use crate::{
    consensus_spec::ConsensusSpec,
    types::{
        BeaconBlockHeader, ExecutionPayloadHeader, ExecutionPayloadHeaderCapella,
        ExecutionPayloadHeaderDeneb, Forks, LightClientHeader, SyncCommittee,
    },
};

/// `FINALIZED_ROOT_GINDEX`: `get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')`.
pub const FINALIZED_ROOT_GINDEX: usize = 105;
/// `FINALIZED_ROOT_GINDEX_ELECTRA`.
pub const FINALIZED_ROOT_GINDEX_ELECTRA: usize = 169;
/// `FINALIZED_ROOT_GINDEX_GLOAS` (Gloas:EIP7688 progressive containers).
pub const FINALIZED_ROOT_GINDEX_GLOAS: usize = 735;
/// `CURRENT_SYNC_COMMITTEE_GINDEX`: `get_generalized_index(BeaconState, 'current_sync_committee')`.
pub const CURRENT_SYNC_COMMITTEE_GINDEX: usize = 54;
/// `CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA`.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: usize = 86;
/// `CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS`.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS: usize = 2_945;
/// `NEXT_SYNC_COMMITTEE_GINDEX`: `get_generalized_index(BeaconState, 'next_sync_committee')`.
pub const NEXT_SYNC_COMMITTEE_GINDEX: usize = 55;
/// `NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA`.
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: usize = 87;
/// `NEXT_SYNC_COMMITTEE_GINDEX_GLOAS`.
pub const NEXT_SYNC_COMMITTEE_GINDEX_GLOAS: usize = 2_946;
/// `EXECUTION_BLOCK_HASH_GINDEX_GLOAS`: `get_generalized_index(BeaconBlockBody,
/// 'signed_execution_payload_bid', 'message', 'parent_block_hash')`.
pub const EXECUTION_BLOCK_HASH_GINDEX_GLOAS: usize = 2_856;
/// `EXECUTION_BLOCK_HASH_GINDEX_DENEB`: `get_generalized_index(deneb.BeaconBlockBody,
/// 'execution_payload', 'block_hash')`.
pub const EXECUTION_BLOCK_HASH_GINDEX_DENEB: usize = 812;
/// `EXECUTION_BLOCK_HASH_GINDEX`: `get_generalized_index(capella.BeaconBlockBody,
/// 'execution_payload', 'block_hash')`.
pub const EXECUTION_BLOCK_HASH_GINDEX_CAPELLA: usize = 412;
/// `EXECUTION_PAYLOAD_GINDEX`: `get_generalized_index(capella.BeaconBlockBody,
/// 'execution_payload')`.
pub const EXECUTION_PAYLOAD_GINDEX: usize = 25;

/// `get_generalized_index(deneb.ExecutionPayloadHeader, 'block_hash')`, the block hash
/// index inside the execution payload header.
const PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB: usize = 44;
/// `get_generalized_index(capella.ExecutionPayloadHeader, 'block_hash')`.
const PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA: usize = 28;

/// `GENESIS_SLOT`.
const GENESIS_SLOT: u64 = 0;

/// `finalized_root_gindex_at_slot`, selected from the authenticated epoch.
pub fn finalized_root_gindex_at_epoch(epoch: u64, forks: &Forks) -> usize {
    if epoch >= forks.gloas.epoch {
        FINALIZED_ROOT_GINDEX_GLOAS
    } else if epoch >= forks.electra.epoch {
        FINALIZED_ROOT_GINDEX_ELECTRA
    } else {
        FINALIZED_ROOT_GINDEX
    }
}

/// `current_sync_committee_gindex_at_slot`, selected from the authenticated epoch.
pub fn current_sync_committee_gindex_at_epoch(epoch: u64, forks: &Forks) -> usize {
    if epoch >= forks.gloas.epoch {
        CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS
    } else if epoch >= forks.electra.epoch {
        CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA
    } else {
        CURRENT_SYNC_COMMITTEE_GINDEX
    }
}

/// `next_sync_committee_gindex_at_slot`, selected from the authenticated epoch.
pub fn next_sync_committee_gindex_at_epoch(epoch: u64, forks: &Forks) -> usize {
    if epoch >= forks.gloas.epoch {
        NEXT_SYNC_COMMITTEE_GINDEX_GLOAS
    } else if epoch >= forks.electra.epoch {
        NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA
    } else {
        NEXT_SYNC_COMMITTEE_GINDEX
    }
}

/// `is_valid_light_client_header`'s execution block hash gindex, selected from the
/// authenticated epoch. `None` before Capella, where the upgraded execution fields must
/// be exact zeros.
///
/// Selection follows the slot, not the received wire variant: a Gloas-format header
/// upgraded from an earlier fork keeps the gindex of that fork.
pub fn execution_block_hash_gindex_at_epoch(epoch: u64, forks: &Forks) -> Option<usize> {
    if epoch >= forks.gloas.epoch {
        Some(EXECUTION_BLOCK_HASH_GINDEX_GLOAS)
    } else if epoch >= forks.deneb.epoch {
        Some(EXECUTION_BLOCK_HASH_GINDEX_DENEB)
    } else if epoch >= forks.capella.epoch {
        Some(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA)
    } else {
        None
    }
}

/// `get_lc_execution_root`'s block hash gindex inside `ExecutionPayloadHeader`, selected
/// from the authenticated epoch.
fn payload_header_block_hash_gindex_at_epoch(epoch: u64, forks: &Forks) -> Option<usize> {
    if epoch >= forks.deneb.epoch {
        Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB)
    } else if epoch >= forks.capella.epoch {
        Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA)
    } else {
        None
    }
}

pub fn is_finality_proof_valid(
    attested_header: &BeaconBlockHeader,
    finality_header: &BeaconBlockHeader,
    finality_branch: &[B256],
    current_epoch: u64,
    forks: &Forks,
) -> bool {
    let gindex = finalized_root_gindex_at_epoch(current_epoch, forks);

    // A Gloas-format branch is normalized to `floorlog2(FINALIZED_ROOT_GINDEX_GLOAS)`,
    // so a pre-Gloas epoch accepts it only with the zero padding that upgrade adds.
    is_valid_normalized_merkle_branch(
        finality_header.tree_hash_root(),
        finality_branch,
        gindex,
        attested_header.state_root,
    )
}

pub fn is_next_committee_proof_valid<S: ConsensusSpec>(
    attested_header: &BeaconBlockHeader,
    next_committee: &SyncCommittee<S>,
    next_committee_branch: &[B256],
    current_epoch: u64,
    forks: &Forks,
) -> bool {
    let gindex = next_sync_committee_gindex_at_epoch(current_epoch, forks);

    is_valid_normalized_merkle_branch(
        next_committee.tree_hash_root(),
        next_committee_branch,
        gindex,
        attested_header.state_root,
    )
}

pub fn is_current_committee_proof_valid<S: ConsensusSpec>(
    attested_header: &BeaconBlockHeader,
    current_committee: &SyncCommittee<S>,
    current_committee_branch: &[B256],
    current_epoch: u64,
    forks: &Forks,
) -> bool {
    let gindex = current_sync_committee_gindex_at_epoch(current_epoch, forks);

    is_valid_normalized_merkle_branch(
        current_committee.tree_hash_root(),
        current_committee_branch,
        gindex,
        attested_header.state_root,
    )
}

pub fn is_execution_payload_proof_valid(
    attested_header: &BeaconBlockHeader,
    execution: &ExecutionPayloadHeader,
    execution_branch: &[B256],
) -> bool {
    is_proof_valid(
        attested_header.body_root,
        execution,
        execution_branch,
        floorlog2(EXECUTION_PAYLOAD_GINDEX),
        get_subtree_index(EXECUTION_PAYLOAD_GINDEX),
    )
}

/// `is_valid_light_client_header` for a header that carries the last executed execution
/// block hash instead of the execution payload header: the hash is proven into
/// `beacon.body_root` at the gindex of the header's own fork.
pub fn is_execution_block_hash_proof_valid(
    beacon: &BeaconBlockHeader,
    execution_block_hash: B256,
    execution_branch: &[B256],
    gindex: usize,
) -> bool {
    is_valid_normalized_merkle_branch(
        execution_block_hash,
        execution_branch,
        gindex,
        beacon.body_root,
    )
}

/// `get_lc_execution_root`: the execution root a light client header commits to.
///
/// At and after Gloas the header commits to the last executed execution block hash
/// directly. An upgraded (Gloas-format) pre-Gloas header commits to the execution
/// payload header root instead, recovered here from the normalized execution branch,
/// which is leaf-first and zero padded to
/// `floorlog2(EXECUTION_BLOCK_HASH_GINDEX_GLOAS)`. A legacy pre-Gloas header carries the
/// execution payload header itself.
///
/// The header must already satisfy `is_valid_light_client_header`; this function only
/// derives the committed root.
pub fn get_lc_execution_root<S: ConsensusSpec>(header: &LightClientHeader, forks: &Forks) -> B256 {
    let epoch = header.beacon().slot / S::slots_per_epoch();

    // [New in Gloas:EIP7732]
    if epoch >= forks.gloas.epoch {
        return header.execution_block_hash().copied().unwrap_or_default();
    }

    // A legacy pre-Gloas header carries the execution payload header itself.
    if let Ok(execution) = header.execution() {
        return execution.tree_hash_root();
    }

    // [Modified in Gloas:EIP7732] An upgraded header at `GENESIS_SLOT` commits to the
    // empty execution payload header of its fork.
    if header.beacon().slot == GENESIS_SLOT {
        if epoch >= forks.deneb.epoch {
            return ExecutionPayloadHeaderDeneb::default().tree_hash_root();
        }
        if epoch >= forks.capella.epoch {
            return ExecutionPayloadHeaderCapella::default().tree_hash_root();
        }
    }

    // [Modified in Gloas:EIP7732] The upgraded header only proves the execution block
    // hash, so the payload header root is folded from the nodes below the execution
    // payload. Pre-Capella commits to no executed payload at all.
    let (Some(payload_gindex), Ok(branch)) = (
        payload_header_block_hash_gindex_at_epoch(epoch, forks),
        header.execution_branch_gloas(),
    ) else {
        return B256::ZERO;
    };

    let depth = floorlog2(payload_gindex);
    let Some(inner_len) = branch
        .len()
        .checked_sub(floorlog2(EXECUTION_PAYLOAD_GINDEX))
    else {
        return B256::ZERO;
    };
    let Some(start) = inner_len.checked_sub(depth) else {
        return B256::ZERO;
    };

    // The slice below the execution payload is exactly `depth` nodes long.
    compute_merkle_branch_root(
        header.execution_block_hash().copied().unwrap_or_default(),
        &branch[start..inner_len],
        depth,
        get_subtree_index(payload_gindex),
    )
    .unwrap_or(B256::ZERO)
}

/// `floorlog2`, the depth of a generalized index's tree.
fn floorlog2(gindex: usize) -> usize {
    debug_assert!(gindex > 0, "generalized indices are positive");
    usize::BITS as usize - 1 - gindex.leading_zeros() as usize
}

/// `get_subtree_index`, the left/right position within the index's depth.
fn get_subtree_index(gindex: usize) -> usize {
    gindex % (1usize << floorlog2(gindex))
}

/// `compute_merkle_branch_root`: folds a leaf-first branch into the root it proves,
/// without comparing it to an expected root. `None` when `branch` is not `depth` long.
fn compute_merkle_branch_root(
    leaf: B256,
    branch: &[B256],
    depth: usize,
    index: usize,
) -> Option<B256> {
    if branch.len() != depth {
        return None;
    }

    let mut derived_root = leaf;
    let mut hasher = Sha256::new();

    for (i, node) in branch.iter().enumerate() {
        if !(index / 2usize.pow(i as u32)).is_multiple_of(2) {
            hasher.update(node);
            hasher.update(derived_root);
        } else {
            hasher.update(derived_root);
            hasher.update(node);
        }

        derived_root = B256::from_slice(hasher.finalize_reset().as_slice());
    }

    Some(derived_root)
}

/// `is_valid_normalized_merkle_branch`: entries above the gindex depth must be zero.
fn is_valid_normalized_merkle_branch(
    leaf: B256,
    branch: &[B256],
    gindex: usize,
    root: B256,
) -> bool {
    let depth = floorlog2(gindex);
    if branch.len() < depth {
        return false;
    }

    let num_extra = branch.len() - depth;
    if branch[..num_extra].iter().any(|node| !node.is_zero()) {
        return false;
    }

    is_proof_valid(
        root,
        &leaf,
        &branch[num_extra..],
        depth,
        get_subtree_index(gindex),
    )
}

fn is_proof_valid<T: TreeHash>(
    root: B256,
    leaf_object: &T,
    branch: &[B256],
    depth: usize,
    index: usize,
) -> bool {
    compute_merkle_branch_root(leaf_object.tree_hash_root(), branch, depth, index) == Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_spec::MinimalConsensusSpec;
    use crate::types::{Fork, LightClientHeaderGloas};
    use alloy::primitives::fixed_bytes;
    use ssz_types::FixedVector;

    /// `EXECUTION_BLOCK_HASH_GINDEX_GLOAS` (2856), aliased for readable assertions.
    const EXECUTION_GINDEX: usize = EXECUTION_BLOCK_HASH_GINDEX_GLOAS;

    /// Independent re-implementation of the consensus branch fold, used to build
    /// self-consistent fixtures. The pinned spec ships no Gloas runtime vector yet.
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

    /// Eleven distinct non-zero branch nodes.
    fn test_branch() -> Vec<B256> {
        (1..=11u8).map(B256::with_last_byte).collect()
    }

    fn branch_valid(leaf: B256, branch: &[B256], root: B256) -> bool {
        is_valid_normalized_merkle_branch(leaf, branch, EXECUTION_GINDEX, root)
    }

    fn test_forks(electra_epoch: u64, gloas_epoch: u64) -> Forks {
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
                epoch: electra_epoch,
                fork_version: fixed_bytes!("05000001"),
            },
            fulu: Fork {
                epoch: electra_epoch + 1,
                fork_version: fixed_bytes!("06000001"),
            },
            gloas: Fork {
                epoch: gloas_epoch,
                fork_version: fixed_bytes!("07000001"),
            },
        }
    }

    #[test]
    fn gindex_selection_follows_the_fork_schedule() {
        let forks = test_forks(2, 4);
        let finalized = |epoch| finalized_root_gindex_at_epoch(epoch, &forks);
        let current = |epoch| current_sync_committee_gindex_at_epoch(epoch, &forks);
        let next = |epoch| next_sync_committee_gindex_at_epoch(epoch, &forks);

        assert_eq!(finalized(1), FINALIZED_ROOT_GINDEX);
        assert_eq!(finalized(2), FINALIZED_ROOT_GINDEX_ELECTRA);
        assert_eq!(finalized(4), FINALIZED_ROOT_GINDEX_GLOAS);
        assert_eq!(current(1), CURRENT_SYNC_COMMITTEE_GINDEX);
        assert_eq!(current(2), CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA);
        assert_eq!(current(4), CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS);
        assert_eq!(next(1), NEXT_SYNC_COMMITTEE_GINDEX);
        assert_eq!(next(2), NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA);
        assert_eq!(next(4), NEXT_SYNC_COMMITTEE_GINDEX_GLOAS);
    }

    #[test]
    fn gloas_gindices_match_the_pinned_spec() {
        assert_eq!(EXECUTION_BLOCK_HASH_GINDEX_GLOAS, 2_856);
        assert_eq!(FINALIZED_ROOT_GINDEX_GLOAS, 735);
        assert_eq!(CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS, 2_945);
        assert_eq!(NEXT_SYNC_COMMITTEE_GINDEX_GLOAS, 2_946);

        // Branch lengths are `floorlog2(gindex)`.
        assert_eq!(floorlog2(EXECUTION_GINDEX), 11);
        assert_eq!(floorlog2(FINALIZED_ROOT_GINDEX_GLOAS), 9);
        assert_eq!(floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS), 11);
        assert_eq!(floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_GLOAS), 11);

        assert_eq!(get_subtree_index(EXECUTION_GINDEX), 808);
        assert_eq!(get_subtree_index(FINALIZED_ROOT_GINDEX_GLOAS), 223);
        assert_eq!(get_subtree_index(CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS), 897);
        assert_eq!(get_subtree_index(NEXT_SYNC_COMMITTEE_GINDEX_GLOAS), 898);

        // Pre-Gloas indices stay frozen.
        assert_eq!(floorlog2(FINALIZED_ROOT_GINDEX), 6);
        assert_eq!(get_subtree_index(FINALIZED_ROOT_GINDEX), 41);
        assert_eq!(floorlog2(FINALIZED_ROOT_GINDEX_ELECTRA), 7);
        assert_eq!(get_subtree_index(FINALIZED_ROOT_GINDEX_ELECTRA), 41);
        assert_eq!(floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX), 5);
        assert_eq!(get_subtree_index(CURRENT_SYNC_COMMITTEE_GINDEX), 22);
        assert_eq!(floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA), 6);
        assert_eq!(get_subtree_index(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA), 22);
        assert_eq!(floorlog2(NEXT_SYNC_COMMITTEE_GINDEX), 5);
        assert_eq!(get_subtree_index(NEXT_SYNC_COMMITTEE_GINDEX), 23);
        assert_eq!(floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA), 6);
        assert_eq!(get_subtree_index(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA), 23);
    }

    #[test]
    fn pre_gloas_execution_gindices_match_the_pinned_spec() {
        assert_eq!(EXECUTION_PAYLOAD_GINDEX, 25);
        assert_eq!(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA, 412);
        assert_eq!(EXECUTION_BLOCK_HASH_GINDEX_DENEB, 812);

        assert_eq!(floorlog2(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA), 8);
        assert_eq!(floorlog2(EXECUTION_BLOCK_HASH_GINDEX_DENEB), 9);
        assert_eq!(get_subtree_index(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA), 156);
        assert_eq!(get_subtree_index(EXECUTION_BLOCK_HASH_GINDEX_DENEB), 300);

        // `get_generalized_index(<fork>.ExecutionPayloadHeader, 'block_hash')`.
        assert_eq!(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA, 28);
        assert_eq!(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB, 44);
        assert_eq!(floorlog2(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA), 4);
        assert_eq!(floorlog2(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB), 5);
        assert_eq!(
            get_subtree_index(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA),
            12
        );
        assert_eq!(
            get_subtree_index(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB),
            12
        );
    }

    /// The payload-header gindices compose the pinned body-level indices through the
    /// execution payload gindex.
    #[test]
    fn payload_header_gindices_compose_into_the_body_indices() {
        for (payload_gindex, body_gindex) in [
            (
                PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA,
                EXECUTION_BLOCK_HASH_GINDEX_CAPELLA,
            ),
            (
                PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB,
                EXECUTION_BLOCK_HASH_GINDEX_DENEB,
            ),
        ] {
            assert_eq!(
                EXECUTION_PAYLOAD_GINDEX * (1 << floorlog2(payload_gindex))
                    + get_subtree_index(payload_gindex),
                body_gindex
            );
        }
    }

    #[test]
    fn execution_block_hash_gindex_selection_follows_the_fork_schedule() {
        let forks = {
            let mut forks = test_forks(4, 6);
            forks.deneb.epoch = 2;
            forks
        };

        let body = |epoch| execution_block_hash_gindex_at_epoch(epoch, &forks);
        let payload = |epoch| payload_header_block_hash_gindex_at_epoch(epoch, &forks);

        assert_eq!(body(0), Some(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA));
        assert_eq!(body(2), Some(EXECUTION_BLOCK_HASH_GINDEX_DENEB));
        assert_eq!(body(5), Some(EXECUTION_BLOCK_HASH_GINDEX_DENEB));
        assert_eq!(body(6), Some(EXECUTION_BLOCK_HASH_GINDEX_GLOAS));
        assert_eq!(payload(0), Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA));
        assert_eq!(payload(2), Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB));
        assert_eq!(payload(6), Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_DENEB));

        // Before Capella an upgraded header commits to no executed payload.
        let pre_capella = {
            let mut forks = forks.clone();
            forks.capella.epoch = 1;
            forks
        };
        assert_eq!(execution_block_hash_gindex_at_epoch(0, &pre_capella), None);
        assert_eq!(
            payload_header_block_hash_gindex_at_epoch(0, &pre_capella),
            None
        );
        assert_eq!(
            execution_block_hash_gindex_at_epoch(1, &pre_capella),
            Some(EXECUTION_BLOCK_HASH_GINDEX_CAPELLA)
        );
        assert_eq!(
            payload_header_block_hash_gindex_at_epoch(1, &pre_capella),
            Some(PAYLOAD_HEADER_BLOCK_HASH_GINDEX_CAPELLA)
        );
    }

    fn gloas_header_at(slot: u64, execution_block_hash: B256) -> LightClientHeader {
        LightClientHeader::Gloas(LightClientHeaderGloas {
            beacon: BeaconBlockHeader {
                slot,
                ..Default::default()
            },
            execution_block_hash,
            execution_branch: FixedVector::from(vec![B256::ZERO; 11]),
        })
    }

    /// `get_lc_execution_root` returns the empty payload header root of the slot's fork
    /// for an upgraded header at `GENESIS_SLOT`, not a root folded from its branch.
    #[test]
    fn upgraded_genesis_header_commits_to_the_empty_payload_header() {
        let execution_root = |header: &LightClientHeader, forks: &Forks| {
            get_lc_execution_root::<MinimalConsensusSpec>(header, forks)
        };
        let deneb_empty = ExecutionPayloadHeaderDeneb::default().tree_hash_root();
        let capella_empty = ExecutionPayloadHeaderCapella::default().tree_hash_root();
        assert_ne!(deneb_empty, capella_empty);

        let header = gloas_header_at(GENESIS_SLOT, B256::ZERO);

        // Deneb (and Capella) active at genesis, Gloas later.
        let deneb_at_genesis = test_forks(0, 1);
        assert_eq!(execution_root(&header, &deneb_at_genesis), deneb_empty);

        // Capella active at genesis, Deneb later.
        let capella_at_genesis = {
            let mut forks = test_forks(2, 3);
            forks.deneb.epoch = 1;
            forks
        };
        assert_eq!(execution_root(&header, &capella_at_genesis), capella_empty);

        // Gloas active at genesis: the header commits to its block hash directly.
        let block_hash = B256::with_last_byte(0xaa);
        let header = gloas_header_at(GENESIS_SLOT, block_hash);
        assert_eq!(execution_root(&header, &test_forks(0, 0)), block_hash);
    }

    #[test]
    fn normalized_branch_accepts_a_valid_branch() {
        let leaf = B256::with_last_byte(7);
        let branch = test_branch();
        let root = fold(leaf, &branch, EXECUTION_GINDEX);

        assert!(branch_valid(leaf, &branch, root));

        // Zero padding above the gindex depth is tolerated.
        let padded: Vec<B256> = [vec![B256::ZERO; 4], branch.clone()].concat();
        assert!(branch_valid(leaf, &padded, root));
    }

    #[test]
    fn normalized_branch_rejects_malformed_branches() {
        let leaf = B256::with_last_byte(7);
        let branch = test_branch();
        let root = fold(leaf, &branch, EXECUTION_GINDEX);

        // A tampered node breaks the recomputed root.
        let mut tampered = branch.clone();
        tampered[0] = B256::with_last_byte(99);
        assert!(!branch_valid(leaf, &tampered, root));

        // Non-zero padding above the gindex depth is rejected.
        let mut bad_padding: Vec<B256> = [vec![B256::ZERO; 4], branch.clone()].concat();
        bad_padding[0] = B256::with_last_byte(1);
        assert!(!branch_valid(leaf, &bad_padding, root));

        // A branch shorter than the gindex depth is rejected.
        assert!(!branch_valid(leaf, &branch[..10], root));

        // An 11-node branch cannot prove the execution payload header index.
        let wrong_gindex = is_valid_normalized_merkle_branch(leaf, &branch, 25, root);
        assert!(!wrong_gindex);
    }
}
