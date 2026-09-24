use std::cmp;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::B256;
use eyre::Result;
use ssz_types::BitVector;
use tracing::{info, warn};
use tree_hash::TreeHash;
#[cfg(target_arch = "wasm32")]
use wasmtimer::std::{SystemTime, UNIX_EPOCH};

use crate::consensus_spec::ConsensusSpec;
use crate::errors::ConsensusError;
use crate::proof::{
    execution_block_hash_gindex_at_epoch, is_current_committee_proof_valid,
    is_execution_block_hash_proof_valid, is_execution_payload_proof_valid, is_finality_proof_valid,
    is_next_committee_proof_valid,
};
use crate::types::bls::Signature;
use crate::types::{
    BeaconBlockHeader, Bootstrap, FinalityUpdate, Forks, GenericUpdate, LightClientHeader,
    LightClientStore, OptimisticUpdate, Update,
};
use crate::utils::{
    calculate_fork_version, compute_committee_sign_root, compute_fork_data_root,
    get_participating_aggregate_pubkey,
};

/// `get_lc_execution_root`, re-exported with the other light client helpers.
pub use crate::proof::get_lc_execution_root;

pub fn verify_bootstrap<S: ConsensusSpec>(
    bootstrap: &Bootstrap<S>,
    checkpoint: B256,
    forks: &Forks,
) -> Result<()> {
    if !is_valid_header::<S>(bootstrap.header(), forks) {
        return Err(ConsensusError::InvalidExecutionPayloadProof.into());
    }

    let committee_valid = is_current_committee_proof_valid(
        bootstrap.header().beacon(),
        bootstrap.current_sync_committee(),
        bootstrap.current_sync_committee_branch(),
        bootstrap.header().beacon().slot / S::slots_per_epoch(),
        forks,
    );

    let header_hash = bootstrap.header().beacon().tree_hash_root();
    let header_valid = header_hash == checkpoint;

    if !header_valid {
        return Err(ConsensusError::InvalidHeaderHash(header_hash, checkpoint).into());
    }

    if !committee_valid {
        return Err(ConsensusError::InvalidCurrentSyncCommitteeProof.into());
    }

    Ok(())
}

pub fn verify_update<S: ConsensusSpec>(
    update: &Update<S>,
    expected_current_slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
) -> Result<()> {
    let update = GenericUpdate::from(update);
    verify_generic_update::<S>(&update, expected_current_slot, store, genesis_root, forks)
}

pub fn verify_finality_update<S: ConsensusSpec>(
    update: &FinalityUpdate<S>,
    expected_current_slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
) -> Result<()> {
    let update = GenericUpdate::from(update);
    verify_generic_update::<S>(&update, expected_current_slot, store, genesis_root, forks)
}

pub fn verify_optimistic_update<S: ConsensusSpec>(
    update: &OptimisticUpdate<S>,
    expected_current_slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
) -> Result<()> {
    let update = GenericUpdate::from(update);
    verify_generic_update::<S>(&update, expected_current_slot, store, genesis_root, forks)
}

pub fn apply_bootstrap<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    bootstrap: &Bootstrap<S>,
) {
    *store = LightClientStore {
        finalized_header: bootstrap.header().clone(),
        current_sync_committee: bootstrap.current_sync_committee().clone(),
        next_sync_committee: None,
        optimistic_header: bootstrap.header().clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
        best_valid_update: None,
    };
}

pub fn apply_update<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    update: &Update<S>,
) -> Option<B256> {
    let update = GenericUpdate::from(update);
    apply_generic_update::<S>(store, &update)
}

pub fn apply_finality_update<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    update: &FinalityUpdate<S>,
) -> Option<B256> {
    let update = GenericUpdate::from(update);
    apply_generic_update::<S>(store, &update)
}

pub fn apply_optimistic_update<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    update: &OptimisticUpdate<S>,
) -> Option<B256> {
    let update = GenericUpdate::from(update);
    apply_generic_update::<S>(store, &update)
}

// implements state changes from apply_light_client_update and process_light_client_update in
// the specification
/// Returns the new checkpoint if one is created, otherwise None
pub fn apply_generic_update<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    update: &GenericUpdate<S>,
) -> Option<B256> {
    let committee_bits = get_bits::<S>(&update.sync_aggregate.sync_committee_bits);

    // update best valid update
    if store.best_valid_update.is_none()
        || is_better_update(update, store.best_valid_update.as_ref().unwrap())
    {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        u64::max(store.current_max_active_participants, committee_bits);

    let should_update_optimistic = committee_bits > safety_threshold(store)
        && update.attested_header.beacon().slot > store.optimistic_header.beacon().slot;

    if should_update_optimistic {
        store.optimistic_header = update.attested_header.clone();
    }

    let update_attested_period = calc_sync_period::<S>(update.attested_header.beacon().slot);

    let update_finalized_slot = update
        .finalized_header
        .as_ref()
        .map(|h| h.beacon().slot)
        .unwrap_or(0);

    let update_finalized_period = calc_sync_period::<S>(update_finalized_slot);

    let update_has_finalized_next_committee = store.next_sync_committee.is_none()
        && has_sync_update(update)
        && has_finality_update(update)
        && update_finalized_period == update_attested_period;

    let should_apply_update = {
        let has_majority = committee_bits * 3 >= S::sync_committee_size() * 2;
        if !has_majority {
            warn!("skipping block with low vote count");
        }

        let update_is_newer = update_finalized_slot > store.finalized_header.beacon().slot;
        let good_update = update_is_newer || update_has_finalized_next_committee;

        has_majority && good_update
    };

    if should_apply_update {
        let checkpoint = apply_update_no_quorum_check(store, update);
        store.best_valid_update = None;
        checkpoint
    } else {
        None
    }
}

fn apply_update_no_quorum_check<S: ConsensusSpec>(
    store: &mut LightClientStore<S>,
    update: &GenericUpdate<S>,
) -> Option<B256> {
    let store_period = calc_sync_period::<S>(store.finalized_header.beacon().slot);
    let update_finalized_slot = update
        .finalized_header
        .as_ref()
        .map(|h| h.beacon().slot)
        .unwrap_or(0);
    let update_finalized_period = calc_sync_period::<S>(update_finalized_slot);

    if store.next_sync_committee.is_none() {
        if update_finalized_period != store_period {
            return None;
        }
        store
            .next_sync_committee
            .clone_from(&update.next_sync_committee);
    } else if update_finalized_period == store_period + 1 {
        info!(target: "helios::consensus", "sync committee updated");
        store.current_sync_committee = store.next_sync_committee.clone().unwrap();
        store
            .next_sync_committee
            .clone_from(&update.next_sync_committee);
        store.previous_max_active_participants = store.current_max_active_participants;
        store.current_max_active_participants = 0;
    }

    if update_finalized_slot > store.finalized_header.beacon().slot {
        store.finalized_header = update.finalized_header.clone().unwrap();

        if store.finalized_header.beacon().slot > store.optimistic_header.beacon().slot {
            store.optimistic_header = store.finalized_header.clone();
        }

        if store
            .finalized_header
            .beacon()
            .slot
            .is_multiple_of(S::slots_per_epoch())
        {
            let checkpoint = store.finalized_header.beacon().tree_hash_root();
            return Some(checkpoint);
        }
    }

    None
}

// implements checks from validate_light_client_update and process_light_client_update in the
// specification
pub fn verify_generic_update<S: ConsensusSpec>(
    update: &GenericUpdate<S>,
    expected_current_slot: u64,
    store: &LightClientStore<S>,
    genesis_root: B256,
    forks: &Forks,
) -> Result<()> {
    let bits = get_bits::<S>(&update.sync_aggregate.sync_committee_bits);
    if bits == 0 {
        return Err(ConsensusError::InsufficientParticipation.into());
    }

    if !is_valid_header::<S>(&update.attested_header, forks) {
        return Err(ConsensusError::InvalidExecutionPayloadProof.into());
    }

    let update_finalized_slot = update
        .finalized_header
        .clone()
        .map(|v| v.beacon().slot)
        .unwrap_or_default();

    let valid_time: bool = expected_current_slot >= update.signature_slot
        && update.signature_slot > update.attested_header.beacon().slot
        && update.attested_header.beacon().slot >= update_finalized_slot;

    if !valid_time {
        return Err(ConsensusError::InvalidTimestamp.into());
    }

    let store_period = calc_sync_period::<S>(store.finalized_header.beacon().slot);
    let update_sig_period = calc_sync_period::<S>(update.signature_slot);
    let valid_period = if store.next_sync_committee.is_some() {
        update_sig_period == store_period || update_sig_period == store_period + 1
    } else {
        update_sig_period == store_period
    };
    if !valid_period {
        return Err(ConsensusError::InvalidPeriod.into());
    }

    let update_attested_period = calc_sync_period::<S>(update.attested_header.beacon().slot);
    let update_has_next_committee = store.next_sync_committee.is_none()
        && update.next_sync_committee.is_some()
        && update_attested_period == store_period;

    if update.attested_header.beacon().slot <= store.finalized_header.beacon().slot
        && !update_has_next_committee
    {
        return Err(ConsensusError::NotRelevant.into());
    }

    let update_attested_epoch = update.attested_header.beacon().slot / S::slots_per_epoch();

    if let Some(finalized_header) = &update.finalized_header {
        if let Some(finality_branch) = &update.finality_branch {
            if !is_valid_header::<S>(finalized_header, forks) {
                return Err(ConsensusError::InvalidExecutionPayloadProof.into());
            }

            let is_valid = is_finality_proof_valid(
                update.attested_header.beacon(),
                finalized_header.beacon(),
                finality_branch,
                update_attested_epoch,
                forks,
            );

            if !is_valid {
                return Err(ConsensusError::InvalidFinalityProof.into());
            }
        } else {
            return Err(ConsensusError::InvalidFinalityProof.into());
        }
    }

    if let Some(next_sync_committee) = &update.next_sync_committee {
        if let Some(next_sync_committee_branch) = &update.next_sync_committee_branch {
            let is_valid = is_next_committee_proof_valid(
                update.attested_header.beacon(),
                next_sync_committee,
                next_sync_committee_branch,
                update_attested_epoch,
                forks,
            );

            if !is_valid {
                return Err(ConsensusError::InvalidNextSyncCommitteeProof.into());
            }
        } else {
            return Err(ConsensusError::InvalidNextSyncCommitteeProof.into());
        }
    }

    let sync_committee = if update_sig_period == store_period {
        &store.current_sync_committee
    } else {
        store.next_sync_committee.as_ref().unwrap()
    };

    let agg_pk = get_participating_aggregate_pubkey(
        sync_committee,
        &update.sync_aggregate.sync_committee_bits,
    )?;

    let fork_version = calculate_fork_version::<S>(forks, update.signature_slot.saturating_sub(1));
    let fork_data_root = compute_fork_data_root(fork_version, genesis_root);
    let is_valid_sig = verify_sync_committee_signature(
        &agg_pk,
        update.attested_header.beacon(),
        &update.sync_aggregate.sync_committee_signature,
        fork_data_root,
    );

    if !is_valid_sig {
        return Err(ConsensusError::InvalidSignature.into());
    }

    Ok(())
}

/// WARNING: `force_update` allows Helios to accept a header with less than a quorum of signatures.
/// Use with caution only in cases where it is not possible that valid updates are being censored.
pub fn force_update<S: ConsensusSpec>(store: &mut LightClientStore<S>, current_slot: u64) {
    if current_slot > store.finalized_header.beacon().slot + S::slots_per_sync_committee_period() {
        if let Some(mut best_valid_update) = store.best_valid_update.clone() {
            if best_valid_update
                .finalized_header
                .as_ref()
                .unwrap()
                .beacon()
                .slot
                <= store.finalized_header.beacon().slot
            {
                best_valid_update.finalized_header =
                    Some(best_valid_update.attested_header.clone());
            }
            apply_update_no_quorum_check(store, &best_valid_update);
            store.best_valid_update = None;
        }
    }
}

pub fn expected_current_slot(now: SystemTime, genesis_time: u64) -> u64 {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let since_genesis = now - genesis_time;

    since_genesis / 12
}

pub fn calc_sync_period<S: ConsensusSpec>(slot: u64) -> u64 {
    let epoch = slot / S::slots_per_epoch();
    epoch / S::epochs_per_sync_committee_period()
}

pub fn get_bits<S: ConsensusSpec>(bitfield: &BitVector<S::SyncCommitteeSize>) -> u64 {
    bitfield.iter().filter(|v| *v).count() as u64
}

fn is_better_update<S: ConsensusSpec>(
    new_update: &GenericUpdate<S>,
    old_update: &GenericUpdate<S>,
) -> bool {
    let max_active_participants = new_update.sync_aggregate.sync_committee_bits.len() as u64;
    let new_num_active_participants = get_bits::<S>(&new_update.sync_aggregate.sync_committee_bits);
    let old_num_active_participants = get_bits::<S>(&old_update.sync_aggregate.sync_committee_bits);
    let new_has_supermajority = new_num_active_participants * 3 >= max_active_participants * 2;
    let old_has_supermajority = old_num_active_participants * 3 >= max_active_participants * 2;

    if new_has_supermajority != old_has_supermajority {
        return new_has_supermajority;
    }

    if !new_has_supermajority && new_num_active_participants != old_num_active_participants {
        return new_num_active_participants > old_num_active_participants;
    }

    // compare presence of relevant sync committee
    let new_has_relevant_sync_committee = new_update.next_sync_committee_branch.is_some()
        && calc_sync_period::<S>(new_update.attested_header.beacon().slot)
            == calc_sync_period::<S>(new_update.signature_slot);
    let old_has_relevant_sync_committee = old_update.next_sync_committee_branch.is_some()
        && calc_sync_period::<S>(old_update.attested_header.beacon().slot)
            == calc_sync_period::<S>(old_update.signature_slot);
    if new_has_relevant_sync_committee != old_has_relevant_sync_committee {
        return new_has_relevant_sync_committee;
    }

    // compare indication of any finality
    let new_has_finality = new_update.finality_branch.is_some();
    let old_has_finality = old_update.finality_branch.is_some();
    if new_has_finality != old_has_finality {
        return new_has_finality;
    }

    // compare sync committee finality
    if new_has_finality {
        let new_has_sync_committee_finality =
            calc_sync_period::<S>(
                new_update
                    .finalized_header
                    .clone()
                    .unwrap_or_default()
                    .beacon()
                    .slot,
            ) == calc_sync_period::<S>(new_update.attested_header.beacon().slot);
        let old_has_sync_committee_finality =
            calc_sync_period::<S>(
                old_update
                    .finalized_header
                    .clone()
                    .unwrap_or_default()
                    .beacon()
                    .slot,
            ) == calc_sync_period::<S>(old_update.attested_header.beacon().slot);
        if new_has_sync_committee_finality != old_has_sync_committee_finality {
            return new_has_sync_committee_finality;
        }
    }

    // tiebreaker 1: Sync committee participation beyond supermajority
    if new_num_active_participants != old_num_active_participants {
        return new_num_active_participants > old_num_active_participants;
    }

    // tiebreaker 2: Prefer older data (fewer changes to best)
    if new_update.attested_header.beacon().slot != old_update.attested_header.beacon().slot {
        return new_update.attested_header.beacon().slot < old_update.attested_header.beacon().slot;
    }

    // tiebreaker 3: prefer updates with earlier signature slots
    new_update.signature_slot < old_update.signature_slot
}

fn has_sync_update<S: ConsensusSpec>(update: &GenericUpdate<S>) -> bool {
    update.next_sync_committee.is_some() && update.next_sync_committee_branch.is_some()
}

fn has_finality_update<S: ConsensusSpec>(update: &GenericUpdate<S>) -> bool {
    update.finality_branch.is_some()
}

fn verify_sync_committee_signature(
    aggregate_public_key: &bls12_381::G1Affine,
    attested_header: &BeaconBlockHeader,
    signature: &Signature,
    fork_data_root: B256,
) -> bool {
    let header_root = attested_header.tree_hash_root();
    let signing_root = compute_committee_sign_root(header_root, fork_data_root);
    signature.verify(signing_root.as_slice(), aggregate_public_key)
}

fn safety_threshold<S: ConsensusSpec>(store: &LightClientStore<S>) -> u64 {
    cmp::max(
        store.current_max_active_participants,
        store.previous_max_active_participants,
    ) / 2
}

/// Strict check for a header in the Gloas:EIP7732 representation: the received variant
/// carries the last executed execution block hash instead of the execution payload
/// header. `epoch` is the header's own authenticated epoch, so the proof gindex follows
/// the slot while the representation follows the received variant.
fn is_valid_gloas_header(header: &LightClientHeader, epoch: u64, forks: &Forks) -> bool {
    let (Ok(block_hash), Ok(branch)) = (
        header.execution_block_hash(),
        header.execution_branch_gloas(),
    ) else {
        return false;
    };

    match execution_block_hash_gindex_at_epoch(epoch, forks) {
        Some(gindex) => {
            is_execution_block_hash_proof_valid(header.beacon(), *block_hash, branch, gindex)
        }
        // [Modified in Gloas:EIP7732] Before Capella an upgraded header commits to no
        // executed payload, so both fields must be exact zeros.
        None => block_hash.is_zero() && branch.iter().all(B256::is_zero),
    }
}

fn is_valid_header<S: ConsensusSpec>(header: &LightClientHeader, forks: &Forks) -> bool {
    let epoch = header.beacon().slot / S::slots_per_epoch();

    // Gloas:EIP7732 replaces the execution payload header with the last executed
    // execution block hash. The representation is the received variant, so a header
    // upgraded from an earlier fork stays valid after the fork, while a legacy
    // payload-header representation is only valid before it.
    if epoch >= forks.gloas.epoch || header.execution_block_hash().is_ok() {
        return is_valid_gloas_header(header, epoch, forks);
    }

    // This deviates from the spec in that it dos not check that the blob fields are unset prior to
    // deneb. This is fine since an honest sync committee will never sign an invalid block, which
    // includes blocks that have the blob fields set pre-deneb.
    if epoch < forks.capella.epoch {
        header.execution().is_err() && header.execution_block_hash().is_err()
    } else if let (Ok(execution), Ok(execution_branch)) =
        (header.execution(), header.execution_branch())
    {
        is_execution_payload_proof_valid(header.beacon(), execution, execution_branch)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_spec::MinimalConsensusSpec;
    use crate::proof::{
        execution_block_hash_gindex_at_epoch, is_current_committee_proof_valid,
        is_finality_proof_valid, CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
        CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS, EXECUTION_BLOCK_HASH_GINDEX_CAPELLA,
        EXECUTION_BLOCK_HASH_GINDEX_DENEB, EXECUTION_BLOCK_HASH_GINDEX_GLOAS,
        EXECUTION_PAYLOAD_GINDEX, FINALIZED_ROOT_GINDEX_ELECTRA, FINALIZED_ROOT_GINDEX_GLOAS,
    };
    use crate::types::{
        BeaconBlockHeader, ExecutionPayloadHeader, Fork, LightClientHeaderDeneb,
        LightClientHeaderElectra, LightClientHeaderGloas, SyncCommittee,
    };
    use alloy::primitives::{fixed_bytes, B256};
    use sha2::{Digest, Sha256};
    use ssz_types::FixedVector;

    /// The consensus spec under test.
    type Spec = MinimalConsensusSpec;

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
                epoch: 0,
                fork_version: fixed_bytes!("05000001"),
            },
            fulu: Fork {
                epoch: 0,
                fork_version: fixed_bytes!("06000001"),
            },
            gloas: Fork {
                epoch: gloas_epoch,
                fork_version: fixed_bytes!("07000001"),
            },
        }
    }

    fn gloas_branch() -> Vec<B256> {
        (1..=11u8).map(B256::with_last_byte).collect()
    }

    fn gloas_header(
        slot: u64,
        execution_block_hash: B256,
        execution_branch: Vec<B256>,
        body_root: B256,
    ) -> LightClientHeader {
        gloas_header_with_state(
            slot,
            B256::ZERO,
            execution_block_hash,
            execution_branch,
            body_root,
        )
    }

    /// A Gloas-format header with an authenticated state root.
    fn gloas_header_with_state(
        slot: u64,
        state_root: B256,
        execution_block_hash: B256,
        execution_branch: Vec<B256>,
        body_root: B256,
    ) -> LightClientHeader {
        LightClientHeader::Gloas(LightClientHeaderGloas {
            beacon: BeaconBlockHeader {
                slot,
                state_root,
                body_root,
                ..Default::default()
            },
            execution_block_hash,
            execution_branch: FixedVector::from(execution_branch),
        })
    }

    /// A legacy pre-Gloas header that carries the execution payload header itself.
    fn legacy_header(
        slot: u64,
        execution: ExecutionPayloadHeader,
        execution_branch: Vec<B256>,
        body_root: B256,
    ) -> LightClientHeader {
        LightClientHeader::Deneb(LightClientHeaderDeneb {
            beacon: BeaconBlockHeader {
                slot,
                body_root,
                ..Default::default()
            },
            execution,
            execution_branch: FixedVector::from(execution_branch),
        })
    }

    /// The schedule under test: every pre-Gloas fork at its own epoch.
    fn schedule(
        capella_epoch: u64,
        deneb_epoch: u64,
        electra_epoch: u64,
        fulu_epoch: u64,
        gloas_epoch: u64,
    ) -> Forks {
        let mut forks = test_forks(gloas_epoch);
        forks.capella.epoch = capella_epoch;
        forks.deneb.epoch = deneb_epoch;
        forks.electra.epoch = electra_epoch;
        forks.fulu.epoch = fulu_epoch;
        forks
    }

    /// `floorlog2`: the depth of a generalized index.
    fn depth(gindex: usize) -> usize {
        usize::BITS as usize - 1 - gindex.leading_zeros() as usize
    }

    /// The block hash index inside the execution payload header, composed from the
    /// body-level index through `EXECUTION_PAYLOAD_GINDEX`.
    fn payload_header_gindex(body_gindex: usize) -> usize {
        let scale = 1usize << (depth(body_gindex) - depth(EXECUTION_PAYLOAD_GINDEX));
        scale + (body_gindex - EXECUTION_PAYLOAD_GINDEX * scale)
    }

    /// A normalized (Gloas-format) execution branch, as the Electra->Gloas upgrade of a
    /// pre-Gloas header produces it: the block hash is proven into the execution payload
    /// header at that fork's own gindex, the payload header into the body, and the branch
    /// is zero padded to the Gloas branch length.
    struct UpgradedExecution {
        block_hash: B256,
        payload_root: B256,
        body_root: B256,
        branch: Vec<B256>,
    }

    fn upgraded_execution(slot: u64, forks: &Forks, block_hash: B256) -> UpgradedExecution {
        let epoch = slot / Spec::slots_per_epoch();
        let body_gindex =
            execution_block_hash_gindex_at_epoch(epoch, forks).expect("a pre-Gloas fork");
        let payload_gindex = payload_header_gindex(body_gindex);

        let payload_proof: Vec<B256> = (1..=depth(payload_gindex) as u8)
            .map(|node| B256::with_last_byte(0x40 + node))
            .collect();
        let payload_root = fold(block_hash, &payload_proof, payload_gindex);

        let body_proof: Vec<B256> = (1..=4u8)
            .map(|node| B256::with_last_byte(0x60 + node))
            .collect();
        let body_root = fold(payload_root, &body_proof, EXECUTION_PAYLOAD_GINDEX);

        let padding = depth(EXECUTION_BLOCK_HASH_GINDEX_GLOAS) - depth(body_gindex);
        let mut branch = vec![B256::ZERO; padding];
        branch.extend(payload_proof);
        branch.extend(body_proof);

        UpgradedExecution {
            block_hash,
            payload_root,
            body_root,
            branch,
        }
    }

    fn pre_gloas_header(slot: u64) -> LightClientHeader {
        LightClientHeader::Electra(LightClientHeaderElectra {
            beacon: BeaconBlockHeader {
                slot,
                ..Default::default()
            },
            execution: ExecutionPayloadHeader::Electra(Default::default()),
            execution_branch: FixedVector::from(vec![B256::ZERO; 4]),
        })
    }

    #[test]
    fn gloas_header_is_accepted_at_and_after_the_fork() {
        let forks = test_forks(1);
        let first_slot = forks.gloas.epoch * Spec::slots_per_epoch();

        let execution_block_hash = B256::with_last_byte(0xaa);
        let branch = gloas_branch();
        let body_root = fold(execution_block_hash, &branch, EXECUTION_GINDEX);

        for slot in [first_slot, first_slot + 1] {
            let header = gloas_header(slot, execution_block_hash, branch.clone(), body_root);
            assert!(is_valid_header::<Spec>(&header, &forks));
        }
    }

    #[test]
    fn gloas_header_rejects_a_malformed_execution_branch() {
        let forks = test_forks(1);
        let slot = forks.gloas.epoch * Spec::slots_per_epoch();

        let execution_block_hash = B256::with_last_byte(0xaa);
        let branch = gloas_branch();
        let body_root = fold(execution_block_hash, &branch, EXECUTION_GINDEX);

        let mut tampered = branch.clone();
        tampered[5] = B256::with_last_byte(0xbb);
        let header = gloas_header(slot, execution_block_hash, tampered, body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));

        let wrong_hash = B256::with_last_byte(0xcc);
        let header = gloas_header(slot, wrong_hash, branch, body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn gloas_header_at_a_pre_fork_slot_uses_the_slot_gindex() {
        let forks = schedule(1, 2, 3, 4, 5);
        let slots_per_epoch = Spec::slots_per_epoch();

        // A Gloas-gindex (2856) branch cannot prove a pre-Gloas slot: its nodes sit above
        // the depth that slot selects and are not the zero padding the upgrade adds.
        let slot = (forks.gloas.epoch - 1) * slots_per_epoch;
        let execution_block_hash = B256::with_last_byte(0xaa);
        let branch = gloas_branch();
        let body_root = fold(execution_block_hash, &branch, EXECUTION_GINDEX);

        let header = gloas_header(slot, execution_block_hash, branch, body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));

        // A pre-Gloas header variant is rejected once the Gloas fork is active.
        let header = pre_gloas_header(forks.gloas.epoch * slots_per_epoch);
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn upgraded_gloas_header_is_valid_at_every_pre_fork_execution_fork() {
        let forks = schedule(1, 2, 3, 4, 5);
        let slots_per_epoch = Spec::slots_per_epoch();

        // Capella (gindex 412) and Deneb/Fulu (gindex 812) upgraded headers differ only
        // in how much zero padding the upgrade adds in front of the same shape.
        for (epoch, gindex, padding) in [
            (1u64, EXECUTION_BLOCK_HASH_GINDEX_CAPELLA, 3usize),
            (2, EXECUTION_BLOCK_HASH_GINDEX_DENEB, 2),
            (4, EXECUTION_BLOCK_HASH_GINDEX_DENEB, 2),
        ] {
            assert_eq!(
                execution_block_hash_gindex_at_epoch(epoch, &forks),
                Some(gindex)
            );

            let slot = epoch * slots_per_epoch;
            let execution = upgraded_execution(slot, &forks, B256::with_last_byte(0xaa));
            assert_eq!(execution.branch.len(), 11);
            assert!(execution.branch[..padding].iter().all(B256::is_zero));

            let header = gloas_header(
                slot,
                execution.block_hash,
                execution.branch,
                execution.body_root,
            );
            assert!(
                is_valid_header::<Spec>(&header, &forks),
                "an upgraded header at epoch {epoch} stays valid"
            );
            assert_eq!(
                get_lc_execution_root::<Spec>(&header, &forks),
                execution.payload_root,
                "the payload header root is recovered at epoch {epoch}"
            );
        }
    }

    #[test]
    fn upgraded_gloas_header_only_accepts_zero_padding() {
        let forks = schedule(1, 2, 3, 4, 5);
        let slots_per_epoch = Spec::slots_per_epoch();

        // The same branch, with a nonzero node where the upgrade writes padding.
        for (epoch, padding) in [(1u64, 3usize), (4, 2)] {
            let slot = epoch * slots_per_epoch;
            let execution = upgraded_execution(slot, &forks, B256::with_last_byte(0xaa));
            let mut tampered = vec![B256::with_last_byte(0xdd); padding];
            tampered.extend_from_slice(&execution.branch[padding..]);

            let header = gloas_header(slot, execution.block_hash, tampered, execution.body_root);
            assert!(
                !is_valid_header::<Spec>(&header, &forks),
                "nonzero padding at epoch {epoch} must be rejected"
            );
        }

        // A wrong block hash cannot be proven into the same body root.
        let slot = 4 * slots_per_epoch;
        let execution = upgraded_execution(slot, &forks, B256::with_last_byte(0xaa));
        let header = gloas_header(
            slot,
            B256::with_last_byte(0xbb),
            execution.branch.clone(),
            execution.body_root,
        );
        assert!(!is_valid_header::<Spec>(&header, &forks));

        // The branch is bound to the gindex its own slot selects: at a Gloas slot the
        // same normalized branch and body root must match gindex 2856 instead.
        let header = gloas_header(
            forks.gloas.epoch * slots_per_epoch,
            execution.block_hash,
            execution.branch,
            execution.body_root,
        );
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn upgraded_gloas_header_before_capella_requires_exact_zeros() {
        // Epoch 0 is pre-Capella in this schedule: the upgraded wire form commits to no
        // executed payload, so both execution fields must be exact zeros.
        let forks = schedule(1, 2, 3, 4, 5);
        let body_root = B256::with_last_byte(0xaa);

        let header = gloas_header(0, B256::ZERO, vec![B256::ZERO; 11], body_root);
        assert!(is_valid_header::<Spec>(&header, &forks));
        assert_eq!(get_lc_execution_root::<Spec>(&header, &forks), B256::ZERO);

        // A nonzero branch or block hash is not the upgraded Altair/Bellatrix shape.
        let header = gloas_header(0, B256::ZERO, gloas_branch(), body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));

        let header = gloas_header(
            0,
            B256::with_last_byte(0xaa),
            vec![B256::ZERO; 11],
            body_root,
        );
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn legacy_pre_gloas_header_validation_is_unchanged() {
        let forks = schedule(1, 2, 3, 4, 5);
        let slots_per_epoch = Spec::slots_per_epoch();

        // A legacy payload-header representation with a real four-node proof.
        let execution = ExecutionPayloadHeader::Deneb(Default::default());
        let branch: Vec<B256> = (1..=4u8).map(B256::with_last_byte).collect();
        let body_root = fold(
            execution.tree_hash_root(),
            &branch,
            EXECUTION_PAYLOAD_GINDEX,
        );

        for slot in [2 * slots_per_epoch, 4 * slots_per_epoch] {
            let header = legacy_header(slot, execution.clone(), branch.clone(), body_root);
            assert!(is_valid_header::<Spec>(&header, &forks));
        }

        // Before Capella only the shape without an execution payload header is valid.
        let header = legacy_header(0, execution.clone(), branch.clone(), body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));

        // Once Gloas is active the legacy representation is rejected even though its
        // execution payload header proof still verifies.
        let header = legacy_header(
            forks.gloas.epoch * slots_per_epoch,
            execution,
            branch,
            body_root,
        );
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn pre_gloas_header_validation_is_unchanged() {
        let forks = test_forks(u64::MAX);

        // The zero execution branch cannot prove an execution payload header.
        let header = pre_gloas_header(0);
        assert!(!is_valid_header::<Spec>(&header, &forks));

        // A Gloas-shaped header is rejected while Gloas is unscheduled: a pre-Capella
        // slot only accepts the exact-zero upgrade shape.
        let execution_block_hash = B256::with_last_byte(0xaa);
        let branch = gloas_branch();
        let body_root = fold(execution_block_hash, &branch, EXECUTION_GINDEX);
        let header = gloas_header(0, execution_block_hash, branch, body_root);
        assert!(!is_valid_header::<Spec>(&header, &forks));
    }

    #[test]
    fn normalized_finality_branch_is_accepted_before_the_fork() {
        let forks = schedule(1, 2, 3, 4, 5);
        let epoch = 4;
        let slots_per_epoch = Spec::slots_per_epoch();

        // A pre-Gloas attested slot still selects the Electra finality gindex (169,
        // depth 7), so the upgraded nine-node branch pads with two zero nodes.
        let finalized = BeaconBlockHeader {
            slot: epoch * slots_per_epoch,
            ..Default::default()
        };
        let proof: Vec<B256> = (1..=7u8)
            .map(|node| B256::with_last_byte(0xb0 + node))
            .collect();
        let mut branch = vec![B256::ZERO; 2];
        branch.extend(proof.clone());
        assert_eq!(branch.len(), 9);

        let attested = BeaconBlockHeader {
            state_root: fold(
                finalized.tree_hash_root(),
                &proof,
                FINALIZED_ROOT_GINDEX_ELECTRA,
            ),
            ..Default::default()
        };
        assert!(is_finality_proof_valid(
            &attested, &finalized, &branch, epoch, &forks
        ));

        // Nonzero padding above the gindex depth is not a valid normalization.
        let mut tampered = branch.clone();
        tampered[0] = B256::with_last_byte(0xee);
        assert!(!is_finality_proof_valid(
            &attested, &finalized, &tampered, epoch, &forks
        ));

        // A branch proving the Gloas gindex is not accepted before the fork.
        let attested_gloas = BeaconBlockHeader {
            state_root: fold(
                finalized.tree_hash_root(),
                &branch,
                FINALIZED_ROOT_GINDEX_GLOAS,
            ),
            ..Default::default()
        };
        assert!(!is_finality_proof_valid(
            &attested_gloas,
            &finalized,
            &branch,
            epoch,
            &forks
        ));
    }

    #[test]
    fn normalized_committee_branch_is_accepted_before_the_fork() {
        let forks = schedule(1, 2, 3, 4, 5);
        let epoch = 4;
        let slots_per_epoch = Spec::slots_per_epoch();

        // The upgraded Gloas-length committee branch pads the Electra proof (gindex 86,
        // depth 6) with five zero nodes.
        let committee = SyncCommittee::<Spec>::default();
        let proof: Vec<B256> = (1..=6u8)
            .map(|node| B256::with_last_byte(0xc0 + node))
            .collect();
        let mut branch = vec![B256::ZERO; 5];
        branch.extend(proof.clone());
        assert_eq!(branch.len(), 11);

        let attested = BeaconBlockHeader {
            slot: epoch * slots_per_epoch,
            state_root: fold(
                committee.tree_hash_root(),
                &proof,
                CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            ),
            ..Default::default()
        };
        assert!(is_current_committee_proof_valid::<Spec>(
            &attested, &committee, &branch, epoch, &forks
        ));

        let mut tampered = branch.clone();
        tampered[0] = B256::with_last_byte(0xee);
        assert!(!is_current_committee_proof_valid::<Spec>(
            &attested, &committee, &tampered, epoch, &forks
        ));

        // A branch proving the Gloas gindex is not accepted before the fork.
        let attested_gloas = BeaconBlockHeader {
            slot: epoch * slots_per_epoch,
            state_root: fold(
                committee.tree_hash_root(),
                &branch,
                CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
            ),
            ..Default::default()
        };
        assert!(!is_current_committee_proof_valid::<Spec>(
            &attested_gloas,
            &committee,
            &branch,
            epoch,
            &forks
        ));
    }

    #[test]
    fn post_fork_update_carries_an_upgraded_finalized_header() {
        let forks = schedule(1, 2, 3, 4, 5);
        let slots_per_epoch = Spec::slots_per_epoch();
        let attested_epoch = forks.gloas.epoch;

        // The attested header is at a Gloas slot; the finalized header it commits to is
        // an upgraded Fulu header, exactly as the fork document's upgrade produces one.
        let finalized_execution =
            upgraded_execution(4 * slots_per_epoch, &forks, B256::with_last_byte(0xaa));
        let finalized = gloas_header(
            4 * slots_per_epoch,
            finalized_execution.block_hash,
            finalized_execution.branch,
            finalized_execution.body_root,
        );

        // The finality branch has the Gloas length (nine nodes) and proves the finalized
        // beacon header into the attested state root at gindex 735.
        let finality_proof: Vec<B256> = (1..=9u8)
            .map(|node| B256::with_last_byte(0x80 + node))
            .collect();
        let attested_block_hash = B256::with_last_byte(0xbb);
        let attested_branch = gloas_branch();
        let attested = gloas_header_with_state(
            attested_epoch * slots_per_epoch,
            fold(
                finalized.beacon().tree_hash_root(),
                &finality_proof,
                FINALIZED_ROOT_GINDEX_GLOAS,
            ),
            attested_block_hash,
            attested_branch.clone(),
            fold(attested_block_hash, &attested_branch, EXECUTION_GINDEX),
        );

        assert!(is_valid_header::<Spec>(&attested, &forks));
        assert!(is_valid_header::<Spec>(&finalized, &forks));
        assert!(is_finality_proof_valid(
            attested.beacon(),
            finalized.beacon(),
            &finality_proof,
            attested_epoch,
            &forks,
        ));
    }
}
