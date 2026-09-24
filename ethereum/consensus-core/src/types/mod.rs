use std::marker::PhantomData;

use alloy::primitives::{Address, FixedBytes, B256, U256};
use alloy_rlp::RlpEncodable;
use eyre::Result;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{serde_utils::quoted_u64_var_list, BitList, BitVector, FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::consensus_spec::ConsensusSpec;

use self::{
    bls::{PublicKey, Signature},
    bytes::{ByteList, ByteVector},
};

pub mod bls;
pub mod bytes;
mod serde_utils;

pub type LogsBloom = ByteVector<typenum::U256>;
pub type KZGCommitment = ByteVector<typenum::U48>;
pub type Transaction = ByteList<typenum::U1073741824>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LightClientStore<S: ConsensusSpec> {
    pub finalized_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<S>,
    pub next_sync_committee: Option<SyncCommittee<S>>,
    pub optimistic_header: LightClientHeader,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
    pub best_valid_update: Option<GenericUpdate<S>>,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
#[serde(bound = "S: ConsensusSpec")]
pub struct BeaconBlock<S: ConsensusSpec> {
    #[serde(with = "serde_utils::u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body: BeaconBlockBody<S>,
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(Deserialize, Clone, Debug, Encode, TreeHash, Default),
        serde(deny_unknown_fields),
        serde(bound = "S: ConsensusSpec"),
    )
)]
#[derive(Encode, TreeHash, Deserialize, Debug, Clone)]
#[serde(untagged)]
#[serde(bound = "S: ConsensusSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BeaconBlockBody<S: ConsensusSpec> {
    randao_reveal: Signature,
    eth1_data: Eth1Data,
    graffiti: B256,
    proposer_slashings: VariableList<ProposerSlashing, S::MaxProposerSlashings>,

    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "attester_slashings_base")
    )]
    attester_slashings: VariableList<AttesterSlashing<S>, S::MaxAttesterSlashings>,
    #[superstruct(only(Electra), partial_getter(rename = "attester_slashings_electra"))]
    attester_slashings: VariableList<AttesterSlashing<S>, S::MaxAttesterSlashingsElectra>,

    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "attestations_base")
    )]
    attestations: VariableList<Attestation<S>, S::MaxAttestations>,
    #[superstruct(only(Electra), partial_getter(rename = "attestations_electra"))]
    attestations: VariableList<Attestation<S>, S::MaxAttestationsElectra>,

    deposits: VariableList<Deposit, S::MaxDeposits>,
    voluntary_exits: VariableList<SignedVoluntaryExit, S::MaxVoluntaryExits>,
    sync_aggregate: SyncAggregate<S>,
    pub execution_payload: ExecutionPayload<S>,
    #[superstruct(only(Capella, Deneb, Electra))]
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, S::MaxBlsToExecutionChanged>,
    #[superstruct(only(Deneb, Electra))]
    blob_kzg_commitments: VariableList<KZGCommitment, S::MaxBlobKzgCommitments>,
    #[superstruct(only(Electra))]
    execution_requests: ExecutionRequests<S>,
}

impl<S: ConsensusSpec> Default for BeaconBlockBody<S> {
    fn default() -> Self {
        BeaconBlockBody::Electra(BeaconBlockBodyElectra::default())
    }
}

#[derive(Default, Clone, Debug, Encode, TreeHash, Deserialize)]
pub struct SignedBlsToExecutionChange {
    message: BlsToExecutionChange,
    signature: Signature,
}

#[derive(Default, Clone, Debug, Encode, TreeHash, Deserialize)]
pub struct BlsToExecutionChange {
    #[serde(with = "serde_utils::u64")]
    validator_index: u64,
    from_bls_pubkey: PublicKey,
    to_execution_address: Address,
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(Default, Debug, Deserialize, Encode, TreeHash, Clone),
        serde(deny_unknown_fields),
        serde(bound = "S: ConsensusSpec"),
    )
)]
#[derive(Debug, Deserialize, Clone, Encode, TreeHash)]
#[serde(untagged)]
#[serde(bound = "S: ConsensusSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload<S: ConsensusSpec> {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: LogsBloom,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64")]
    pub timestamp: u64,
    pub extra_data: ByteList<typenum::U32>,
    #[serde(with = "serde_utils::u256")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions: VariableList<Transaction, typenum::U1048576>,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub withdrawals: VariableList<Withdrawal, S::MaxWithdrawals>,
    #[superstruct(only(Deneb, Electra))]
    #[serde(with = "serde_utils::u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra))]
    #[serde(with = "serde_utils::u64")]
    pub excess_blob_gas: u64,
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    phantom: PhantomData<S>,
}

impl<S: ConsensusSpec> Default for ExecutionPayload<S> {
    fn default() -> Self {
        ExecutionPayload::<S>::Bellatrix(ExecutionPayloadBellatrix::<S>::default())
    }
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Serialize,
            Deserialize,
            Debug,
            Default,
            Encode,
            Decode,
            TreeHash,
            Clone,
            PartialEq
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: LogsBloom,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64")]
    pub timestamp: u64,
    pub extra_data: ByteList<typenum::U32>,
    #[serde(with = "serde_utils::u256")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions_root: B256,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub withdrawals_root: B256,
    #[superstruct(only(Deneb, Electra))]
    #[serde(with = "serde_utils::u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra))]
    #[serde(with = "serde_utils::u64")]
    pub excess_blob_gas: u64,
}

impl Default for ExecutionPayloadHeader {
    fn default() -> Self {
        ExecutionPayloadHeader::Bellatrix(ExecutionPayloadHeaderBellatrix::default())
    }
}

#[derive(Default, Clone, Debug, Encode, TreeHash, Deserialize, RlpEncodable)]
pub struct Withdrawal {
    #[serde(with = "serde_utils::u64")]
    index: u64,
    #[serde(with = "serde_utils::u64")]
    validator_index: u64,
    address: Address,
    #[serde(with = "serde_utils::u64")]
    amount: u64,
}

impl From<Withdrawal> for alloy::eips::eip4895::Withdrawal {
    fn from(value: Withdrawal) -> Self {
        alloy::eips::eip4895::Withdrawal {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address,
            amount: value.amount,
        }
    }
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
struct SignedBeaconBlockHeader {
    message: BeaconBlockHeader,
    signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Default, Encode, Decode, TreeHash, Clone, PartialEq)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
#[serde(bound = "S: ConsensusSpec")]
pub struct AttesterSlashing<S: ConsensusSpec> {
    attestation_1: IndexedAttestation<S>,
    attestation_2: IndexedAttestation<S>,
}

#[superstruct(
    variants(Electra, Base),
    variant_attributes(
        derive(Deserialize, Debug, Default, Encode, TreeHash, Clone,),
        serde(deny_unknown_fields),
    )
)]
#[derive(Deserialize, Debug, Encode, TreeHash, Clone)]
#[serde(bound = "S: ConsensusSpec")]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct IndexedAttestation<S: ConsensusSpec> {
    #[serde(with = "quoted_u64_var_list")]
    #[superstruct(only(Electra), partial_getter(rename = "attesting_indices_electra"))]
    attesting_indices: VariableList<u64, S::MaxValidatorsPerSlot>,
    #[serde(with = "quoted_u64_var_list")]
    #[superstruct(only(Base), partial_getter(rename = "attesting_indices_base"))]
    attesting_indices: VariableList<u64, S::MaxValidatorsPerCommittee>,
    data: AttestationData,
    signature: Signature,
}

impl<S: ConsensusSpec> Default for IndexedAttestation<S> {
    fn default() -> Self {
        IndexedAttestation::Electra(IndexedAttestationElectra::default())
    }
}

#[superstruct(
    variants(Electra, Base),
    variant_attributes(
        derive(Deserialize, Debug, Encode, TreeHash, Clone,),
        serde(deny_unknown_fields),
    )
)]
#[derive(Deserialize, Debug, Encode, TreeHash, Clone)]
#[serde(bound = "S: ConsensusSpec")]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct Attestation<S: ConsensusSpec> {
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    aggregation_bits: BitList<S::MaxValidatorsPerSlot>,
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    aggregation_bits: BitList<S::MaxValidatorsPerCommittee>,
    data: AttestationData,
    signature: Signature,
    #[superstruct(only(Electra))]
    committee_bits: BitVector<S::MaxCommitteesPerSlot>,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
struct AttestationData {
    #[serde(with = "serde_utils::u64")]
    slot: u64,
    #[serde(with = "serde_utils::u64")]
    index: u64,
    beacon_block_root: B256,
    source: Checkpoint,
    target: Checkpoint,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
struct Checkpoint {
    #[serde(with = "serde_utils::u64")]
    epoch: u64,
    root: B256,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct SignedVoluntaryExit {
    message: VoluntaryExit,
    signature: Signature,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
struct VoluntaryExit {
    #[serde(with = "serde_utils::u64")]
    epoch: u64,
    #[serde(with = "serde_utils::u64")]
    validator_index: u64,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct Deposit {
    proof: FixedVector<B256, typenum::U33>,
    data: DepositData,
}

#[derive(Deserialize, Default, Debug, Encode, TreeHash, Clone)]
struct DepositData {
    pubkey: PublicKey,
    withdrawal_credentials: B256,
    #[serde(with = "serde_utils::u64")]
    amount: u64,
    signature: Signature,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct Eth1Data {
    deposit_root: B256,
    #[serde(with = "serde_utils::u64")]
    deposit_count: u64,
    block_hash: B256,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct ExecutionRequests<S: ConsensusSpec> {
    deposits: VariableList<DepositRequest, S::MaxDepositRequests>,
    withdrawals: VariableList<WithdrawalRequest, S::MaxWithdrawalRequests>,
    consolidations: VariableList<ConsolidationRequest, S::MaxConsolidationRequests>,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct DepositRequest {
    pubkey: PublicKey,
    withdrawal_credentials: B256,
    #[serde(with = "serde_utils::u64")]
    amount: u64,
    signature: Signature,
    #[serde(with = "serde_utils::u64")]
    index: u64,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct WithdrawalRequest {
    source_address: Address,
    validator_pubkey: PublicKey,
    #[serde(with = "serde_utils::u64")]
    amount: u64,
}

#[derive(Deserialize, Debug, Default, Encode, TreeHash, Clone)]
pub struct ConsolidationRequest {
    source_address: Address,
    source_pubkey: PublicKey,
    target_pubkey: PublicKey,
}

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(
        derive(Deserialize, Debug),
        serde(deny_unknown_fields),
        serde(bound = "S: ConsensusSpec"),
    ),
    specific_variant_attributes(Base(derive(Decode)), Electra(derive(Decode)))
)]
#[derive(Deserialize, Debug, Decode)]
#[serde(untagged)]
#[serde(bound = "S: ConsensusSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct Bootstrap<S: ConsensusSpec> {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<S>,
    #[superstruct(
        only(Base),
        partial_getter(rename = "current_sync_committee_branch_base")
    )]
    pub current_sync_committee_branch: FixedVector<B256, typenum::U5>,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "current_sync_committee_branch_electra")
    )]
    pub current_sync_committee_branch: FixedVector<B256, typenum::U6>,
    #[superstruct(
        only(Gloas),
        partial_getter(rename = "current_sync_committee_branch_gloas")
    )]
    pub current_sync_committee_branch: FixedVector<B256, typenum::U11>,
}

impl<S: ConsensusSpec> Bootstrap<S> {
    pub fn current_sync_committee_branch(&self) -> &[B256] {
        match self {
            Bootstrap::Base(inner) => &inner.current_sync_committee_branch,
            Bootstrap::Electra(inner) => &inner.current_sync_committee_branch,
            Bootstrap::Gloas(inner) => &inner.current_sync_committee_branch,
        }
    }
}

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(
        derive(Serialize, Deserialize, Debug, Clone),
        serde(deny_unknown_fields),
        serde(bound = "S: ConsensusSpec"),
    ),
    specific_variant_attributes(Base(derive(Decode)), Electra(derive(Decode)))
)]
#[derive(Serialize, Deserialize, Debug, Clone, Decode)]
#[serde(untagged)]
#[serde(bound = "S: ConsensusSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct Update<S: ConsensusSpec> {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee<S>,
    #[superstruct(only(Base), partial_getter(rename = "next_sync_committee_branch_base"))]
    pub next_sync_committee_branch: FixedVector<B256, typenum::U5>,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "next_sync_committee_branch_electra")
    )]
    pub next_sync_committee_branch: FixedVector<B256, typenum::U6>,
    #[superstruct(
        only(Gloas),
        partial_getter(rename = "next_sync_committee_branch_gloas")
    )]
    pub next_sync_committee_branch: FixedVector<B256, typenum::U11>,
    pub finalized_header: LightClientHeader,
    #[superstruct(only(Base), partial_getter(rename = "finality_branch_base"))]
    pub finality_branch: FixedVector<B256, typenum::U6>,
    #[superstruct(only(Electra), partial_getter(rename = "finality_branch_electra"))]
    pub finality_branch: FixedVector<B256, typenum::U7>,
    #[superstruct(only(Gloas), partial_getter(rename = "finality_branch_gloas"))]
    pub finality_branch: FixedVector<B256, typenum::U9>,
    pub sync_aggregate: SyncAggregate<S>,
    #[serde(with = "serde_utils::u64")]
    pub signature_slot: u64,
}

impl<S: ConsensusSpec> Update<S> {
    pub fn next_sync_committee_branch(&self) -> &[B256] {
        match self {
            Update::Base(inner) => &inner.next_sync_committee_branch,
            Update::Electra(inner) => &inner.next_sync_committee_branch,
            Update::Gloas(inner) => &inner.next_sync_committee_branch,
        }
    }

    pub fn finality_branch(&self) -> &[B256] {
        match self {
            Update::Base(inner) => &inner.finality_branch,
            Update::Electra(inner) => &inner.finality_branch,
            Update::Gloas(inner) => &inner.finality_branch,
        }
    }
}

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(
        derive(Serialize, Deserialize, Debug, Clone),
        serde(deny_unknown_fields),
        serde(bound = "S: ConsensusSpec"),
    ),
    specific_variant_attributes(Base(derive(Decode)), Electra(derive(Decode)))
)]
#[derive(Serialize, Deserialize, Debug, Clone, Decode)]
#[serde(untagged)]
#[serde(bound = "S: ConsensusSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct FinalityUpdate<S: ConsensusSpec> {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    #[superstruct(only(Base), partial_getter(rename = "finality_branch_base"))]
    pub finality_branch: FixedVector<B256, typenum::U6>,
    #[superstruct(only(Electra), partial_getter(rename = "finality_branch_electra"))]
    pub finality_branch: FixedVector<B256, typenum::U7>,
    #[superstruct(only(Gloas), partial_getter(rename = "finality_branch_gloas"))]
    pub finality_branch: FixedVector<B256, typenum::U9>,
    pub sync_aggregate: SyncAggregate<S>,
    #[serde(with = "serde_utils::u64")]
    pub signature_slot: u64,
}

impl<S: ConsensusSpec> FinalityUpdate<S> {
    pub fn finality_branch(&self) -> &[B256] {
        match self {
            FinalityUpdate::Base(inner) => &inner.finality_branch,
            FinalityUpdate::Electra(inner) => &inner.finality_branch,
            FinalityUpdate::Gloas(inner) => &inner.finality_branch,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "S: ConsensusSpec")]
pub struct OptimisticUpdate<S: ConsensusSpec> {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate<S>,
    #[serde(with = "serde_utils::u64")]
    pub signature_slot: u64,
}

// The Gloas light client header is a fixed-size SSZ container that the enclosing
// containers inline. The shared `LightClientHeader` enum is variable-size, so the Gloas
// containers decode through these layouts, which hold the concrete Gloas header.

#[derive(Decode)]
struct BootstrapGloasSsz<S: ConsensusSpec> {
    header: LightClientHeaderGloas,
    current_sync_committee: SyncCommittee<S>,
    current_sync_committee_branch: FixedVector<B256, typenum::U11>,
}

#[derive(Decode)]
struct UpdateGloasSsz<S: ConsensusSpec> {
    attested_header: LightClientHeaderGloas,
    next_sync_committee: SyncCommittee<S>,
    next_sync_committee_branch: FixedVector<B256, typenum::U11>,
    finalized_header: LightClientHeaderGloas,
    finality_branch: FixedVector<B256, typenum::U9>,
    sync_aggregate: SyncAggregate<S>,
    signature_slot: u64,
}

#[derive(Decode)]
struct FinalityUpdateGloasSsz<S: ConsensusSpec> {
    attested_header: LightClientHeaderGloas,
    finalized_header: LightClientHeaderGloas,
    finality_branch: FixedVector<B256, typenum::U9>,
    sync_aggregate: SyncAggregate<S>,
    signature_slot: u64,
}

#[derive(Decode)]
struct OptimisticUpdateSsz<S: ConsensusSpec> {
    attested_header: LightClientHeader,
    sync_aggregate: SyncAggregate<S>,
    signature_slot: u64,
}

#[derive(Decode)]
struct OptimisticUpdateGloasSsz<S: ConsensusSpec> {
    attested_header: LightClientHeaderGloas,
    sync_aggregate: SyncAggregate<S>,
    signature_slot: u64,
}

impl<S: ConsensusSpec> ssz::Decode for BootstrapGloas<S> {
    fn is_ssz_fixed_len() -> bool {
        <BootstrapGloasSsz<S> as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <BootstrapGloasSsz<S> as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let layout = <BootstrapGloasSsz<S> as ssz::Decode>::from_ssz_bytes(bytes)?;
        Ok(Self {
            header: LightClientHeader::Gloas(layout.header),
            current_sync_committee: layout.current_sync_committee,
            current_sync_committee_branch: layout.current_sync_committee_branch,
        })
    }
}

impl<S: ConsensusSpec> ssz::Decode for UpdateGloas<S> {
    fn is_ssz_fixed_len() -> bool {
        <UpdateGloasSsz<S> as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <UpdateGloasSsz<S> as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let layout = <UpdateGloasSsz<S> as ssz::Decode>::from_ssz_bytes(bytes)?;
        Ok(Self {
            attested_header: LightClientHeader::Gloas(layout.attested_header),
            next_sync_committee: layout.next_sync_committee,
            next_sync_committee_branch: layout.next_sync_committee_branch,
            finalized_header: LightClientHeader::Gloas(layout.finalized_header),
            finality_branch: layout.finality_branch,
            sync_aggregate: layout.sync_aggregate,
            signature_slot: layout.signature_slot,
        })
    }
}

impl<S: ConsensusSpec> ssz::Decode for FinalityUpdateGloas<S> {
    fn is_ssz_fixed_len() -> bool {
        <FinalityUpdateGloasSsz<S> as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <FinalityUpdateGloasSsz<S> as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let layout = <FinalityUpdateGloasSsz<S> as ssz::Decode>::from_ssz_bytes(bytes)?;
        Ok(Self {
            attested_header: LightClientHeader::Gloas(layout.attested_header),
            finalized_header: LightClientHeader::Gloas(layout.finalized_header),
            finality_branch: layout.finality_branch,
            sync_aggregate: layout.sync_aggregate,
            signature_slot: layout.signature_slot,
        })
    }
}

impl<S: ConsensusSpec> ssz::Decode for OptimisticUpdate<S> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    /// The Gloas layout is selected by its exact fixed length. A pre-Gloas layout cannot
    /// have that length: in place of the 496-byte Gloas header it holds a 4-byte offset
    /// plus either the 112-byte beacon-only header or a header that carries a full
    /// execution payload header (at least 780 bytes).
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() == <OptimisticUpdateGloasSsz<S> as ssz::Decode>::ssz_fixed_len() {
            let layout = <OptimisticUpdateGloasSsz<S> as ssz::Decode>::from_ssz_bytes(bytes)?;
            return Ok(Self {
                attested_header: LightClientHeader::Gloas(layout.attested_header),
                sync_aggregate: layout.sync_aggregate,
                signature_slot: layout.signature_slot,
            });
        }

        let layout = <OptimisticUpdateSsz<S> as ssz::Decode>::from_ssz_bytes(bytes)?;
        Ok(Self {
            attested_header: layout.attested_header,
            sync_aggregate: layout.sync_aggregate,
            signature_slot: layout.signature_slot,
        })
    }
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Gloas),
    variant_attributes(
        derive(Default, Debug, Clone, Serialize, Deserialize, Decode, PartialEq),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Decode, PartialEq)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub execution: ExecutionPayloadHeader,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub execution_branch: FixedVector<B256, typenum::U4>,
    /// Gloas:EIP7732 drops `execution` and carries the last executed execution block
    /// hash, proven into `BeaconBlockBody` at `EXECUTION_BLOCK_HASH_GINDEX_GLOAS`.
    #[superstruct(only(Gloas))]
    pub execution_block_hash: B256,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_branch_gloas"))]
    pub execution_branch: FixedVector<B256, typenum::U11>,
}

impl Default for LightClientHeader {
    fn default() -> Self {
        LightClientHeader::Bellatrix(LightClientHeaderBellatrix::default())
    }
}

#[derive(Debug, Clone, Default, Encode, TreeHash, Serialize, Deserialize, Decode, PartialEq)]
pub struct SyncCommittee<S: ConsensusSpec> {
    pub pubkeys: FixedVector<PublicKey, S::SyncCommitteeSize>,
    pub aggregate_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Encode, Decode, TreeHash)]
pub struct SyncAggregate<S: ConsensusSpec> {
    pub sync_committee_bits: BitVector<S::SyncCommitteeSize>,
    pub sync_committee_signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Forks {
    pub genesis: Fork,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
    pub deneb: Fork,
    pub electra: Fork,
    pub fulu: Fork,
    #[serde(default = "unscheduled_fork")]
    pub gloas: Fork,
}

impl Default for Forks {
    fn default() -> Self {
        Self {
            genesis: Fork::default(),
            altair: Fork::default(),
            bellatrix: Fork::default(),
            capella: Fork::default(),
            deneb: Fork::default(),
            electra: Fork::default(),
            fulu: Fork::default(),
            gloas: unscheduled_fork(),
        }
    }
}

/// A fork that never activates. Gloas:EIP7732 stays inactive until its fork epoch is
/// configured, including in schedules serialized before the `gloas` field existed.
fn unscheduled_fork() -> Fork {
    Fork {
        epoch: u64::MAX,
        fork_version: FixedBytes::ZERO,
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Fork {
    pub epoch: u64,
    pub fork_version: FixedBytes<4>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GenericUpdate<S: ConsensusSpec> {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate<S>,
    pub signature_slot: u64,
    pub next_sync_committee: Option<SyncCommittee<S>>,
    pub next_sync_committee_branch: Option<Vec<B256>>,
    pub finalized_header: Option<LightClientHeader>,
    pub finality_branch: Option<Vec<B256>>,
}

impl<S: ConsensusSpec> From<&Update<S>> for GenericUpdate<S> {
    fn from(update: &Update<S>) -> Self {
        Self {
            attested_header: update.attested_header().clone(),
            sync_aggregate: update.sync_aggregate().clone(),
            signature_slot: *update.signature_slot(),
            next_sync_committee: default_to_none(update.next_sync_committee().clone()),
            next_sync_committee_branch: default_branch_to_none(update.next_sync_committee_branch()),
            finalized_header: default_header_to_none(update.finalized_header().clone()),
            finality_branch: default_branch_to_none(update.finality_branch()),
        }
    }
}

impl<S: ConsensusSpec> From<&FinalityUpdate<S>> for GenericUpdate<S> {
    fn from(update: &FinalityUpdate<S>) -> Self {
        Self {
            attested_header: update.attested_header().clone(),
            sync_aggregate: update.sync_aggregate().clone(),
            signature_slot: *update.signature_slot(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: default_header_to_none(update.finalized_header().clone()),
            finality_branch: default_branch_to_none(update.finality_branch()),
        }
    }
}

impl<S: ConsensusSpec> From<&OptimisticUpdate<S>> for GenericUpdate<S> {
    fn from(update: &OptimisticUpdate<S>) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: None,
            finality_branch: None,
        }
    }
}

fn default_to_none<T: Default + PartialEq>(value: T) -> Option<T> {
    if value == T::default() {
        None
    } else {
        Some(value)
    }
}

fn default_branch_to_none(value: &[B256]) -> Option<Vec<B256>> {
    for elem in value {
        if !elem.is_zero() {
            return Some(value.to_vec());
        }
    }

    None
}

fn default_header_to_none(value: LightClientHeader) -> Option<LightClientHeader> {
    match &value {
        LightClientHeader::Bellatrix(header) => {
            if header.beacon == BeaconBlockHeader::default() {
                None
            } else {
                Some(value)
            }
        }
        LightClientHeader::Capella(header) => match &header.execution {
            ExecutionPayloadHeader::Bellatrix(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderBellatrix::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Capella(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderCapella::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Deneb(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderDeneb::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Electra(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderElectra::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
        },
        LightClientHeader::Deneb(header) => match &header.execution {
            ExecutionPayloadHeader::Bellatrix(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderBellatrix::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Capella(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderCapella::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Deneb(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderDeneb::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Electra(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderElectra::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
        },
        LightClientHeader::Electra(header) => match &header.execution {
            ExecutionPayloadHeader::Bellatrix(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderBellatrix::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Capella(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderCapella::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Deneb(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderDeneb::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
            ExecutionPayloadHeader::Electra(payload_header) => {
                let is_default = header.beacon == BeaconBlockHeader::default()
                    && payload_header == &ExecutionPayloadHeaderElectra::default();

                if is_default {
                    None
                } else {
                    Some(value)
                }
            }
        },
        LightClientHeader::Gloas(header) => {
            let is_default = header.beacon == BeaconBlockHeader::default()
                && header.execution_block_hash.is_zero()
                && header.execution_branch.iter().all(B256::is_zero);

            if is_default {
                None
            } else {
                Some(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_spec::MinimalConsensusSpec;

    fn gloas_header(slot: u64, execution_block_hash: B256) -> LightClientHeader {
        LightClientHeader::Gloas(LightClientHeaderGloas {
            beacon: BeaconBlockHeader {
                slot,
                ..Default::default()
            },
            execution_block_hash,
            execution_branch: FixedVector::from(vec![B256::ZERO; 11]),
        })
    }

    /// A fork schedule serialized before the `gloas` field existed still loads, with
    /// Gloas unscheduled and every earlier fork unchanged.
    #[test]
    fn forks_without_gloas_deserialize_with_gloas_unscheduled() {
        let json = r#"{
            "genesis": {"epoch": 0, "fork_version": "0x00000001"},
            "altair": {"epoch": 1, "fork_version": "0x01000001"},
            "bellatrix": {"epoch": 2, "fork_version": "0x02000001"},
            "capella": {"epoch": 3, "fork_version": "0x03000001"},
            "deneb": {"epoch": 4, "fork_version": "0x04000001"},
            "electra": {"epoch": 5, "fork_version": "0x05000001"},
            "fulu": {"epoch": 6, "fork_version": "0x06000001"}
        }"#;
        let forks: Forks = serde_json::from_str(json).unwrap();

        assert_eq!(forks.gloas.epoch, u64::MAX);
        assert_eq!(forks.gloas.fork_version, FixedBytes::<4>::ZERO);
        assert_eq!(forks.genesis.fork_version, FixedBytes::from([0, 0, 0, 1]));
        assert_eq!(forks.deneb.epoch, 4);
        assert_eq!(forks.fulu.epoch, 6);
        assert_eq!(forks.fulu.fork_version, FixedBytes::from([6, 0, 0, 1]));
        assert_eq!(Forks::default().gloas.epoch, u64::MAX);

        // An explicit Gloas entry is kept.
        let json = json.replace(
            r#""fulu": {"epoch": 6, "fork_version": "0x06000001"}"#,
            r#""fulu": {"epoch": 6, "fork_version": "0x06000001"},
            "gloas": {"epoch": 7, "fork_version": "0x07000001"}"#,
        );
        let forks: Forks = serde_json::from_str(&json).unwrap();
        assert_eq!(forks.gloas.epoch, 7);
        assert_eq!(forks.gloas.fork_version, FixedBytes::from([7, 0, 0, 1]));
    }

    /// An upgraded pre-fork finalized header is not the empty header, so a Gloas update
    /// must carry it (and its finality proof) instead of dropping it as absent. The
    /// empty header and the empty sync committee stay absent.
    #[test]
    fn gloas_update_carries_an_upgraded_pre_fork_finalized_header() {
        let update = Update::<MinimalConsensusSpec>::Gloas(UpdateGloas {
            attested_header: gloas_header(40, B256::with_last_byte(0xaa)),
            next_sync_committee: SyncCommittee::default(),
            next_sync_committee_branch: FixedVector::from(vec![B256::ZERO; 11]),
            // Pre-Capella upgrade shape: no executed payload committed yet.
            finalized_header: gloas_header(24, B256::ZERO),
            finality_branch: FixedVector::from(vec![B256::with_last_byte(1); 9]),
            sync_aggregate: SyncAggregate::default(),
            signature_slot: 41,
        });

        let generic = GenericUpdate::<MinimalConsensusSpec>::from(&update);

        assert!(generic.finalized_header.is_some());
        assert!(generic.finality_branch.is_some());
        assert!(generic.next_sync_committee.is_none());
        assert!(generic.next_sync_committee_branch.is_none());
    }
}
