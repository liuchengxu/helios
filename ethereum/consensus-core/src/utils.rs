use alloy::primitives::B256;
use eyre::Result;
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    consensus_spec::ConsensusSpec,
    types::{Forks, SyncCommittee},
};
use bls12_381::{G1Affine, G1Projective};

pub fn compute_committee_sign_root(header: B256, fork_data_root: B256) -> B256 {
    let domain_type = [7, 00, 00, 00];
    let domain = compute_domain(domain_type, fork_data_root);
    compute_signing_root(header, domain)
}

pub fn calculate_fork_version<S: ConsensusSpec>(
    forks: &Forks,
    slot: u64,
) -> FixedVector<u8, typenum::U4> {
    let epoch = slot / S::slots_per_epoch();

    let version = if epoch >= forks.gloas.epoch {
        forks.gloas.fork_version
    } else if epoch >= forks.fulu.epoch {
        forks.fulu.fork_version
    } else if epoch >= forks.electra.epoch {
        forks.electra.fork_version
    } else if epoch >= forks.deneb.epoch {
        forks.deneb.fork_version
    } else if epoch >= forks.capella.epoch {
        forks.capella.fork_version
    } else if epoch >= forks.bellatrix.epoch {
        forks.bellatrix.fork_version
    } else if epoch >= forks.altair.epoch {
        forks.altair.fork_version
    } else {
        forks.genesis.fork_version
    };

    FixedVector::from(version.as_slice().to_vec())
}

pub fn compute_fork_data_root(
    current_version: FixedVector<u8, typenum::U4>,
    genesis_validator_root: B256,
) -> B256 {
    let fork_data = ForkData {
        current_version,
        genesis_validator_root,
    };

    fork_data.tree_hash_root()
}

/// Computes the aggregate public key for the participating members of the sync committee.
/// with given participation bitfield and committee aggregate public key.
pub fn get_participating_aggregate_pubkey<S: ConsensusSpec>(
    committee: &SyncCommittee<S>,
    bitfield: &BitVector<S::SyncCommitteeSize>,
) -> Result<G1Affine> {
    let total = bitfield.len();
    let participating = bitfield.iter().filter(|b| *b).count();
    if participating == 0 {
        return Err(eyre::eyre!("no participating keys"));
    }

    if participating > total / 2 {
        let mut agg = G1Projective::from(committee.aggregate_pubkey.point()?);
        for (i, bit) in bitfield.iter().enumerate() {
            if !bit {
                agg -= G1Projective::from(committee.pubkeys[i].point()?);
            }
        }
        Ok(G1Affine::from(agg))
    } else {
        let mut agg = G1Projective::identity();
        for (i, bit) in bitfield.iter().enumerate() {
            if bit {
                agg += G1Projective::from(committee.pubkeys[i].point()?);
            }
        }
        Ok(G1Affine::from(agg))
    }
}

fn compute_signing_root(object_root: B256, domain: B256) -> B256 {
    let data = SigningData {
        object_root,
        domain,
    };

    data.tree_hash_root()
}

fn compute_domain(domain_type: [u8; 4], fork_data_root: B256) -> B256 {
    let start = &domain_type;
    let end = &fork_data_root[..28];
    let d = [start, end].concat();
    B256::from_slice(d.as_slice())
}

#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: B256,
    domain: B256,
}

#[derive(Default, Debug, TreeHash)]
struct ForkData {
    current_version: FixedVector<u8, typenum::U4>,
    genesis_validator_root: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_spec::MinimalConsensusSpec;
    use crate::types::Fork;
    use alloy::primitives::{fixed_bytes, FixedBytes};

    fn test_forks(electra_epoch: u64, fulu_epoch: u64, gloas_epoch: u64) -> Forks {
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
                epoch: fulu_epoch,
                fork_version: fixed_bytes!("06000001"),
            },
            gloas: Fork {
                epoch: gloas_epoch,
                fork_version: fixed_bytes!("07000001"),
            },
        }
    }

    fn as_version(bytes: FixedBytes<4>) -> FixedVector<u8, typenum::U4> {
        FixedVector::from(bytes.to_vec())
    }

    fn version_at(forks: &Forks, epoch: u64) -> FixedVector<u8, typenum::U4> {
        let slot = epoch * MinimalConsensusSpec::slots_per_epoch();
        calculate_fork_version::<MinimalConsensusSpec>(forks, slot)
    }

    #[test]
    fn fork_version_switches_to_gloas_at_the_fork_epoch() {
        let forks = test_forks(2, 4, 8);
        let fulu_version = as_version(forks.fulu.fork_version);
        let gloas_version = as_version(forks.gloas.fork_version);
        let last_fulu_epoch = forks.gloas.epoch - 1;

        // The signature domain is Fulu on the slot before the fork.
        assert_eq!(version_at(&forks, last_fulu_epoch), fulu_version);

        // Gloas signs the first slot of its fork epoch and every later slot.
        assert_eq!(version_at(&forks, forks.gloas.epoch), gloas_version);
        assert_eq!(version_at(&forks, forks.gloas.epoch + 1), gloas_version);
    }

    #[test]
    fn pre_gloas_fork_versions_are_unchanged() {
        let forks = test_forks(2, 4, 8);
        let deneb_version = as_version(forks.deneb.fork_version);
        let electra_version = as_version(forks.electra.fork_version);
        let fulu_version = as_version(forks.fulu.fork_version);
        let last_fulu_epoch = forks.gloas.epoch - 1;

        assert_eq!(version_at(&forks, 0), deneb_version);
        assert_eq!(version_at(&forks, 1), deneb_version);
        assert_eq!(version_at(&forks, forks.electra.epoch), electra_version);
        assert_eq!(version_at(&forks, forks.fulu.epoch), fulu_version);
        assert_eq!(version_at(&forks, last_fulu_epoch), fulu_version);
    }
}
