use bellman::{
    SynthesisError,
    ConstraintSystem
};

use bellman::pairing::{
    Engine
};

use bellman::pairing::bn256::{Bn256, Fr};


use fawkes_crypto::circuit::signal::{Signal};
use fawkes_crypto::ecc::{JubJubParams, JubJubBN256};
use fawkes_crypto::poseidon::{PoseidonParams};
use fawkes_crypto::circuit::poseidon::{poseidon, poseidon_merkle_root};
use fawkes_crypto::circuit::eddsaposeidon::eddsaposeidon_verify;

use fawkes_crypto::circuit::bitify::{into_bits_le};



pub const PROOF_LENGTH:usize = 32;
pub const AMOUNT_LENGTH:usize = 64;
pub const N_TXS:usize = 1024;

#[derive(Clone)]
pub struct Leaf<E:Engine> {
    pub owner: Signal<E>,
    pub amount: Signal<E>,
    pub nonce: Signal<E>
}

impl<E:Engine> Leaf<E> {
    pub fn hash<CS:ConstraintSystem<E>>(&self, mut cs: CS, poseidon_params4: &PoseidonParams<E::Fr>) -> Result<Signal<E>, SynthesisError> {
        poseidon(cs.namespace(||"hash"), &[self.owner.clone(), self.amount.clone(), self.nonce.clone()], poseidon_params4)
    }
}

#[derive(Clone)]
pub struct Tx<E:Engine> {
    pub from: Signal<E>,
    pub to: Signal<E>,
    pub amount: Signal<E>,
    pub nonce: Signal<E>,
    pub s: Signal<E>,
    pub r: Signal<E>
}

impl<E:Engine> Tx<E> {
    pub fn hash<CS:ConstraintSystem<E>>(&self, mut cs: CS, tx_hash_params: &PoseidonParams<E::Fr>)
    -> Result<Signal<E>, SynthesisError> {
        poseidon(cs.namespace(||"hash"), &[self.from.clone(), self.to.clone(), self.amount.clone(), self.nonce.clone()], tx_hash_params)
    }

    pub fn sigverify<CS:ConstraintSystem<E>, J:JubJubParams<E>>(&self, mut cs:CS, owner:&Signal<E>, p: &RollupParams<E,J>)
    -> Result<Signal<E>, SynthesisError> {
        let m = self.hash(cs.namespace(||"m"), &p.poseidon_params5)?;
        eddsaposeidon_verify(cs.namespace(||"sigverify"), &self.s, &self.r, owner, &m, &p.poseidon_params4, &p.jubjub_params)
    }
}

#[derive(Clone)]
pub struct TxEx<E:Engine> {
    pub leaf_from: Leaf<E>,
    pub leaf_to: Leaf<E>,
    pub proof_from_before: Vec<Signal<E>>,
    pub proof_from_after: Vec<Signal<E>>,
    pub proof_to_before: Vec<Signal<E>>,
    pub proof_to_after: Vec<Signal<E>>
}

pub struct RollupParams<E:Engine, J:JubJubParams<E>> {
    pub poseidon_params3 : PoseidonParams<E::Fr>,
    pub poseidon_params4 : PoseidonParams<E::Fr>,
    pub poseidon_params5 : PoseidonParams<E::Fr>,
    pub jubjub_params: J
}

impl RollupParams<Bn256,JubJubBN256> {
    pub fn new() -> Self {
        Self {
            poseidon_params3: PoseidonParams::<Fr>::new(3, 8, 53),
            poseidon_params4: PoseidonParams::<Fr>::new(4, 8, 54),
            poseidon_params5: PoseidonParams::<Fr>::new(5, 8, 54),
            jubjub_params: JubJubBN256::new()
        }
    }
}

// returns root_after
pub fn transaction<E:Engine, CS:ConstraintSystem<E>, J:JubJubParams<E>>(
    mut cs:CS,
    tx: &Tx<E>,
    ex: &TxEx<E>,
    root_before: &Signal<E>,
    params: &RollupParams<E,J>
) -> Result<Signal<E>, SynthesisError> {
    assert!(PROOF_LENGTH==ex.proof_from_before.len() 
        && PROOF_LENGTH==ex.proof_from_after.len()
        && PROOF_LENGTH==ex.proof_to_before.len()
        && PROOF_LENGTH==ex.proof_to_after.len()
    );

    // TODO remove comment
    //(&ex.leaf_from.nonce-&tx.nonce).assert_zero(cs.namespace(||"check nonce"))?;
    
    let _sigverify = tx.sigverify(cs.namespace(||"sigverify"), &ex.leaf_from.owner, &params)?;
    
    // TODO remove comment
    //_sigverify.assert_constant(cs.namespace(||"should be one"), Wrap::one())?;
    
    into_bits_le(cs.namespace(||"limit amount tx"), &tx.amount, AMOUNT_LENGTH)?; 

    let path_from = into_bits_le(cs.namespace(||"leaf_from_path"), &tx.from, PROOF_LENGTH)?;
    let path_to = into_bits_le(cs.namespace(||"leaf_to_path"), &tx.to, PROOF_LENGTH)?;

    into_bits_le(cs.namespace(||"limit amount from before"), &ex.leaf_from.amount, AMOUNT_LENGTH)?;  
    
    let leaf_from_before_hash = ex.leaf_from.hash(cs.namespace(||"leaf_from_before_hash"), &params.poseidon_params4)?;
    let root_before2 = poseidon_merkle_root(cs.namespace(||"root_before2"), &leaf_from_before_hash, &ex.proof_from_before, &path_from, &params.poseidon_params3)?;
    
    // TODO remove comment
    //(&root_before2 - root_before).assert_zero(cs.namespace(||"check root_before2"))?;
    root_before.assert_nonzero(cs.namespace(|| "dummy root_before"))?;
    root_before2.assert_nonzero(cs.namespace(|| "dummy root_before2"))?;
    

    let mut leaf_from_after = ex.leaf_from.clone();
    leaf_from_after.amount = leaf_from_after.amount - &tx.amount;
    leaf_from_after.nonce = leaf_from_after.nonce + Signal::one();

    into_bits_le(cs.namespace(||"limit amount from after"), &leaf_from_after.amount, AMOUNT_LENGTH)?;
    let leaf_from_after_hash = leaf_from_after.hash(cs.namespace(||"leaf_from_after_hash"), &params.poseidon_params4)?;
    let root_after = poseidon_merkle_root(cs.namespace(||"root_after"), &leaf_from_after_hash, &ex.proof_from_after, &path_from, &params.poseidon_params3)?;

    into_bits_le(cs.namespace(||"limit amount to before"), &ex.leaf_to.amount, AMOUNT_LENGTH)?; 
    
    let leaf_to_before_hash = ex.leaf_to.hash(cs.namespace(||"leaf_to_before_hash"), &params.poseidon_params4)?;
    let root_after2 = poseidon_merkle_root(cs.namespace(||"root_after2"), &leaf_to_before_hash, &ex.proof_to_before, &path_to, &params.poseidon_params3)?;
    
    // TODO remove comment
    //(&root_after2 - root_after).assert_zero(cs.namespace(||"check root_after2"))?;
    root_after.assert_nonzero(cs.namespace(|| "dummy root_after"))?;
    root_after2.assert_nonzero(cs.namespace(|| "dummy root_after2"))?;


    let mut leaf_to_after = ex.leaf_to.clone();
    leaf_to_after.amount = leaf_to_after.amount + &tx.amount;
    into_bits_le(cs.namespace(||"limit amount to after"), &leaf_to_after.amount, AMOUNT_LENGTH)?;

    let leaf_to_after_hash = leaf_to_after.hash(cs.namespace(||"leaf_to_after_hash"), &params.poseidon_params4)?;
    poseidon_merkle_root(cs.namespace(||"root_final"), &leaf_to_after_hash, &ex.proof_to_after, &path_to, &params.poseidon_params3)
}


pub fn rollup<E:Engine, CS:ConstraintSystem<E>, J:JubJubParams<E>>(
    mut cs: CS,
    txs:&[Tx<E>],
    exs:&[TxEx<E>],
    root_before: &Signal<E>,
    params: &RollupParams<E,J>
) -> Result<Signal<E>, SynthesisError> {
    assert!(txs.len()==N_TXS && exs.len()==N_TXS);
    let mut root = root_before.clone();
    for i in 0..N_TXS {
        root = transaction(cs.namespace(||format!("transact{}", i)), &txs[i], &exs[i], &root, &params)?;
    }
    Ok(root)
}


