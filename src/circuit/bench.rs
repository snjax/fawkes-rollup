use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit
};

use bellman::groth16::{
    generate_random_parameters,
    create_random_proof,
    prepare_verifying_key,
    verify_proof
};

use bellman::pairing::{
    Engine
};

use bellman::pairing::bn256::{Bn256};
use sapling_crypto::circuit::test::TestConstraintSystem;

use fawkes_crypto::circuit::signal::{Signal};
use fawkes_crypto::ecc::{JubJubParams, JubJubBN256};
use fawkes_crypto::wrappedmath::Wrap;

use std::time::SystemTime;

use crate::circuit::rollup::*;
use rand::{Rng, thread_rng};
use std::fs::File;
use std::io::{BufWriter, BufReader};

fn gen_merkle_proof_allocated<E:Engine, CS:ConstraintSystem<E>, R:Rng> (
    mut cs:CS,
    rng: &mut R
) -> Result<Vec<Signal<E>>, SynthesisError> {
    (0..PROOF_LENGTH).map(|i|
        Signal::alloc(cs.namespace(|| format!("proof[{}]", i)), Some(rng.gen()))
    ).collect()
}


fn gen_leaf_allocated<E:Engine, CS:ConstraintSystem<E>, R:Rng, J:JubJubParams<E>>(
    mut cs:CS,
    rng: &mut R,
    params: &RollupParams<E,J>
) -> Result<Leaf<E>, SynthesisError> {
    let r = fawkes_crypto::ecc::EdwardsPoint::<E>::rand(rng, &params.jubjub_params)
        .mul(Wrap::<J::Fs>::from(8u64).into_repr(), &params.jubjub_params).into_xy().0;
    Ok(Leaf {
        owner: Signal::alloc(cs.namespace(|| "r"), Some(r))?,
        amount: Signal::alloc(cs.namespace(|| "amount"), Some(Wrap::from((rng.gen::<u16>() as u64 + 1u64) << 32)))?,
        nonce: Signal::alloc(cs.namespace(|| "nonce"), Some(Wrap::from(rng.gen::<u32>() as u64)))?
    })
}



fn gen_txex_allocated<E:Engine, CS:ConstraintSystem<E>, R:Rng, J:JubJubParams<E>> (
    mut cs:CS,
    rng: &mut R,
    params: &RollupParams<E,J>
) -> Result<TxEx<E>, SynthesisError> {
    Ok(TxEx {
        leaf_from: gen_leaf_allocated(cs.namespace(|| "leaf_from"), rng, params)?,
        leaf_to: gen_leaf_allocated(cs.namespace(|| "leaf_to"), rng, params)?,
        proof_from_before: gen_merkle_proof_allocated(cs.namespace(||"proof_from_before"), rng)?,
        proof_from_after: gen_merkle_proof_allocated(cs.namespace(||"proof_from_after"), rng)?,
        proof_to_before: gen_merkle_proof_allocated(cs.namespace(||"proof_to_before"), rng)?,
        proof_to_after: gen_merkle_proof_allocated(cs.namespace(||"proof_to_after"), rng)?
    })
}

fn gen_tx_allocated<E:Engine, CS:ConstraintSystem<E>, R:Rng, J:JubJubParams<E>> (
    mut cs:CS,
    rng: &mut R,
    params: &RollupParams<E,J>
) -> Result<Tx<E>, SynthesisError> {

    let r = fawkes_crypto::ecc::EdwardsPoint::<E>::rand(rng, &params.jubjub_params)
        .mul(Wrap::<J::Fs>::from(8u64).into_repr(), &params.jubjub_params).into_xy().0;

    Ok(Tx {
        from: Signal::alloc(cs.namespace(|| "from"), Some(Wrap::from(rng.gen::<u32>() as u64)))?,
        to: Signal::alloc(cs.namespace(|| "to"), Some(Wrap::from(rng.gen::<u32>() as u64)))?,
        amount: Signal::alloc(cs.namespace(|| "amount"), Some(Wrap::from(rng.gen::<u16>() as u64)))?,
        nonce: Signal::alloc(cs.namespace(|| "nonce"), Some(Wrap::from(rng.gen::<u32>() as u64)))?,
        s: Signal::alloc(cs.namespace(|| "s"), Some(Wrap::from_other(Wrap::new(rng.gen::<J::Fs>()))))?,
        r: Signal::alloc(cs.namespace(|| "r"), Some(r))?
    })
}

struct Rollup<'a, E:Engine, J:JubJubParams<E>>{
    pub params: &'a RollupParams<E, J>
}

impl <'a, E:Engine, J:JubJubParams<E>> Circuit<E> for Rollup<'a, E, J> {
    fn synthesize<CS:ConstraintSystem<E>>(
        self,
        cs:&mut CS
    ) -> Result<(), SynthesisError> {
        let ref mut rng = thread_rng();
    
        let root_before = Signal::alloc(cs.namespace(|| "root"), Some(rng.gen())).unwrap();
    
        let mut txs = vec![];
        let mut exs = vec![];
    
        for i in 0..N_TXS {
            txs.push(gen_tx_allocated(cs.namespace(|| format!("txs[{}]", i)), rng, self.params).unwrap());
            exs.push(gen_txex_allocated(cs.namespace(|| format!("exs[{}]", i)), rng, self.params).unwrap());
        }

        let _root_after = rollup(cs.namespace(|| "rollup"), &txs, &exs, &root_before, self.params).unwrap();


        Ok(())
    }
}


pub fn rollup_bencher_setup() {
    let ref rollup_params = RollupParams::<Bn256, JubJubBN256>::new();
    let ref mut rng = thread_rng();

    let time_from = SystemTime::now();

    let params = {
        let circuit = Rollup::<Bn256, JubJubBN256> {
            params:rollup_params
        };
     
        generate_random_parameters::<Bn256, _, _>(
            circuit,
            rng
        ).unwrap()
    };

    let params_file = File::create("params.bin").unwrap();
    let mut params_file = BufWriter::with_capacity(1024*1024, params_file);
    params.write(&mut params_file).unwrap();
    let difference = SystemTime::now().duration_since(time_from)
        .expect("Clock may have gone backwards");
    println!("Setup completed! {:?}.", difference);
}


pub fn rollup_bencher_proof() {
    let ref rollup_params = RollupParams::<Bn256, JubJubBN256>::new();
    let ref mut rng = thread_rng();

    let time_from = SystemTime::now();


    let params_file = File::open("params.bin").unwrap();
    let mut params_file = BufReader::with_capacity(1024*1024, params_file);

    let params = bellman::groth16::Parameters::<Bn256>::read(&mut params_file, false).unwrap();

    let pvk = prepare_verifying_key(&params.vk);

    let proof = create_random_proof(
        Rollup::<Bn256, JubJubBN256> {
            params:rollup_params
        }, &params, rng
    ).unwrap();
 
    // Verifier checks the proof against the cube
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());

    let difference = SystemTime::now().duration_since(time_from)
        .expect("Clock may have gone backwards");
    println!("Proof completed and verified! {:?}.", difference);
}


pub fn rollup_bencher_info() {
    let ref rollup_params = RollupParams::<Bn256, JubJubBN256>::new();
    let mut cs = TestConstraintSystem::<Bn256>::new();

    let rollup = Rollup::<Bn256, JubJubBN256> {
        params:rollup_params
    };

    let time_from = SystemTime::now();
    rollup.synthesize(&mut cs).unwrap();

    let difference = SystemTime::now().duration_since(time_from)
    .expect("Clock may have gone backwards");
    println!("synthesize completed! {:?}.", difference);
    println!("Number of constraints {:?}.", cs.num_constraints());


    let err = cs.which_is_unsatisfied();
    if err.is_some() {
        panic!("ERROR satisfying in {}\n", err.unwrap());
    }

}