/// Signature scheme was made using https://2π.com/22/bls-signatures/
use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{pairing::Pairing, Group};
use ark_std::UniformRand;

use crate::poseidon_hash::sponge::PoseidonSponge;

pub struct BlsSig {
    pub(crate) alice_pub: G2,
    pub(crate) signature: G1,
}

impl BlsSig {
    pub fn sign(message: Fr) -> BlsSig {
        // Random number generator.
        let mut rng = ark_std::test_rng();

        // Alice's private and public key generation.
        let alice_priv = Fr::rand(&mut rng);
        let alice_pub = G2::generator() * alice_priv;

        // Hashes message "m".
        let mut sponge = PoseidonSponge::new();
        sponge.update(&[message]);

        let msg_hash = PoseidonSponge::squeeze(&mut sponge);

        // Maps message "m" onto a point in group G2.
        let msg_g1 = G1::generator() * msg_hash;

        // Computes the signature.
        let signature = msg_g1 * alice_priv;

        BlsSig {
            alice_pub,
            signature,
        }
    }
}

pub fn bls_verify(message: Fr, sign: BlsSig) {
    // Hashes message "m"
    let mut sponge = PoseidonSponge::new();
    sponge.update(&[message]);

    let msg_hash = PoseidonSponge::squeeze(&mut sponge);

    // Given a signature and a public key, verifies that e(σ, g2) = e(pub_key, H(m)).
    if Bn254::pairing(&sign.signature, &G2::generator())
        == Bn254::pairing(&(G1::generator() * msg_hash), &sign.alice_pub)
    {
        println!("Signature matches. Alice signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
