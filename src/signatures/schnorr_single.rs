use ark_ec::{AffineRepr, Group};
/// Signature scheme was made using https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
use ark_ff::{BigInteger, Field, FpConfig, PrimeField, Zero};
use ark_test_curves::{
    bls12_381::{Fr, G1Projective as G1},
    UniformRand,
};

use crate::poseidon_hash::sponge::PoseidonSponge;

pub struct SchSign {
    pub(crate) big_r: G1,
    pub(crate) s: Fr,
    pub(crate) alice_pub: G1,
}

impl SchSign {
    pub fn signature(message: Fr) -> SchSign {
        // Random number generator.
        let rng = ark_std::test_rng();

        // Alice's private and public key generation.
        let alice_priv = Fr::rand(&mut rng);
        let alice_pub = G1::generator() * alice_priv;

        // Alice chooses a random number "r" and generates "R".
        let r = Fr::rand(&mut rng);
        let big_r = G1::generator() * r;

        // To protect against attacks, we choose key prefixed Schnorr signatures which
        // means that the public key is prefixed to the message in the challenge hash input.
        // Concatenates "r", "alice pub key" and "message" then hashes them.
        let big_r_fr = Fr::from_le_bytes_mod_order(&big_r.x.0.to_bytes_le());
        let alice_pub_fr = Fr::from_bytes(&alice_pub.x.to_bytes()).unwrap();

        let mut sponge = PoseidonSponge::new();
        sponge.update(&[big_r_fr, alice_pub_fr, message]);
        let e = PoseidonSponge::squeeze(&mut sponge);

        // Calculates "s" value
        let s = r + (e * alice_priv);

        SchSign {
            big_r,
            s,
            alice_pub,
        }
    }
}

pub fn sch_verify(message: Fr, signature: SchSign) {
    // Concatenates "r", "alice pub key" and "message" then hashes them.
    let big_r_fr = Fr::from_bytes(&signature.big_r.x.to_bytes()).unwrap();
    let alice_pub_fr = Fr::from_bytes(&signature.alice_pub.x.to_bytes()).unwrap();

    let mut sponge = PoseidonSponge::new();
    sponge.update(&[big_r_fr, alice_pub_fr, message]);
    let e_v = PoseidonSponge::squeeze(&mut sponge);

    // Verifies that the equation holds.
    if G1::generator() * signature.s == (signature.alice_pub * e_v) + signature.big_r {
        println!("Signature matches. Alice signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
