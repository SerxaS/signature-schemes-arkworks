#[cfg(test)]
mod test {
    use crate::signatures::{
        bls_single::{bls_verify, BlsSig},
        schnorr_musig::{sch_musig_verify, SchMuSig},
        schnorr_single::{sch_verify, SchSign},
    };
    use ark_bn254::Fr;
    use ark_std::UniformRand;

    #[test]
    fn schnorr_test() {
        // Random number generator.
        let mut rng = ark_std::test_rng();

        // Message that wants to sign.
        let tx_num = Fr::rand(&mut rng);

        // Alice signs message.
        let signature = SchSign::signature(tx_num);

        // Bob verifies Alice's signature that signed from herself.
        sch_verify(tx_num, signature);
    }

    #[test]
    fn schnorr_musig_test() {
        // Random number generator.
        let mut rng = ark_std::test_rng();

        // Message that wants to sign.
        let alice_tx_num = Fr::rand(&mut rng);
        let bob_tx_num = Fr::rand(&mut rng);

        // Alice signs message.
        let signature = SchMuSig::signature(alice_tx_num, bob_tx_num);

        // Bob verifies Alice's signature that signed from herself.
        sch_musig_verify(alice_tx_num, bob_tx_num, signature);
    }

    #[test]
    fn bls_test() {
        // Random number generator.
        let mut rng = ark_std::test_rng();

        // Message that wants to sign.
        let tx_num = Fr::rand(&mut rng);

        // Alice signs message.
        let signature = BlsSig::sign(tx_num);

        // Bob verifies Alice's signature that signed from herself.
        bls_verify(tx_num, signature);
    }
}
