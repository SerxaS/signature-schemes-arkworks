mod poseidon_hash;
mod signatures;

#[cfg(test)]
mod test {
    use crate::signatures::schnorr_single::{sch_verify, SchSign};
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
}
