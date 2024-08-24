pub mod params;
/// Native sponge implementation
pub mod sponge;
use self::params::hasher::{poseidon_bn254_5x5::Params, RoundParams, Sbox};
use ark_test_curves::bls12_381::Fr;

type P = Params;
/// Constructs objects.
#[derive(Clone)]
pub struct Poseidon {
    /// Constructs an array for the inputs.
    inputs: [Fr; 5],
}

impl Poseidon {
    /// Create the objects.
    pub fn new(inputs: [Fr; 5]) -> Self {
        Poseidon { inputs }
    }

    /// The Hades Design Strategy for Hashing.
    /// Mixing rounds with half-full S-box layers and
    /// rounds with partial S-box layers.
    /// More detailed explanation for
    /// The Round Function (TRF) and Hades:
    /// https://eprint.iacr.org/2019/458.pdf#page=5
    pub fn permute(&self) -> [Fr; 5] {
        let full_rounds = P::full_rounds();
        let half_full_rounds = full_rounds / 2;
        let partial_rounds = P::partial_rounds();
        let round_constants = P::round_constants();
        let total_count = P::round_constants_count();

        let first_round_end = half_full_rounds * 5;
        let first_round_constants = &round_constants[0..first_round_end];

        let second_round_end = first_round_end + partial_rounds * 5;
        let second_round_constants = &round_constants[first_round_end..second_round_end];

        let third_round_constants = &round_constants[second_round_end..total_count];

        let mut state = self.inputs;
        for round in 0..half_full_rounds {
            let round_consts = P::load_round_constants(round, first_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying S-boxes for the full round.
            for state in state.iter_mut().take(5) {
                // 2. step for the TRF.
                // SubWords step.
                *state = P::sbox_f(*state);
            }
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        for round in 0..partial_rounds {
            let round_consts = P::load_round_constants(round, second_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying single S-box for the partial round.
            // 2. step for the TRF.
            // SubWords step, denoted by S-box.
            state[0] = P::sbox_f(state[0]);
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        for round in 0..half_full_rounds {
            let round_consts = P::load_round_constants(round, third_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying S-boxes for the full round.
            for state in state.iter_mut().take(5) {
                // 2. step for the TRF.
                // SubWords step, denoted by S-box.
                *state = P::sbox_f(*state);
            }
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        state
    }
}
