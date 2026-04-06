pub mod specialization {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct NoSpecialization;
}

pub mod mac {
    use std::marker::PhantomData;
    use swanky_party::{IsParty, Party, Prover, Verifier};

    pub trait MacTypes {
        type VF: Copy;
        type TF: Copy;
    }

    impl<VF: Copy, TF: Copy, S> MacTypes for (VF, TF, S) {
        type VF = VF;
        type TF = TF;
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Mac<P: Party, T: MacTypes> {
        value: Option<T::VF>,
        tag: T::TF,
        _party: PhantomData<P>,
    }

    impl<P: Party, T: MacTypes> Mac<P, T> {
        pub fn zero() -> Self
        where
            T::TF: Default,
        {
            Self {
                value: None,
                tag: T::TF::default(),
                _party: PhantomData,
            }
        }

        pub fn tag(&self, _: IsParty<P, P>) -> T::TF {
            self.tag
        }
    }

    impl<T: MacTypes> Mac<Prover, T> {
        pub fn prover_new(_: IsParty<Prover, Prover>, value: T::VF, pad: T::TF) -> Self {
            Self {
                value: Some(value),
                tag: pad,
                _party: PhantomData,
            }
        }

        pub fn prover_extract(&self, _: IsParty<Prover, Prover>) -> (T::VF, T::TF) {
            (self.value.expect("prover Mac missing value"), self.tag)
        }
    }

    impl<T: MacTypes> Mac<Verifier, T> {
        pub fn verifier_new(_: IsParty<Verifier, Verifier>, tag: T::TF) -> Self {
            Self {
                value: None,
                tag,
                _party: PhantomData,
            }
        }
    }

    impl<T: MacTypes> From<Mac<Prover, T>> for (T::VF, T::TF) {
        fn from(value: Mac<Prover, T>) -> Self {
            (value.value.expect("prover Mac missing value"), value.tag)
        }
    }
}

pub mod vole {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct VoleSizes {
        pub base_voles_needed: usize,
    }

    impl VoleSizes {
        pub const fn of<VF, TF>() -> Self {
            Self {
                base_voles_needed: 0,
            }
        }
    }
}
