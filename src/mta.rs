use paillier::*;
use std::borrow::Cow;

pub use paillier::RawCiphertext;

#[derive(Clone, Debug)]
pub struct Enc {
    ek: EncryptionKey,
}

#[derive(Clone, Debug)]
pub struct Dec {
    enc: Enc,
    dk: DecryptionKey,
}

impl Enc {
    pub fn new(bs: usize) -> Self {
        let (ek, _dk) = Paillier::keypair_with_modulus_size(bs + 1).keys(); // safe to multiply
        Self { ek: ek }
    }
    pub fn random_bigint(&self) -> paillier::BigInt {
        use curv::arithmetic::traits::Samplable;
        BigInt::sample_below(&self.ek.n)
    }
    pub fn encrypt<'d>(&self, m: &BigInt) -> RawCiphertext<'d> {
        let r = Paillier::encrypt(&self.ek, RawPlaintext(Cow::Borrowed(m)));
        r
    }
    pub fn add<'c1, 'c2, 'd>(
        &self,
        a: RawCiphertext<'c1>,
        b: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        Paillier::add(&self.ek, a, b)
    }
    pub fn mul<'c1, 'c2, 'd>(&self, a: RawCiphertext<'c1>, b: &BigInt) -> RawCiphertext<'d> {
        Paillier::mul(&self.ek, a, RawPlaintext(Cow::Borrowed(b)))
    }
}

impl Dec {
    pub fn new(bs: usize) -> Self {
        let bs = if bs < 2047 { 2047 } else { bs };
        let (ek, dk) = Paillier::keypair_with_modulus_size(bs + 1).keys(); // safe to multiply
        Self {
            enc: Enc { ek: ek },
            dk: dk,
        }
    }
    pub fn random_bigint(&self) -> paillier::BigInt {
        self.enc.random_bigint()
    }

    pub fn encrypt<'d>(&self, m: &BigInt) -> RawCiphertext<'d> {
        self.enc.encrypt(m)
    }
    pub fn decrypt<'d>(&self, m: RawCiphertext<'d>) -> BigInt {
        let r = Paillier::decrypt(&self.dk, m);
        r.0.into_owned()
    }
}

#[derive(Debug)]
pub struct Alice {
    dec: Dec,
    pub m: BigInt,
    pub a: BigInt,
    pub fin: bool,
}
#[derive(Debug)]
pub struct Bob {
    pub m: BigInt,
    pub a: BigInt,
    pub fin: bool,
}

impl Alice {
    pub fn new(bs: usize, m: BigInt) -> Alice {
        Self {
            dec: Dec::new(bs),
            m: m,
            a: BigInt::from(0),
            fin: false,
        }
    }

    pub fn to_bob(&self) -> (&Enc, RawCiphertext) {
        (&self.dec.enc, self.dec.encrypt(&self.m))
    }
    pub fn from_bob<'c>(&mut self, data: &RawCiphertext<'c>) {
        self.a = self.dec.decrypt(data.clone());
        self.fin = true;
    }
}

impl Bob {
    pub fn new(m: BigInt) -> Self {
        Self {
            m: m,
            a: BigInt::from(0),
            fin: false,
        }
    }

    pub fn from_alice<'c, 'd>(&mut self, enc: &Enc, data: &RawCiphertext<'c>) -> RawCiphertext<'d> {
        let beta = enc.random_bigint();

        let b = enc.encrypt(&beta);
        let r = enc.add(enc.mul(data.clone(), &self.m), b);

        self.a = -beta;
        self.fin = true;
        r
    }
}

enum Role {
    Init(),
    A(Alice),
    B(Bob),
}
impl Role {
    pub fn as_alice_mut(&mut self) -> &mut Alice {
        if let Role::A(ref mut r) = self {
            return r;
        } else {
            panic!("not a Alice");
        }
    }
    pub fn as_bob_mut(&mut self) -> &mut Bob {
        if let Role::B(ref mut r) = self {
            return r;
        } else {
            panic!("not a Bob");
        }
    }
}

pub struct Party {
    bitsize: usize,
    pub m: BigInt,
    role: Role,
}
impl Party {
    pub fn new(bs: usize, m: BigInt) -> Self {
        Self {
            bitsize: bs,
            m: m,
            role: Role::Init(),
        }
    }
    pub fn get_secret(&self) -> &BigInt {
        &self.m
    }

    pub fn as_alice(&mut self) -> &mut Alice {
        self.role.as_alice_mut()
    }
    pub fn as_bob(&mut self) -> &mut Bob {
        self.role.as_bob_mut()
    }

    pub fn get_result(&self) -> Option<(&BigInt, &BigInt)> {
        match &self.role {
            Role::A(alice) if alice.fin == true => Some((&alice.m, &alice.a)),
            Role::B(bob) if bob.fin == true => Some((&bob.m, &bob.a)),
            _ => None,
        }
    }

    pub fn alicization(&mut self) -> &mut Alice {
        self.role = Role::A(Alice::new(self.bitsize, self.m.clone()));
        self.role.as_alice_mut()
    }
    pub fn bobization(&mut self) -> &mut Bob {
        self.role = Role::B(Bob::new(self.m.clone()));
        self.role.as_bob_mut()
    }
}

#[cfg(test)]
mod tests {
    extern crate paillier;
    use ::mta::*;
    use paillier::BigInt;

    #[test]
    fn test_mta() {
        fn gen_party() -> Party {
            use curv::arithmetic::traits::{Converter, Samplable};
            let v =
                BigInt::sample_range(&BigInt::from_hex("80000000"), &BigInt::from_hex("ffffffff"));
            Party::new(8, v)
        }
        let mut p1 = gen_party();
        let mut p2 = gen_party();
        let (alice, bob) = {
            let alice = p1.alicization();
            let bob = p2.bobization();

            let x2 = {
                let (e, x1) = alice.to_bob();
                let x2 = bob.from_alice(e, &x1);
                x2
            };
            alice.from_bob(&x2);

            assert_eq!(&alice.m * &bob.m, &alice.a + &bob.a);
            (
                (alice.m.clone(), alice.a.clone()),
                (bob.m.clone(), bob.a.clone()),
            )
        };

        let a = p1.get_result().clone().unwrap();
        let b = p2.get_result().clone().unwrap();

        assert_eq!(&alice.0, a.0);
        assert_eq!(&alice.1, a.1);
        assert_eq!(&bob.0, b.0);
        assert_eq!(&bob.1, b.1);

        /*
        println!("alice.m = {:?}", &alice.m);
        println!("bob.m = {:?}", &bob.m);
        println!("mul = {:?}", &alice.m * &bob.m);

        println!("alice.a = {:?}", &alice.a);
        println!("alice.a = {:?}", &bob.a);
        println!("add = {:?}", &alice.a + &bob.a);
         */
    }
}
