extern crate paillier;
use paillier::*;
use ::std::borrow::Cow;
use ::field;

pub use paillier::RawCiphertext;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Enc {
   ek: EncryptionKey,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Dec {
   enc: Enc,
   dk: DecryptionKey,
}

impl Enc {
   pub fn new() -> Self {
      let (ek,_dk) = Paillier::keypair().keys();
      Self {
         ek: ek,
      }
   }
   pub fn encrypt<'d>(&self, m:&BigInt) -> RawCiphertext<'d> {
      let r = Paillier::encrypt(&self.ek, RawPlaintext(Cow::Borrowed(m)));
      //r.0.into_owned()
      r
   }
   pub fn add<'c1,'c2, 'd>(&self, a:RawCiphertext<'c1>, b:RawCiphertext<'c2>) -> RawCiphertext<'d> {
      Paillier::add(&self.ek, a, b)
   }
   pub fn mul<'c1,'c2, 'd>(&self, a:RawCiphertext<'c1>, b:&BigInt) -> RawCiphertext<'d> {
      Paillier::mul(&self.ek, a, RawPlaintext(Cow::Borrowed(b)))
   }
}

impl Dec {
   pub fn new() -> Self {
      let (ek,dk) = Paillier::keypair().keys();
      Self {
         enc: Enc { ek: ek },
         dk: dk,
      }
   }
   pub fn encrypt<'d>(&self, m:&BigInt) -> RawCiphertext<'d> {
      self.enc.encrypt(m)
   }
   pub fn decrypt<'d>(&self, m:RawCiphertext<'d>) -> BigInt {
      //let r = Paillier::decrypt(&self.dk, RawCiphertext(Cow::Borrowed(m)));
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
   pub fn new(m:BigInt) -> Alice {
      Self {
         dec: Dec::new(),
         m: m,
         a: BigInt::from(0),
         fin: false,
      }
   }

   pub fn to_bob(&self) -> (&Enc, RawCiphertext) {
      (&self.dec.enc, self.dec.encrypt(&self.m))
   }
   pub fn from_bob<'c>(&mut self, data:&RawCiphertext<'c>) {
      self.a = self.dec.decrypt(data.clone());
      self.fin = true;
   }
}

impl Bob {
   pub fn new(m:BigInt) -> Self {
      Self {
         m: m,
         a: BigInt::from(0),
         fin: false,
      }
   }

   pub fn from_alice<'c, 'd>(&mut self, enc:&Enc, data:&RawCiphertext<'c>) -> RawCiphertext<'d> {
      let beta = field::random_bigint();

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
         return r
      } else {
         panic!("not a Alice");
      }
   }
   pub fn as_bob_mut(&mut self) -> &mut Bob {
      if let Role::B(ref mut r) = self {
         return r
      } else {
         panic!("not a Bob");
      }
   }
}

pub struct Player {
   pub m: BigInt,
   role: Role,
}
impl Player {
   pub fn new() -> Self {
      Self {
         m: field::random_bigint(),
         role: Role::Init(),
      }
   }
   pub fn new_with(m:BigInt) -> Self {
      Self {
         m: m,
         role: Role::Init(),
      }
   }
   pub fn get_secret(&self) -> &BigInt { &self.m }

   pub fn as_alice(&mut self) -> &mut Alice { self.role.as_alice_mut() }
   pub fn as_bob(&mut self) -> &mut Bob { self.role.as_bob_mut() }

   pub fn get_result(&self) -> Option<(&BigInt,&BigInt)> {
      match &self.role {
         Role::A(alice) if alice.fin == true => Some((&alice.m, &alice.a)),
         Role::B(bob) if bob.fin == true => Some((&bob.m, &bob.a)),
         _ => None,
      }
   }

   pub fn alicization(&mut self) -> &mut Alice {
      self.role = Role::A(Alice::new(self.m.clone()));
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
   use paillier::*;
   use ::mta::*;

   impl Alice {
      #[inline] pub fn m(&self) -> &BigInt { &self.m }
      #[inline] pub fn a(&self) -> &BigInt { &self.a }
   }
   impl Bob {
      #[inline] pub fn m(&self) -> &BigInt { &self.m }
      #[inline] pub fn a(&self) -> &BigInt { &self.a }
   }

   #[test]
   fn test_mta() {
      let mut p1 = Player::new();
      let mut p2 = Player::new();
      let alice = p1.alicization();
      let bob = p2.bobization();

      let x2 = {
         let (e,x1) = alice.to_bob();
         let x2 = bob.from_alice(e, &x1);
         x2
      };
      alice.from_bob(&x2);

      assert_eq!(&alice.m * &bob.m, &alice.a + &bob.a);

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
