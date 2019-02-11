extern crate paillier;
use paillier::*;
use paillier::arithimpl::traits::Samplable;
use ::std::borrow::Cow;
use std::ops::Shr;

lazy_static! {
   static ref ORDER:BigInt = BigInt::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
   static ref HALF_ORDER:BigInt = ORDER.clone().shr(1);
}
fn random_bigint() -> BigInt {
   BigInt::sample_range(&HALF_ORDER, &ORDER)
   //BigInt::sample_range(&BigInt::from(10), &BigInt::from(20))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Enc {
   ek: EncryptionKey,
}

#[derive(Serialize, Deserialize, Debug)]
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
      Paillier::mul(&self.ek, a, RawPlaintext(Cow::Borrowed(b))
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
pub struct Alice<'a> {
   dec: &'a Dec,
   m: &'a BigInt,
   a: BigInt,
}
#[derive(Debug)]
pub struct Bob<'a> {
   enc: &'a Enc,
   m: &'a BigInt,
   a: BigInt,
}

impl <'a> Alice<'a> {
   pub fn new(dec: &'a Dec, m:&'a BigInt) -> Self {
      Self {
         dec: dec,
         m: m,
         a: BigInt::from(0),
      }
   }
   pub fn to_bob(&self) -> RawCiphertext {
      self.dec.encrypt(&self.m)
   }
   pub fn from_bob<'c>(&mut self, data:RawCiphertext<'c>) {
      self.a = self.dec.decrypt(data);
   }
}

impl <'a> Bob<'a> {
   pub fn new(enc: &'a Enc, m:&'a BigInt) -> Self {
      Self {
         enc: enc,
         m: m,
         a: BigInt::from(0),
      }
   }
   pub fn from_alice<'c, 'd>(&mut self, data:RawCiphertext<'c>) -> RawCiphertext<'d> {
      let beta = random_bigint();

      let b = self.enc.encrypt(&beta);
      let r = self.enc.add(self.enc.mul(data, self.m), b);

      self.a = -beta;
      r
   }
}


pub struct Player {
   dec: Dec,
   m: BigInt,
}
impl Player {
   pub fn new() -> Self {
      Self { dec: Dec::new(), m:random_bigint() }
   }
   pub fn get_enc(&self) -> &Enc { &self.dec.enc }
   pub fn get_secret(&self) -> &BigInt { &self.m }

   pub fn alicization(&self) -> Alice {
      Alice::new(&self.dec, &self.m)
   }
   pub fn bobization<'a>(&'a self, alice:&'a Player) -> Bob {
      Bob::new(alice.get_enc(), &self.m)
   }
}


#[cfg(test)]
mod tests {
   #[test]
   fn test() {
      use ::mta::*;
      let p1 = Player::new();
      let p2 = Player::new();
      let mut alice = p1.alicization();
      let mut bob = p2.bobization(&p1);

      let x2 = {
         let x1 = alice.to_bob();
         let x2 = bob.from_alice(x1.clone());
         x2
      };
      alice.from_bob(x2);

      assert_eq!(alice.m * bob.m, &alice.a + &bob.a);

      println!("alice.m = {:?}", alice.m);
      println!("bob.m = {:?}", bob.m);
      println!("mul = {:?}", alice.m * bob.m);

      println!("alice.a = {:?}", &alice.a);
      println!("alice.a = {:?}", &bob.a);
      println!("add = {:?}", &alice.a + &bob.a);
   }
}
