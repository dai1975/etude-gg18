extern crate gmp;
use self::gmp::mpz::Mpz;
use std::convert::From;

extern crate secp256k1;
use self::secp256k1::{Secp256k1, SecretKey};
use self::secp256k1::constants::{SECRET_KEY_SIZE};
//rand 0.4
use self::secp256k1::rand::{Rng};
use self::secp256k1::rand::os::{OsRng};

use ::mta;

fn seckey_to_mpz(sk: &SecretKey) -> Mpz {
   let a:&[u8] = unsafe { std::slice::from_raw_parts(sk.as_ptr(), SECRET_KEY_SIZE) };
   Mpz::from(a)
}
fn seckey_from_mpz<T>(z: &Mpz) -> SecretKey {
   let v = Vec::<u8>::from(z);
   SecretKey::from_slice(v.as_slice()).unwrap()
}

struct Player {
   pub i:  usize,
   ui: SecretKey,
   ki: SecretKey,
   ri: SecretKey,
   mta_kr: Vec<mta::Player>,
   mta_ku: Vec<mta::Player>,
}
impl Player {
   pub fn new<RNG:Rng>(i:usize, rng: &mut RNG) -> Self {
      Self {
         i: i,
         ui: SecretKey::new(rng),
         ki: SecretKey::from_slice(&[0; SECRET_KEY_SIZE]).expect("ki"),
         ri: SecretKey::from_slice(&[0; SECRET_KEY_SIZE]).expect("ri"),
         mta_kr: Vec::new(),
         mta_ku: Vec::new(),
      }
   }
   pub fn prepare_sign<RNG:Rng>(&mut self, rng:&mut RNG, n:usize) {
      self.ki = SecretKey::new(rng);
      self.ri = SecretKey::new(rng);
      self.mta_ku.resize_with(n, ||{mta::Player::new()});
      self.mta_kr.resize_with(n, ||{mta::Player::new()});
   }
   pub fn new_alice_kr(&mut self, j:usize) -> &mut mta::Alice {
      self.mta_kr[j].alicization()
   }
   pub fn new_bob_kr(&mut self, j:usize) -> &mut mta::Bob {
      self.mta_kr[j].bobization()
   }
   pub fn new_alice_ku(&mut self, j:usize) -> &mut mta::Alice {
      self.mta_ku[j].alicization()
   }
   pub fn new_bob_ku(&mut self, j:usize) -> &mut mta::Bob {
      self.mta_ku[j].bobization()
   }
}

pub struct GG18 {
   n: usize,
   players: Vec<Player>,
}

impl GG18 {
   pub fn new(n:usize) -> Self {
      let mut rng = OsRng::new().expect("OsRng");
      let players = (0..n).map(|i| Player::new(i, &mut rng)).collect();
      Self {
         n:n,
         players:players,
      }
   }
   pub fn n(&self) -> usize { self.n }

   pub fn sign(&mut self) {
      self.phase1_prepare();
      self.phase2_exchange_mta();
   }
   fn phase1_prepare(&mut self) {
      let mut rng = OsRng::new().expect("OsRng");
      let n = self.n;
      self.players.iter_mut().for_each(|p| {
         p.prepare_sign(&mut rng, n);
      });
   }
   fn phase2_exchange_mta(&mut self) {
      let n = self.n;
      for i in 0..n-1 {
         let (left,right) = self.players.as_mut_slice().split_at_mut(i+1);
         for j in i+1..n {
            let mut alice = left[i].new_alice_kr(j);
            let mut bob = right[j-i-1].new_bob_kr(i);
            let x2 = {
               let (e, x1) = alice.to_bob();
               let x2 = bob.from_alice(e.clone(), x1.clone());
               x2
            };
            alice.from_bob(x2.clone());
         }
      }
   }
}


#[cfg(test)]
mod tests {
   #[test]
   fn test_mta_exchange() {
      let mut gg18 = ::etude::GG18::new(4);
      gg18.phase1_prepare();
      gg18.phase2_exchange_mta();

      let n = gg18.n();
      for i in 0..n-1 {
         let (left,right) = gg18.players.as_slice().split_at(i+1);
         for j in i+1..n {
            let alice = left[i].mta_kr[j].as_alice();
            let bob = right[j-i-1].mta_kr[i].as_bob();

            assert_eq!(alice.m() * bob.m(), alice.a() + bob.a());
         }
      }
   }
}
