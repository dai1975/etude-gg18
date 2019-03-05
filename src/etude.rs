extern crate gmp;
use self::gmp::mpz::Mpz;
use std::convert::From;

extern crate secp256k1;
use self::secp256k1::{Secp256k1, SecretKey, PublicKey};
use self::secp256k1::constants::{SECRET_KEY_SIZE};
//use self::secp256k1::key::{ONE_KEY};
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
   pub n: usize,
   pub i: usize,
   pub ctx: Secp256k1<secp256k1::All>,

   ui: Option<SecretKey>,
   ki: Option<SecretKey>,
   ri: Option<SecretKey>,
   gri: Option<PublicKey>,
   grs: Vec<PublicKey>,
   kr: Vec<(Mpz,Mpz)>, //mul, add
   ku: Vec<(Mpz,Mpz)>,

   state: PlayerState,
}

enum PlayerState {
   Void { },
   BroadcastingGr {
      grs: Vec<Option<PublicKey>>,
   },
   Mta {
      kr: Vec<mta::Player>,
      ku: Vec<mta::Player>,
   },
   BroadcastingDelta {
   },
}

impl Player {
   pub fn get_state_name(&self) -> &'static str {
      match self.state {
         PlayerState::Void { } => "Void",
         PlayerState::BroadcastingGr { .. } => "BroadcastingGr",
         PlayerState::Mta { .. } => "Mta",
         PlayerState::BroadcastingDelta { .. } => "BroadcastingDelta",
      }
   }

   pub fn new(i:usize, n:usize) -> Self {
      Player {
         n: n,
         i: i,
         ctx: Secp256k1::new(),
         ui: None,
         ki: None,
         ri: None,
         gri: None,
         grs: Vec::new(),
         kr: Vec::<(Mpz,Mpz)>::new(),
         ku: Vec::<(Mpz,Mpz)>::new(),
         state: PlayerState::Void { },
      }
   }

   pub fn begin<RNG:Rng>(&mut self, rng:&mut RNG) {
      if let PlayerState::Void { } = self.state {
         let n = self.n;
         self.ui = Some(SecretKey::new(rng));
         self.ki = Some(SecretKey::new(rng));
         self.ri = Some(SecretKey::new(rng));
         self.gri = Some(PublicKey::from_secret_key(&self.ctx, &self.ri.unwrap()));
         let mut grs:Vec<Option<PublicKey>> = vec![None; n];
         grs[self.i] = self.gri.clone();
         self.state = PlayerState::BroadcastingGr { grs: grs };
      } else {
         panic!("invalid state");
      }
   }

   pub fn on_gr(&mut self, i:usize, gr:PublicKey) {
      if let PlayerState::BroadcastingGr { ref mut grs } = self.state {
         grs[i] = Some(gr);
         if grs.iter().find(|o|o.is_none()).is_some() {
            return;
         }
         self.grs = grs.into_iter().map(|o| o.unwrap()).collect();
      } else {
         panic!("invalid state");
      }
      self.state = PlayerState::Mta {
         kr: (0..self.n).map(|_| mta::Player::new()).collect(),
         ku: (0..self.n).map(|_| mta::Player::new()).collect(),
      };
   }

   pub fn on_mta_1(&mut self, from:usize) -> Vec<(mta::Enc, mta::RawCiphertext)> {
      let mut vec = Vec::<(mta::Enc, mta::RawCiphertext)>::with_capacity(2);
      if let PlayerState::Mta { kr, ku } = &mut self.state {
         {
            let (e,c) = kr[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }
         {
            let (e,c) = ku[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }

      } else {
         panic!("invalid state");
      }
      vec
   }

   pub fn on_mta_2(&mut self, from:usize, inp:Vec<(mta::Enc, mta::RawCiphertext)>) -> Vec<mta::RawCiphertext> {
      let mut vec = Vec::<mta::RawCiphertext>::with_capacity(2);
      if let PlayerState::Mta { kr, ku } = &mut self.state {
         {
            let bob = kr[from].bobization();
            let c = bob.from_alice(&inp[0].0, &inp[0].1);
            vec.push(c);
         }
         {
            let bob = ku[from].bobization();
            let c = bob.from_alice(&inp[1].0, &inp[1].1);
            vec.push(c);
         }
      } else {
         panic!("invalid state");
      }
      self.check_mta_fin();
      vec
   }
   pub fn on_mta_3(&mut self, from:usize, inp:Vec<mta::RawCiphertext>) {
      if let PlayerState::Mta { kr, ku } = &mut self.state {
         {
            let alice = kr[from].as_alice();
            alice.from_bob(&inp[0]);
         }
         {
            let alice = ku[from].as_alice();
            alice.from_bob(&inp[1]);
         }
      } else {
         panic!("invalid state");
      }
      self.check_mta_fin();
   }
   fn check_mta_fin(&mut self,) {
      let mut new_kr: Vec<(Mpz,Mpz)> = Vec::with_capacity(self.n);
      let mut new_ku: Vec<(Mpz,Mpz)> = Vec::with_capacity(self.n);
      if let PlayerState::Mta { kr, ku } = &mut self.state {
         for i in 0..(self.n) {
            if (i == self.i) {
               new_kr.push((Mpz::new(), Mpz::new()));
               new_ku.push((Mpz::new(), Mpz::new()));
            } else if let (Some(rkr), Some(rku)) = (kr[i].get_result(), ku[i].get_result()) {
               new_kr.push((rkr.0.clone(), rkr.1.clone()));
               new_ku.push((rku.0.clone(), rku.1.clone()));
            } else {
               return;
            }
         }
      } else {
         panic!("invalid state");
      }
      self.kr = new_kr;
      self.ku = new_ku;
      self.state = PlayerState::BroadcastingDelta { };
   }
}

   /*
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
    */


pub struct Etude {
   n: usize,
   players: Vec<Player>,
}

impl Etude {
   pub fn new(n:usize) -> Self {
      let players = (0..n).map(|i| Player::new(i, n)).collect();
      Self {
         n:n,
         players:players,
      }
   }

   pub fn sign(&mut self) {
      self.phase1_begin();
      self.phase2_broadcast_gr();
   }

   fn phase1_begin(&mut self) {
      let mut rng = OsRng::new().expect("OsRng");
      self.players.iter_mut().for_each(|p| {
         p.begin(&mut rng);
      });
   }
   fn phase2_broadcast_gr(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let gri = self.players[i].gri.unwrap().clone();
               self.players[j].on_gr(i, gri);
            }
         }
      }
   }

   fn phase3_exchange_mta(&mut self) {
      for i in 0..(self.n-1) {
         let (left,right) = self.players.as_mut_slice().split_at_mut(i+1);
         let mut pi = &mut left[i];
         for j in (i+1)..(self.n) {
            let pj = &mut right[j-i-1];
            let from_bob = {
               let from_alice = pi.on_mta_1(j);
               pj.on_mta_2(i, from_alice)
            };
            pi.on_mta_3(j, from_bob);
         }
      }
   }
}


#[cfg(test)]
mod tests {
   #[test]
   fn test_mta_exchange() {
      let mut gg18 = ::etude::Etude::new(4);
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "Void"));

      gg18.phase1_begin();
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingGr"));

      gg18.phase2_broadcast_gr();
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "Mta"));

      gg18.phase3_exchange_mta();
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingDelta"));

      let n = gg18.n;
      for i in 0..n {
         for j in 0..n {
            if i != j {
               let akr = &gg18.players[i].kr[j];
               let bkr = &gg18.players[j].kr[i];
               assert_eq!(&akr.0 * &bkr.0, &akr.1 + &bkr.1);

               let aku = &gg18.players[i].ku[j];
               let bku = &gg18.players[j].ku[i];
               assert_eq!(&aku.0 * &bku.0, &aku.1 + &bku.1);
            }
         }
      }
   }
}
