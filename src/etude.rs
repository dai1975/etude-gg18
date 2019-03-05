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

   kri: Option<Mpz>,
   kui: Option<Mpz>,

   sign_rx: Option<Mpz>,
   sign_si: Option<Mpz>,

   state: PlayerState,
}

enum PlayerState {
   Void { },
   BroadcastingGr {
      grs: Vec<Option<PublicKey>>,
   },
   Mta {
      kr: Vec<mta::Player>,
      rk: Vec<mta::Player>,
      ku: Vec<mta::Player>,
      uk: Vec<mta::Player>,
   },
   BroadcastingDelta {
      deltas: Vec<Option<Mpz>>,
   },
   BroadcastingSign {
   },
}

impl Player {
   pub fn get_state_name(&self) -> &'static str {
      match self.state {
         PlayerState::Void { } => "Void",
         PlayerState::BroadcastingGr { .. } => "BroadcastingGr",
         PlayerState::Mta { .. } => "Mta",
         PlayerState::BroadcastingDelta { .. } => "BroadcastingDelta",
         PlayerState::BroadcastingSign { .. } => "BroadcastingSign",
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
         kri: None,
         kui: None,
         sign_rx: None,
         sign_si: None,
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

   pub fn on_gri(&mut self, i:usize, gr:PublicKey) {
      if let PlayerState::BroadcastingGr { ref mut grs } = self.state {
         grs[i] = Some(gr);
         if grs.iter().find(|o|o.is_none()).is_some() {
            return;
         }
         self.grs = grs.into_iter().map(|o| o.unwrap()).collect();
      } else {
         panic!("invalid state");
      }
      let ki = seckey_to_mpz(&self.ki.unwrap());
      let ri = seckey_to_mpz(&self.ri.unwrap());
      let ui = seckey_to_mpz(&self.ui.unwrap());
      self.state = PlayerState::Mta {
         kr: (0..self.n).map(|_| mta::Player::new_with(ki.clone())).collect(),
         rk: (0..self.n).map(|_| mta::Player::new_with(ri.clone())).collect(),
         ku: (0..self.n).map(|_| mta::Player::new_with(ki.clone())).collect(),
         uk: (0..self.n).map(|_| mta::Player::new_with(ui.clone())).collect(),
      };
   }

   pub fn on_mta_1(&mut self, from:usize) -> Vec<(mta::Enc, mta::RawCiphertext)> {
      let mut vec = Vec::<(mta::Enc, mta::RawCiphertext)>::with_capacity(4);
      if let PlayerState::Mta { kr, rk, ku, uk } = &mut self.state {
         {
            let (e,c) = kr[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }
         {
            let (e,c) = rk[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }
         {
            let (e,c) = ku[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }
         {
            let (e,c) = uk[from].alicization().to_bob();;
            vec.push((e.clone(), c));
         }

      } else {
         panic!("invalid state");
      }
      vec
   }

   pub fn on_mta_2(&mut self, from:usize, inp:Vec<(mta::Enc, mta::RawCiphertext)>) -> Vec<mta::RawCiphertext> {
      let mut vec = Vec::<mta::RawCiphertext>::with_capacity(4);
      if let PlayerState::Mta { kr, rk, ku, uk } = &mut self.state {
         {
            let bob = kr[from].bobization();
            let c = bob.from_alice(&inp[0].0, &inp[0].1);
            vec.push(c);
         }
         {
            let bob = rk[from].bobization();
            let c = bob.from_alice(&inp[1].0, &inp[1].1);
            vec.push(c);
         }
         {
            let bob = ku[from].bobization();
            let c = bob.from_alice(&inp[2].0, &inp[2].1);
            vec.push(c);
         }
         {
            let bob = uk[from].bobization();
            let c = bob.from_alice(&inp[3].0, &inp[3].1);
            vec.push(c);
         }
      } else {
         panic!("invalid state");
      }
      self.check_mta_fin();
      vec
   }
   pub fn on_mta_3(&mut self, from:usize, inp:Vec<mta::RawCiphertext>) {
      if let PlayerState::Mta { kr, rk, ku, uk } = &mut self.state {
         {
            let alice = kr[from].as_alice();
            alice.from_bob(&inp[0]);
         }
         {
            let alice = rk[from].as_alice();
            alice.from_bob(&inp[1]);
         }
         {
            let alice = ku[from].as_alice();
            alice.from_bob(&inp[2]);
         }
         {
            let alice = uk[from].as_alice();
            alice.from_bob(&inp[3]);
         }
      } else {
         panic!("invalid state");
      }
      self.check_mta_fin();
   }
   fn check_mta_fin(&mut self,) {
      let mut kr_a: Vec<Mpz> = Vec::with_capacity(self.n);
      let mut rk_a: Vec<Mpz> = Vec::with_capacity(self.n);
      let mut ku_a: Vec<Mpz> = Vec::with_capacity(self.n);
      let mut uk_a: Vec<Mpz> = Vec::with_capacity(self.n);
      let mut kri = Mpz::new();
      let mut kui = Mpz::new();
      if let PlayerState::Mta { kr, rk, ku, uk } = &mut self.state {
         for i in 0..(self.n) {
            if i == self.i {
               kr_a.push(Mpz::new());
               rk_a.push(Mpz::new());
               ku_a.push(Mpz::new());
               uk_a.push(Mpz::new());
               kri += &kr[i].m * &rk[i].m;
               kui += &ku[i].m * &uk[i].m;
            } else {
               let rkr = kr[i].get_result();
               let rrk = rk[i].get_result();
               let rku = ku[i].get_result();
               let ruk = uk[i].get_result();
               if let (Some(rkr), Some(rrk), Some(rku), Some(ruk)) = (rkr, rrk, rku, ruk) {
                  kr_a.push(rkr.1.clone());
                  rk_a.push(rrk.1.clone());
                  ku_a.push(rku.1.clone());
                  uk_a.push(ruk.1.clone());
                  kri += rkr.1 * rrk.1;
                  kui += rku.1 * ruk.1;
               } else {
                  return;
               }
            }
         }
      } else {
         panic!("invalid state");
      }
      let mut deltas:Vec<Option<Mpz>> = vec![None; self.n];
      deltas[self.i] = Some(kri.clone());
      self.kri = Some(kri);
      self.kui = Some(kui);
      self.state = PlayerState::BroadcastingDelta { deltas: deltas }
   }

   pub fn on_delta_i(&mut self, i:usize, di:Mpz) {
      let mut delta = Mpz::new();
      if let PlayerState::BroadcastingDelta { ref mut deltas } = self.state {
         deltas[i] = Some(di);
         for i in 0..(self.n) {
            if let Some(ref d) = deltas[i] {
               delta += d;
            } else {
               return;
            }
         }
      } else {
         panic!("invalid state");
      }

      /*
      R = (Π g^γ i)^(1/δ ) // = g^(1/k)
      r = H(R)
      si = m*ki + r*σ i
       */
      self.state = PlayerState::BroadcastingSign {
      };
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
      self.phase1_broadcast_gr();
   }

   fn phase1_begin(&mut self) {
      let mut rng = OsRng::new().expect("OsRng");
      self.players.iter_mut().for_each(|p| {
         p.begin(&mut rng);
      });
   }
   fn phase1_broadcast_gr(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let gri = self.players[i].gri.unwrap().clone();
               self.players[j].on_gri(i, gri);
            }
         }
      }
   }

   fn phase2_exchange_mta(&mut self) {
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

   fn phase3_broadcast_delta(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let kri = self.players[i].kri.clone().unwrap();
               self.players[j].on_delta_i(i, kri);
            }
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

      gg18.phase1_broadcast_gr();
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "Mta"));

      gg18.phase2_exchange_mta();
      gg18.players.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingDelta"));
   }
}
