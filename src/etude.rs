extern crate gmp;
use self::gmp::mpz::Mpz;

extern crate curv;
use self::curv::{FE,GE,SK,BigInt};
use self::curv::elliptic::curves::traits::{ECScalar, ECPoint};
use self::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use self::curv::cryptographic_primitives::hashing::traits::Hash;

use ::mta;

// the gmp of curv and pailler is different, so both needs to convert each other.
#[allow(dead_code)]
fn fe_to_mpz(fe:&FE) -> Mpz {
   let tmp = fe.to_big_int().clone().to_str_radix(10);
   let ret = Mpz::from_str_radix(&tmp, 10).unwrap();
   ret
}
#[allow(dead_code)]
fn fe_from_mpz(z:&Mpz) -> FE {
   let tmp = z.to_str_radix(10);
   let fe_z = BigInt::from_str_radix(&tmp, 10).unwrap();
   let ret = <FE as ECScalar<SK>>::from(&fe_z);
   ret
}
#[allow(dead_code)]
fn digest_message(message:&[u8]) -> FE {
   let bn = HSha256::create_hash(&vec![&BigInt::from(message)]);
   <FE as ECScalar<SK>>::from(&bn)
}
#[allow(dead_code)]
fn get_x(p:&GE) -> FE {
   let x:BigInt = p.x_coor().unwrap().mod_floor(&FE::q());
   <FE as ECScalar<SK>>::from(&x)
}

#[allow(dead_code)]
struct Party {
   pub n: usize,
   pub i: usize,

   g: GE,
   ui: Option<FE>,
   gui: Option<GE>,
   y: Option<GE>,

   ki: Option<FE>,
   ri: Option<FE>,
   gri: Option<GE>,
   grs: Vec<GE>,

   delta_i: Option<FE>,
   sigma_i: Option<FE>,

   sign_r: Option<GE>,
   sign_rx: Option<FE>,
   sign_si: Option<FE>,
   sign_s: Option<FE>,

   state: PartyState,
}

#[allow(dead_code)]
enum PartyState {
   Void { },
   BroadcastingGr {
      gus: Vec<Option<GE>>,
      grs: Vec<Option<GE>>,
   },
   Mta {
      kr: Vec<mta::Party>,
      rk: Vec<mta::Party>,
      ku: Vec<mta::Party>,
      uk: Vec<mta::Party>,
   },
   BroadcastingDelta {
      deltas: Vec<Option<Mpz>>,
   },
   CalculatingLocalSign {
      delta: FE,
   },
   BroadcastingSi {
      sis: Vec<Option<FE>>,
   },
   Fin { },
}

#[allow(dead_code)]
impl Party {
   pub fn get_state_name(&self) -> &'static str {
      match self.state {
         PartyState::Void { } => "Void",
         PartyState::BroadcastingGr { .. } => "BroadcastingGr",
         PartyState::Mta { .. } => "Mta",
         PartyState::BroadcastingDelta { .. } => "BroadcastingDelta",
         PartyState::CalculatingLocalSign { .. } => "CalculatingLocalSign",
         PartyState::BroadcastingSi { .. } => "BroadcastingSi",
         PartyState::Fin { .. } => "Fin",
      }
   }

   pub fn new(i:usize, n:usize) -> Self {
      Party {
         g: GE::generator(),
         n: n,
         i: i,
         ui: None,
         gui: None,
         y: None,
         ki: None,
         ri: None,
         gri: None,
         grs: Vec::new(),
         delta_i: None,
         sigma_i: None,
         sign_r: None,
         sign_rx: None,
         sign_si: None,
         sign_s: None,
         state: PartyState::Void { },
      }
   }

   pub fn begin(&mut self) {
      let mut gus:Vec<Option<GE>> = vec![None; self.n];
      let mut grs:Vec<Option<GE>> = vec![None; self.n];

      if let PartyState::Void { } = self.state {
         self.ui = Some(FE::new_random());
         self.ki = Some(FE::new_random());
         self.ri = Some(FE::new_random());
         self.gri = Some(self.g.clone() * &self.ri.unwrap());
         self.gui = Some(self.g.clone() * &self.ui.unwrap());
         gus[self.i] = self.gui.clone();
         grs[self.i] = self.gri.clone();
      } else {
         panic!("invalid state");
      }
      self.state = PartyState::BroadcastingGr { gus:gus, grs:grs };
   }

   pub fn on_gri(&mut self, i:usize, gu:GE, gr:GE) {
      if let PartyState::BroadcastingGr { ref mut gus, ref mut grs } = self.state {
         gus[i] = Some(gu);
         grs[i] = Some(gr);
         if grs.iter().find(|o|o.is_none()).is_some() {
            return;
         }
         self.y = gus.iter().fold(None, |acc,gui| { match acc {
            Some(a) => Some(a + gui.unwrap()),
            None => Some(gui.clone().unwrap()),
         }});
         self.grs = grs.into_iter().map(|o| o.unwrap()).collect();
      } else {
         panic!("invalid state");
      }
      let ki = fe_to_mpz(&self.ki.unwrap());
      let ri = fe_to_mpz(&self.ri.unwrap());
      let ui = fe_to_mpz(&self.ui.unwrap());
      self.state = PartyState::Mta {
         kr: (0..self.n).map(|_| mta::Party::new_with(ki.clone())).collect(),
         rk: (0..self.n).map(|_| mta::Party::new_with(ri.clone())).collect(),
         ku: (0..self.n).map(|_| mta::Party::new_with(ki.clone())).collect(),
         uk: (0..self.n).map(|_| mta::Party::new_with(ui.clone())).collect(),
      };
   }

   pub fn on_mta_1(&mut self, from:usize) -> Vec<(mta::Enc, mta::RawCiphertext)> {
      let mut vec = Vec::<(mta::Enc, mta::RawCiphertext)>::with_capacity(4);
      if let PartyState::Mta { kr, rk, ku, uk } = &mut self.state {
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
      if let PartyState::Mta { kr, rk, ku, uk } = &mut self.state {
         {
            let bob = rk[from].bobization();
            let c = bob.from_alice(&inp[0].0, &inp[0].1); // set kr[i][j] to rk[j][i]
            vec.push(c);
         }
         {
            let bob = kr[from].bobization();
            let c = bob.from_alice(&inp[1].0, &inp[1].1);
            vec.push(c);
         }
         {
            let bob = uk[from].bobization();
            let c = bob.from_alice(&inp[2].0, &inp[2].1);
            vec.push(c);
         }
         {
            let bob = ku[from].bobization();
            let c = bob.from_alice(&inp[3].0, &inp[3].1);
            vec.push(c);
         }
      } else {
         panic!("invalid state");
      }
      vec
   }
   pub fn on_mta_3(&mut self, from:usize, inp:Vec<mta::RawCiphertext>) {
      if let PartyState::Mta { kr, rk, ku, uk } = &mut self.state {
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
   }
   fn on_mta_fin(&mut self) {
      let mut delta_i = Mpz::from(0);
      let mut sigma_i = Mpz::from(0);
      if let PartyState::Mta { kr, rk, ku, uk } = &mut self.state {
         for i in 0..(self.n) {
            if i == self.i {
               delta_i += &kr[i].m * &rk[i].m;
               sigma_i += &ku[i].m * &uk[i].m;
            } else {
               let r_kr = kr[i].get_result();
               let r_rk = rk[i].get_result();
               let r_ku = ku[i].get_result();
               let r_uk = uk[i].get_result();
               if let (Some(r_kr), Some(r_rk), Some(r_ku), Some(r_uk)) = (r_kr, r_rk, r_ku, r_uk) {
                  delta_i += r_kr.1 + r_rk.1;
                  sigma_i += r_ku.1 + r_uk.1;
               } else {
                  return;
               }
            }
         }
      } else {
         panic!("invalid state");
      }
      self.delta_i = Some(fe_from_mpz(&delta_i));
      self.sigma_i = Some(fe_from_mpz(&sigma_i));
      let mut deltas:Vec<Option<Mpz>> = vec![None; self.n];
      deltas[self.i] = Some(delta_i.clone());
      self.state = PartyState::BroadcastingDelta { deltas: deltas }
   }

   pub fn on_delta_i(&mut self, i:usize, di:Mpz) {
      let mut delta = Mpz::new();
      if let PartyState::BroadcastingDelta { ref mut deltas } = self.state {
         deltas[i] = Some(di);
         if deltas.iter().find(|o|o.is_none()).is_some() {
            return;
         }
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
      self.state = PartyState::CalculatingLocalSign {
         delta: fe_from_mpz(&delta),
      };
   }

   pub fn calc_local_signature(&mut self, m:&FE) {
      let sign_r:GE;
      let sign_si:FE;
      if let PartyState::CalculatingLocalSign { ref delta } = self.state {
         //R = (Π g^γ i)^(1/δ ) // = g^(1/k)
         let sum_gri = self.grs.iter().fold(None, |acc,gr| match acc {
            Some(a) => Some(a + gr),
            None => Some(gr.clone()),
         }).unwrap();
         sign_r = sum_gri * delta.invert();
         let rx:FE = get_x(&sign_r);
         sign_si = *m * &self.ki.unwrap() + rx * self.sigma_i.unwrap();

         //si = m*ki + r*σ i
         ;
      } else {
         panic!("invalid state");
      }

      self.sign_r = Some(sign_r);
      self.sign_rx = Some(get_x(&sign_r));
      self.sign_si = Some(sign_si);
      let mut sis:Vec<Option<FE>> = vec![None; self.n];
      sis[self.i] = Some(sign_si);
      self.state = PartyState::BroadcastingSi { sis:sis };
   }

   pub fn on_si(&mut self, i:usize, si:FE) {
      if let PartyState::BroadcastingSi { ref mut sis } = self.state {
         sis[i] = Some(si);
         if sis.iter().find(|o|o.is_none()).is_some() {
            return;
         }

         self.sign_s = sis.into_iter().fold(None, |acc,si| match acc {
            None => Some(si.clone().unwrap()),
            Some(a) => Some(a + si.unwrap()),
         });
      } else {
         panic!("invalid state");
      }

      self.state = PartyState::Fin { };
   }

   pub fn verify(&self, m:&FE) -> bool {
      let rx = self.sign_rx.unwrap();
      let inv_s = self.sign_s.unwrap().invert();

      let g_m_s = self.g * (*m * &inv_s);
      let y_r_u = self.y.unwrap() * (rx * &inv_s);
      rx == get_x(&(g_m_s + y_r_u))
   }
}


pub struct Etude {
   n: usize,
   parties: Vec<Party>,
}

#[allow(dead_code)]
impl Etude {
   pub fn new(n:usize) -> Self {
      let parties = (0..n).map(|i| Party::new(i, n)).collect();
      Self {
         n:n,
         parties:parties,
      }
   }

   pub fn sign(&mut self, message:&[u8]) {
      self.phase1_begin();
      self.phase1_broadcast_gr();
      self.phase2_exchange_mta();
      self.phase3_broadcast_delta();
      self.phase4_local_sign(&message);
      self.phase5_gather_signatures();
   }

   fn phase1_begin(&mut self) {
      self.parties.iter_mut().for_each(|p| {
         p.begin();
      });
   }
   fn phase1_broadcast_gr(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let gui = self.parties[i].gui.unwrap().clone();
               let gri = self.parties[i].gri.unwrap().clone();
               self.parties[j].on_gri(i, gui, gri);
            }
         }
      }
   }

   fn phase2_exchange_mta(&mut self) {
      for i in 0..(self.n-1) {
         let (left,right) = self.parties.as_mut_slice().split_at_mut(i+1);
         let mut pi = &mut left[i];
         for j in (i+1)..(self.n) {
            let pj = &mut right[j-i-1];
            {
               let from_bob = {
                  let from_alice = pi.on_mta_1(j);
                  pj.on_mta_2(i, from_alice)
               };
               pi.on_mta_3(j, from_bob);
            }
            /* check mta
            let ki_rj = match &pi.state {
               PartyState::Mta { ref kr, .. } => kr[j].get_result().unwrap().clone(),
               _ => { panic!(""); },
            };
            let rj_ki = match &pj.state {
               PartyState::Mta { ref rk, .. } => rk[i].get_result().unwrap().clone(),
               _ => { panic!(""); },
            };
            println!("mta i={}, j={}", i, j);
            assert_eq!(pi.ki.unwrap(), fe_from_mpz(&ki_rj.0));
            assert_eq!(pj.ri.unwrap(), fe_from_mpz(&rj_ki.0));
            let m = pi.ki.clone().unwrap() * pj.ri.unwrap();
            let a = fe_from_mpz(&(ki_rj.1 + rj_ki.1));
            println!("mta m={}, a={}", serde_json::to_string(&m).unwrap(), serde_json::to_string(&a).unwrap());
            assert_eq!(m, a);
             */
         }
      }
      /* check mta
      for i in 0..self.n {
         let ki = &self.parties[i].ki.unwrap();
         for j in 0..self.n {
            let rj = &self.parties[j].ri.unwrap();
            if i != j {
               let ki_rj_a = match &self.parties[i].state {
                  PartyState::Mta { kr, rk, ku, uk } => kr[j].get_result().unwrap().1.clone(),
                  _ => { panic!(""); },
               };
               let ki_rj_b = match &self.parties[j].state {
                  PartyState::Mta { kr, rk, ku, uk } => rk[i].get_result().unwrap().1.clone(),
                  _ => { panic!(""); },
               };
               println!("mtafin i={}, j={}", i, j);
               let m = ki.clone() * rj;
               let a = fe_from_mpz(&(ki_rj_a + ki_rj_b));
               println!("mtafin m={}, a={}", serde_json::to_string(&m).unwrap(), serde_json::to_string(&a).unwrap());
               assert_eq!(m, a);
            }
         }
      }
      */
      self.parties.iter_mut().for_each(|p| {
         p.on_mta_fin();
      });
   }

   fn phase3_broadcast_delta(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let kri = self.parties[i].delta_i.clone().unwrap();
               self.parties[j].on_delta_i(i, fe_to_mpz(&kri));
            }
         }
      }
   }

   fn phase4_local_sign(&mut self, msg:&[u8]) {
      let m = digest_message(msg);
      for i in 0..(self.n) {
         self.parties[i].calc_local_signature(&m);
      }
   }

   fn phase5_gather_signatures(&mut self) {
      for i in 0..(self.n) {
         for j in 0..(self.n) {
            if i != j {
               let si = self.parties[i].sign_si.clone().unwrap();
               self.parties[j].on_si(i, si);
            }
         }
      }
   }

   fn verify_r(&self) -> bool {
      let r = self.parties[0].sign_r.unwrap();
      for i in 1..self.n {
         let ri = self.parties[i].sign_r.unwrap();
         let result = r == ri;
         //println!("verify_r {}...{}", i, result);
         if !result { return false; }
      }
      true
   }

   fn verify_signature(&self, msg:&[u8]) -> bool {
      let m = digest_message(msg);
      for i in 0..(self.n) {
         let r = self.parties[i].verify(&m);
         //println!("verify {}...{}", i, r);
         if r != true {
            panic!("verify failed at {}", i);
         }
      }
      true
   }
}


#[cfg(test)]
mod tests {
   extern crate gmp;
   use self::gmp::mpz::Mpz;

   extern crate curv;
   use self::curv::{FE,GE};
   use serde_json;

   const WS:&str = "[
    \"665a810dc99d56c604c2a8358a684f70237947e839ef3970a909f2d23aed61a4\",
    \"340cef276f90855df752548d512c1256f94f590a923043c1b7fc179269134d1\",
    \"2bf1905086f970cfb3b538bfe3a47668b06df9957aee5fc564ce89c4b0f386ba\",
    \"2cd2902b57838f651c68343014c2b718737c555f72b318a5c9c6ac8ea2cc47e7\"
   ]";
   const KS:&str = "[
    \"40c9be2c45ab9e80b5071be6face42ee237502545fc89e30b442e4c1390db113\",
    \"26bb56efe35f84c3eff393625e4cc4181e27863f3cd55f490f3b6320cc606f38\",
    \"f84b6192cc2d40100649fede7113e0f040a1ce7c372b638770305ab4381580b\",
    \"2033b1717189b92b954b7ea91c70a3bc1d17eac8de1b73e52d5565da33158300\"
   ]";
   const GAMMAS:&str = "[
    \"26a9762c60ff8c57a70c8e404fa673a0057dd5059ffa2f3319d16d166a446a2c\",
    \"163df239fa0f8fbfe49a305dcc1ba3cd8eee2e67702f7c75849de9afbd5ab42b\",
    \"6cca011b768369e4c348c1d109bab6cbd0a730f9ec6b9ca9ad8aff31262a1516\",
    \"230bde9675f2081dc7b1e692dd93cbd2c8a8a435a98e2e0f848d6d98cd3c1c2e\"
   ]";
   const DELTAS:&str = "[
    \"5778c22f7eeb9e2c2c845f80730694ea830e6ca227804b685ed9d1ab789dbb23\",
    \"e3fb8c46dfc09cdfec15219ae6379cb9feef4f19cf7402140234181c9010e148\",
    \"12b09188aca2ba4671d2b3f25dbebd400b989dbedc3ee6bf490a259c6da1915a\",
    \"ce01cce04f3d15250d7d2fc8818fc044e6c7fc09e55b7cfbabb30434552c786c\"
   ]";
   const SIGMAS:&str = "[
    \"ff82e4bc074b94c8e1252fbd0efb7ab57b42188897120fea50493bd60e1b0a72\",
    \"b2eb357d95805caedb0858804a9e3e9fd1bed51754628989f6bc58cf49d050a0\",
    \"acaa8b123c57756e884237ba41118de9d5890ed2a926e5b9299ee5bc97bd8bb1\",
    \"3dd042e6daf77fe348f1c7f835c71d255da10b0ab6d49fa44727be87149852bd\"
   ]";
   const G_GAMMAS:&str = "[
    {\"x\":\"7613df0eb52e8ebf091e96ecd2a7d883ca57fafb3cd1f44c82a7efe30ae77e71\",\"y\":\"84c5ee9ec9f2606a14014fd2bfa11cd6d55ee79f460eb14cce6ccd52a927de21\"},
    {\"x\":\"7b77e86782ccd597153b1c73cc3d8208044dbe3dbc41407e7bd89b233cd5f49\",\"y\":\"22ba50e3f56b28775081daa044ce7d1026edf27b0d7b3d7e978dc9654e4a1306\"},
    {\"x\":\"b3f1091c4a925527e7c4489fff237f6ace6e0b01edcd9045ed80a9e13d0b3982\",\"y\":\"2a592a30ba422927b81467a988734d3169332d56acad07e55e1a06e41f80fcf\"},
    {\"x\":\"c344775982c830d8cad15465ca5726d34be38683614320bc2451e787cc274d8d\",\"y\":\"32e5a1d2fe702099efe2137423ef0d341060017cb98f1c1f02e3197b49074bba\"}
   ]";
   const S:&str = "\"483e9abd368b17f71043b939c534c305799490ed6b8a85da11c66ff077fbe718\"";
   const RX:&str = "\"bc0c1fe463764cc4e574ac6db5204c0a82e21f1ae9ccd57cdafda9bef3a92ab2\"";
   const Y:&str = "{\"x\":\"2730ded5fe68517c1380c275910d62e3b1f36b5f9eff25242cc2af8fdd0d4748\",\"y\":\"86f2095841ba10b3dd3e81020ee10204903d15952a9c512b7c0f1a60645985ff\"}";
   const M:&str = "\"be8f3353164ce61bba291a78d3bf2c6b3295cbb094238529229a67ac2429f5c0\"";
   const MESSAGE:[u8; 4] = [79, 77, 69, 82];


   #[test]
   fn test_verify() {
      let m:FE = serde_json::from_str(M).unwrap();
      let mut p = ::etude::Party::new(0,1);
      p.state = ::etude::PartyState::Fin{};
      p.y = Some(serde_json::from_str(Y).unwrap());
      p.sign_s = Some(serde_json::from_str(S).unwrap());
      p.sign_rx = Some(serde_json::from_str(RX).unwrap());

      assert_eq!(true, p.verify(&m));
   }

   #[test]
   fn test_phase3() {
      //let message:FE = super::digest_message(&MESSAGE);
      let ks:Vec<FE> = serde_json::from_str(KS).unwrap();
      let deltas:Vec<FE> = serde_json::from_str(DELTAS).unwrap();
      let sigmas:Vec<FE> = serde_json::from_str(SIGMAS).unwrap();
      let g_gammas:Vec<GE> = serde_json::from_str(G_GAMMAS).unwrap();
      let y:GE = serde_json::from_str(Y).unwrap();

      let n:usize = 4;
      let parties:Vec<::etude::Party> = (0..n).map(|i| {
         let mut p = ::etude::Party::new(i,4);
         p.y = Some(y.clone());
         p.ki = Some(ks[i].clone());
         p.delta_i = Some(deltas[i].clone());
         p.sigma_i = Some(sigmas[i].clone());
         p.gri = Some(g_gammas[i].clone());
         p.grs = g_gammas.clone();
         let mut deltas:Vec<Option<Mpz>> = vec![None; n];
         deltas[i] = Some(super::fe_to_mpz(&p.delta_i.clone().unwrap()));
         p.state = ::etude::PartyState::BroadcastingDelta { deltas: deltas };
         p
      }).collect();

      let mut gg18 = ::etude::Etude { n:n, parties:parties };

      gg18.phase3_broadcast_delta();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "CalculatingLocalSign"));

      gg18.phase4_local_sign(&MESSAGE);
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingSi"));

      gg18.phase5_gather_signatures();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "Fin"));

      assert_eq!(true, gg18.verify_r());

      assert_eq!(true, gg18.verify_signature(&MESSAGE));
   }

   #[test]
   fn test_phase0() {
      //let message:FE = super::digest_message(&MESSAGE);
      let us:Vec<FE> = serde_json::from_str(WS).unwrap();
      let ks:Vec<FE> = serde_json::from_str(KS).unwrap();
      let rs:Vec<FE> = serde_json::from_str(GAMMAS).unwrap();

      let deltas:Vec<FE> = serde_json::from_str(DELTAS).unwrap();
      let sigmas:Vec<FE> = serde_json::from_str(SIGMAS).unwrap();
      let g_gammas:Vec<GE> = serde_json::from_str(G_GAMMAS).unwrap();
      let y:GE = serde_json::from_str(Y).unwrap();

      let n:usize = us.len();

      let parties:Vec<::etude::Party> = (0..n).map(|i| {
         let mut p = ::etude::Party::new(i,n);
         p.ui = Some(us[i].clone());
         p.ki = Some(ks[i].clone());
         p.ri = Some(rs[i].clone());

         let gui = p.g.clone() * &p.ui.unwrap();
         let gri = p.g.clone() * &p.ri.unwrap();

         p.gui = Some(gui.clone());
         p.gri = Some(gri.clone());

         let mut gus:Vec<Option<GE>> = vec![None; n];
         let mut grs:Vec<Option<GE>> = vec![None; n];
         gus[i] = Some(gui.clone());
         grs[i] = Some(gri.clone());
         p.state = ::etude::PartyState::BroadcastingGr { gus:gus, grs:grs };
         p
      }).collect();

      let mut gg18 = ::etude::Etude { n:n, parties:parties };

      gg18.phase1_broadcast_gr();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "Mta"));
      for i in 0..n {
         assert_eq!(y, gg18.parties[i].y.unwrap());
         for j in 0..n {
            assert_eq!(g_gammas[j], gg18.parties[i].grs[j]);
         }
      }

      gg18.phase2_exchange_mta();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingDelta"));
      {
         use etude::curv::elliptic::curves::traits::ECScalar;
         let d0 = deltas.iter().fold(FE::zero(), |acc,i| acc + i);
         let d1 = gg18.parties.iter().fold(FE::zero(), |acc,p| acc + p.delta_i.unwrap());
         assert_eq!(d0, d1);
         let s0 = sigmas.iter().fold(FE::zero(), |acc,i| acc + i);
         let s1 = gg18.parties.iter().fold(FE::zero(), |acc,p| acc + p.sigma_i.unwrap());
         assert_eq!(s0, s1);
      }

      gg18.phase3_broadcast_delta();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "CalculatingLocalSign"));

      gg18.phase4_local_sign(&MESSAGE);
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "BroadcastingSi"));

      gg18.phase5_gather_signatures();
      gg18.parties.iter().for_each(|p| assert_eq!(p.get_state_name(), "Fin"));

      assert_eq!(true, gg18.verify_r());

      assert_eq!(true, gg18.verify_signature(&MESSAGE));
   }

   #[test]
   fn test_full_phases() {
      let message = "Miku-san maji tenshi!".as_bytes();
      let mut gg18 = ::etude::Etude::new(4);
      gg18.sign(&message);
      assert_eq!(true, gg18.verify_r());
      assert_eq!(true, gg18.verify_signature(&message));
   }
}
