use crate::{crypto, km_err, Error};

use super::{SecureDeletionData, SecureDeletionSecretManager, SecureDeletionSlot, SlotHolder};

const SLOT_COUNT: usize = 16;

#[derive(Default)]
struct TestSlotManager {
    slots: [Option<SecureDeletionData>; SLOT_COUNT],
}

impl SecureDeletionSecretManager for TestSlotManager {
    fn new_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<(SecureDeletionSlot, SecureDeletionData), Error> {
        for idx in 0..SLOT_COUNT {
            if self.slots[idx].is_none() {
                let mut sdd = SecureDeletionData {
                    factory_reset_secret: [0xaa; 32],
                    secure_deletion_secret: [0; 16],
                };
                rng.fill_bytes(&mut sdd.secure_deletion_secret[..]);
                self.slots[idx] = Some(sdd.clone());
                return Ok((SecureDeletionSlot(idx as u32), sdd));
            }
        }
        Err(km_err!(RollbackResistanceUnavailable, "full"))
    }

    fn get_secret(&self, slot: SecureDeletionSlot) -> Result<SecureDeletionData, Error> {
        let idx = slot.0 as usize;
        if !(0..SLOT_COUNT).contains(&idx) {
            return Err(km_err!(InvalidArgument, "slot idx out of bounds"));
        }
        match &self.slots[idx] {
            Some(data) => Ok(data.clone()),
            None => Err(km_err!(InvalidArgument, "slot idx empty")),
        }
    }

    fn delete_secret(&mut self, slot: SecureDeletionSlot) -> Result<(), Error> {
        match self.slots[slot.0 as usize].take() {
            Some(_data) => Ok(()),
            None => Err(km_err!(InvalidArgument, "slot idx empty")),
        }
    }

    fn delete_all(&mut self) {
        for idx in 0..SLOT_COUNT {
            self.slots[idx] = None;
        }
    }
}

#[derive(Default)]
struct FakeRng(u8);

impl crate::crypto::Rng for FakeRng {
    fn add_entropy(&mut self, _data: &[u8]) {}
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.0;
            self.0 += 1;
        }
    }
}

#[test]
fn test_slot_holder() {
    let mut sdd_mgr = TestSlotManager::default();
    let mut rng = FakeRng::default();
    let (slot_holder0, sdd0) = SlotHolder::new(&mut sdd_mgr, &mut rng).unwrap();
    let slot0 = slot_holder0.consume();
    assert_eq!(slot0, SecureDeletionSlot(0));
    assert!(sdd_mgr.get_secret(slot0).unwrap() == sdd0);

    let (slot_holder1, sdd1) = SlotHolder::new(&mut sdd_mgr, &mut rng).unwrap();
    let slot1 = slot_holder1.consume();
    assert_eq!(slot1, SecureDeletionSlot(1));
    assert!(sdd_mgr.get_secret(slot1).unwrap() == sdd1);

    assert!(sdd_mgr.get_secret(slot0).unwrap() == sdd0);
    assert!(sdd_mgr.get_secret(slot1).unwrap() == sdd1);
    assert!(sdd0 != sdd1);

    // If the slot holder is dropped rather than consumed, it should free the slot.
    let (slot_holder2, _sdd2a) = SlotHolder::new(&mut sdd_mgr, &mut rng).unwrap();
    drop(slot_holder2);
    assert!(sdd_mgr.get_secret(SecureDeletionSlot(2)).is_err());

    // Slot 2 is available again.
    let (slot_holder2, sdd2b) = SlotHolder::new(&mut sdd_mgr, &mut rng).unwrap();
    let slot2 = slot_holder2.consume();
    assert_eq!(slot2, SecureDeletionSlot(2));
    assert!(sdd_mgr.get_secret(slot2).unwrap() == sdd2b);
}
