use super::*;

#[test]
fn test_copyable_tags() {
    for tag in UNPOLICED_COPYABLE_TAGS {
        let info = info(*tag).unwrap();
        assert!(info.user_can_specify.0, "tag {:?} not listed as user-specifiable", tag);
        assert!(
            info.characteristic == info::Characteristic::KeyMintEnforced
                || info.characteristic == info::Characteristic::KeystoreEnforced
                || info.characteristic == info::Characteristic::BothEnforced,
            "tag {:?} with unexpected characteristic {:?}",
            tag,
            info.characteristic
        );
    }
}
