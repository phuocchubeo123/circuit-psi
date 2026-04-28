use circuit_psi::{
    bedoza::{BeDOZa, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::defines::FE,
};

fn fe(n: u8) -> FE {
    FE::from(n as u64)
}

fn make_secret_shares(
    secret: FE,
    left_value: FE,
    left_pad: FE,
    right_pad: FE,
    left_key: FE,
    right_key: FE,
) -> (BeDOZa, BeDOZa) {
    let right_value = secret - left_value;
    let left = BeDOZa::new(
        BeDOZaSender::new(left_value, left_pad),
        BeDOZaReceiver::new(left_key * right_value - right_pad, left_key),
        false,
    );
    let right = BeDOZa::new(
        BeDOZaSender::new(right_value, right_pad),
        BeDOZaReceiver::new(right_key * left_value - left_pad, right_key),
        true,
    );
    (left, right)
}

fn reconstruct_value(left: &BeDOZa, right: &BeDOZa) -> FE {
    left.bedoza_sender().val() + right.bedoza_sender().val()
}

fn assert_cross_tag_checks(local: &BeDOZa, remote: &BeDOZa) {
    let expected_tag =
        local.bedoza_receiver().key() * remote.bedoza_sender().val() - remote.bedoza_sender().pad();
    assert_eq!(local.bedoza_receiver().tag(), expected_tag);
}

#[test]
fn bedoza_add_preserves_value_and_tags() {
    let key_left = fe(9);
    let key_right = fe(41);
    let x_secret = fe(17);
    let y_secret = fe(23);

    let (x_left, x_right) = make_secret_shares(x_secret, fe(5), fe(3), fe(7), key_left, key_right);
    let (y_left, y_right) =
        make_secret_shares(y_secret, fe(11), fe(13), fe(19), key_left, key_right);

    let z_left = &x_left + &y_left;
    let z_right = &x_right + &y_right;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret + y_secret);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}

#[test]
fn bedoza_sub_preserves_value_and_tags() {
    let key_left = fe(29);
    let key_right = fe(47);
    let x_secret = fe(31);
    let y_secret = fe(7);

    let (x_left, x_right) =
        make_secret_shares(x_secret, fe(4), fe(21), fe(12), key_left, key_right);
    let (y_left, y_right) = make_secret_shares(y_secret, fe(2), fe(8), fe(16), key_left, key_right);

    let z_left = &x_left - &y_left;
    let z_right = &x_right - &y_right;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret - y_secret);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}

#[test]
fn bedoza_mul_constant_preserves_value_and_tags() {
    let key_left = fe(14);
    let key_right = fe(33);
    let x_secret = fe(27);
    let constant = fe(6);

    let (x_left, x_right) =
        make_secret_shares(x_secret, fe(9), fe(10), fe(22), key_left, key_right);

    let z_left = &x_left * constant;
    let z_right = &x_right * constant;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret * constant);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}

#[test]
fn bedoza_add_constant_preserves_value_and_tags() {
    let key_left = fe(52);
    let key_right = fe(77);
    let x_secret = fe(19);
    let constant = fe(11);

    let (x_left, x_right) =
        make_secret_shares(x_secret, fe(6), fe(15), fe(24), key_left, key_right);

    let z_left = &x_left + constant;
    let z_right = &x_right + constant;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret + constant);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}

#[test]
fn bedoza_sub_constant_preserves_value_and_tags() {
    let key_left = fe(81);
    let key_right = fe(101);
    let x_secret = fe(55);
    let constant = fe(13);

    let (x_left, x_right) =
        make_secret_shares(x_secret, fe(21), fe(9), fe(28), key_left, key_right);

    let z_left = &x_left - constant;
    let z_right = &x_right - constant;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret - constant);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}

#[test]
fn bedoza_mul_fe_owned_preserves_value_and_tags() {
    let key_left = fe(35);
    let key_right = fe(62);
    let x_secret = fe(44);
    let constant = fe(3);

    let (x_left, x_right) =
        make_secret_shares(x_secret, fe(12), fe(5), fe(17), key_left, key_right);

    let z_left = x_left * constant;
    let z_right = x_right * constant;

    assert_eq!(reconstruct_value(&z_left, &z_right), x_secret * constant);
    assert_cross_tag_checks(&z_left, &z_right);
    assert_cross_tag_checks(&z_right, &z_left);
}
