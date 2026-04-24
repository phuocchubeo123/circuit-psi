use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, send_open_shares},
    },
    math::defines::FE,
    network::tcp_channel::SwankyChannel,
};
use anyhow::{Result, anyhow, ensure};

pub fn batch_multiply(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    side: bool,
    channel: &mut SwankyChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        x_shares.len() == y_shares.len(),
        "Length mismatch between x_shares and y_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        y_shares.len()
    );
    ensure!(
        x_shares.len() == triple_shares.len(),
        "Length mismatch between x_shares and triple_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        triple_shares.len()
    );
    for (i, share) in x_shares.iter().enumerate() {
        ensure!(
            share.bedoza_sender().side() == side,
            "x share sender side mismatch at index {}: expected {}, got {}",
            i,
            side,
            share.bedoza_sender().side()
        );
    }
    for (i, share) in y_shares.iter().enumerate() {
        ensure!(
            share.bedoza_sender().side() == side,
            "y share sender side mismatch at index {}: expected {}, got {}",
            i,
            side,
            share.bedoza_sender().side()
        );
    }
    for (i, triple) in triple_shares.iter().enumerate() {
        let (a_share, b_share, c_share) = triple;
        ensure!(
            a_share.bedoza_sender().side() == side
                && b_share.bedoza_sender().side() == side
                && c_share.bedoza_sender().side() == side,
            "triple sender side mismatch at index {}: expected {}",
            i,
            side
        );
    }

    // First compute d = x - a and e = y - b
    let d_shares: Vec<BeDOZa> = x_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            x_share - a_share
        })
        .collect();

    let e_shares: Vec<BeDOZa> = y_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            y_share - b_share
        })
        .collect();

    // Now open d and e to both parties. The two roles use opposite I/O order to avoid both
    // sides blocking on the same receive call.
    let d_senders: Vec<BeDOZaSender> = d_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect();
    let d_receivers: Vec<BeDOZaReceiver> = d_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();

    let e_senders: Vec<BeDOZaSender> = e_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect();
    let e_receivers: Vec<BeDOZaReceiver> = e_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();

    let (d_receiver_values, e_receiver_values) = if !side {
        send_open_shares(&d_senders, channel)
            .map_err(|e| anyhow!("Failed to send open d shares: {}", e))?;
        send_open_shares(&e_senders, channel)
            .map_err(|e| anyhow!("Failed to send open e shares: {}", e))?;

        let d_values = receive_open_shares(&d_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
        let e_values = receive_open_shares(&e_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;
        (d_values, e_values)
    } else {
        let d_values = receive_open_shares(&d_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
        let e_values = receive_open_shares(&e_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;

        send_open_shares(&d_senders, channel)
            .map_err(|e| anyhow!("Failed to send open d shares: {}", e))?;
        send_open_shares(&e_senders, channel)
            .map_err(|e| anyhow!("Failed to send open e shares: {}", e))?;
        (d_values, e_values)
    };

    let d_values: Vec<FE> = d_shares
        .iter()
        .zip(d_receiver_values.iter())
        .map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value)
        .collect();
    let e_values: Vec<FE> = e_shares
        .iter()
        .zip(e_receiver_values.iter())
        .map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value)
        .collect();

    // Compute db and ea locally
    let db_shares: Vec<BeDOZa> = d_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&d, triple_share)| {
            let (_, b_share, _) = triple_share;
            b_share * d
        })
        .collect();

    let ea_shares: Vec<BeDOZa> = e_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&e, triple_share)| {
            let (a_share, _, _) = triple_share;
            a_share * e
        })
        .collect();

    let de_values: Vec<FE> = d_values
        .iter()
        .zip(e_values.iter())
        .map(|(&d, &e)| d * e)
        .collect();

    // Compute the final result: c = ab + db + ea + de
    let xy_shares: Vec<BeDOZa> = triple_shares
        .iter()
        .zip(db_shares.iter())
        .zip(ea_shares.iter())
        .zip(de_values.iter())
        .map(|((((_, _, c_share), db_share), ea_share), &de)| c_share + db_share + ea_share + de)
        .collect();

    Ok(xy_shares)
}
