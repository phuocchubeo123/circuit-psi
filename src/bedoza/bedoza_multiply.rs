use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, send_open_shares},
        comm_util::{receive_fe_vec, send_fe_vec},
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
    // Various Length Asserts
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
            share.side() == side,
            "x share sender side mismatch at index {}: expected {}, got {}",
            i,
            side,
            share.side()
        );
    }
    for (i, share) in y_shares.iter().enumerate() {
        ensure!(
            share.side() == side,
            "y share sender side mismatch at index {}: expected {}, got {}",
            i,
            side,
            share.side()
        );
    }
    for (i, triple) in triple_shares.iter().enumerate() {
        let (a_share, b_share, c_share) = triple;
        ensure!(
            a_share.side() == side && b_share.side() == side && c_share.side() == side,
            "triple sender side mismatch at index {}: expected {}",
            i,
            side
        );
    }

    let start = std::time::Instant::now();

    // First compute d = x - a and e = y - b
    let d_shares: Vec<BeDOZa> = x_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            x_share - a_share
        })
        .collect();

    println!("Time elapsed: {:?}", start.elapsed());

    let e_shares: Vec<BeDOZa> = y_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            y_share - b_share
        })
        .collect();

    println!("Time elapsed: {:?}", start.elapsed());

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

    println!("Time elapsed: {:?}", start.elapsed());

    let e_senders: Vec<BeDOZaSender> = e_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect();
    let e_receivers: Vec<BeDOZaReceiver> = e_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();

    println!("Time elapsed: {:?}", start.elapsed());

    let (d_receiver_values, e_receiver_values) = if !side {
        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());
        send_open_shares(&d_senders, channel)
            .map_err(|e| anyhow!("Failed to send open d shares: {}", e))?;
        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());
        send_open_shares(&e_senders, channel)
            .map_err(|e| anyhow!("Failed to send open e shares: {}", e))?;
        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());

        let d_values = receive_open_shares(&d_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
        println!("Time elapsed: {:?}", start.elapsed());
        let e_values = receive_open_shares(&e_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;
        println!("Time elapsed: {:?}", start.elapsed());
        (d_values, e_values)
    } else {
        let d_values = receive_open_shares(&d_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
        let e_values = receive_open_shares(&e_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;

        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());
        send_open_shares(&d_senders, channel)
            .map_err(|e| anyhow!("Failed to send open d shares: {}", e))?;
        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());
        send_open_shares(&e_senders, channel)
            .map_err(|e| anyhow!("Failed to send open e shares: {}", e))?;
        println!("Channel bytes sent until this point: {}", channel.bytes_sent());
        println!("Time elapsed: {:?}", start.elapsed());
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

fn finish_batch_multiply(
    triple_shares: &[BeDOZaTriple],
    d_values: &[FE],
    e_values: &[FE],
) -> Vec<BeDOZa> {
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

    triple_shares
        .iter()
        .zip(db_shares.iter())
        .zip(ea_shares.iter())
        .zip(de_values.iter())
        .map(|((((_, _, c_share), db_share), ea_share), &de)| c_share + db_share + ea_share + de)
        .collect()
}

pub fn batch_multiply_cross_owned_sender(
    x_sender_shares: &[BeDOZaSender],
    y_receiver_shares: &[BeDOZaReceiver],
    triple_shares: &[BeDOZaTriple],
    channel: &mut SwankyChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        x_sender_shares.len() == y_receiver_shares.len(),
        "Length mismatch between sender-owned x values and receiver-owned y values: lhs = {}, rhs = {}",
        x_sender_shares.len(),
        y_receiver_shares.len()
    );
    ensure!(
        x_sender_shares.len() == triple_shares.len(),
        "Length mismatch between cross-owned inputs and triple_shares: lhs = {}, rhs = {}",
        x_sender_shares.len(),
        triple_shares.len()
    );

    let d_sender_shares: Vec<BeDOZaSender> = x_sender_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            *x_share - *a_share.bedoza_sender()
        })
        .collect();
    send_open_shares(&d_sender_shares, channel)
        .map_err(|e| anyhow!("Failed to send sender-side d openings: {}", e))?;
    let d_values =
        receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive opened d values: {}", e))?;
    ensure!(
        d_values.len() == x_sender_shares.len(),
        "Opened d length mismatch: expected {}, got {}",
        x_sender_shares.len(),
        d_values.len()
    );

    let e_receiver_shares: Vec<BeDOZaReceiver> = y_receiver_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            *y_share - *b_share.bedoza_receiver()
        })
        .collect();
    let opened_e_values = receive_open_shares(&e_receiver_shares, channel)
        .map_err(|e| anyhow!("Failed to receive opened e shares: {}", e))?;
    let e_values: Vec<FE> = opened_e_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&opened_e, triple_share)| {
            let (_, b_share, _) = triple_share;
            opened_e - b_share.bedoza_sender().val()
        })
        .collect();
    send_fe_vec(&e_values, channel)
        .map_err(|e| anyhow!("Failed to send opened e values: {}", e))?;

    Ok(finish_batch_multiply(triple_shares, &d_values, &e_values))
}

pub fn batch_multiply_cross_owned_receiver(
    x_receiver_shares: &[BeDOZaReceiver],
    y_sender_shares: &[BeDOZaSender],
    triple_shares: &[BeDOZaTriple],
    channel: &mut SwankyChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        x_receiver_shares.len() == y_sender_shares.len(),
        "Length mismatch between sender-owned x values and receiver-owned y values: lhs = {}, rhs = {}",
        x_receiver_shares.len(),
        y_sender_shares.len()
    );
    ensure!(
        x_receiver_shares.len() == triple_shares.len(),
        "Length mismatch between cross-owned inputs and triple_shares: lhs = {}, rhs = {}",
        x_receiver_shares.len(),
        triple_shares.len()
    );

    let d_receiver_shares: Vec<BeDOZaReceiver> = x_receiver_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            *x_share - *a_share.bedoza_receiver()
        })
        .collect();
    let opened_d_values = receive_open_shares(&d_receiver_shares, channel)
        .map_err(|e| anyhow!("Failed to receive opened d shares: {}", e))?;
    let d_values: Vec<FE> = opened_d_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&opened_d, triple_share)| {
            let (a_share, _, _) = triple_share;
            opened_d - a_share.bedoza_sender().val()
        })
        .collect();
    send_fe_vec(&d_values, channel)
        .map_err(|e| anyhow!("Failed to send opened d values: {}", e))?;

    let e_sender_shares: Vec<BeDOZaSender> = y_sender_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            *y_share - *b_share.bedoza_sender()
        })
        .collect();
    send_open_shares(&e_sender_shares, channel)
        .map_err(|e| anyhow!("Failed to send receiver-side e openings: {}", e))?;
    let e_values =
        receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive opened e values: {}", e))?;
    ensure!(
        e_values.len() == y_sender_shares.len(),
        "Opened e length mismatch: expected {}, got {}",
        y_sender_shares.len(),
        e_values.len()
    );

    Ok(finish_batch_multiply(triple_shares, &d_values, &e_values))
}
