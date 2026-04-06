use anyhow::{Context, Result, bail};
use circuit_psi::comm_util::{receive_fe, receive_u8, send_fe, send_u8};
use circuit_psi::cope::Cope;
use circuit_psi::network::tcp_channel::{SwankyChannel, connect_with_retry, listen_to};
use circuit_psi::scalar_field::{FOURQ_SCALAR_BITS, FourQScalarField as FE, random_fourq_elements_from_prg};
use psi_aes::prg::PRG;
use std::time::Instant;

const DEFAULT_ADDR: &str = "127.0.0.1:19090";

#[derive(Clone, Copy)]
enum Role {
    Sender,
    Receiver,
}

fn parse_role(s: &str) -> Result<Role> {
    match s {
        "sender" => Ok(Role::Sender),
        "receiver" => Ok(Role::Receiver),
        _ => bail!("invalid role '{s}', expected 'sender' or 'receiver'"),
    }
}

fn random_fe_vec(n: usize) -> Vec<FE> {
    let mut out = vec![FE::zero(); n];
    let mut prg = PRG::new(None, 0);
    random_fourq_elements_from_prg(&mut prg, &mut out);
    out
}

fn print_stats(role: &str, channel: &SwankyChannel, comm: u64) {
    println!("{role}: counted protocol bytes (comm): {comm}");
    println!("{role}: channel bytes sent: {}", channel.bytes_sent());
    println!("{role}: channel bytes received: {}", channel.bytes_received());
}

fn run_sender(n: usize, addr: &str) -> Result<()> {
    let mut channel = connect_with_retry(addr)
        .with_context(|| format!("failed to connect to {addr}"))?;
    let mut comm = 0u64;

    let delta = random_fe_vec(1)[0];

    let init_start = Instant::now();
    let mut cope = Cope::new(0, FOURQ_SCALAR_BITS);
    cope.initialize_sender(&mut channel, delta, &mut comm);
    let init_time = init_start.elapsed();

    let mut x = vec![FE::zero(); n];
    let extend_start = Instant::now();
    cope.extend_sender_batch(&mut channel, &mut x, n, &mut comm);
    let extend_time = extend_start.elapsed();

    let y = receive_fe(&mut channel).context("sender failed to receive y")?;
    let u = receive_fe(&mut channel).context("sender failed to receive u")?;
    if y.len() != n || u.len() != n {
        bail!(
            "sender expected y/u length {n}, got y={}, u={}",
            y.len(),
            u.len()
        );
    }

    let mut ok = true;
    for i in 0..n {
        if y[i] != x[i] + delta * u[i] {
            println!("Mismatch at index {i}");
            ok = false;
            break;
        }
    }

    let status = if ok { 1u8 } else { 0u8 };
    comm += send_u8(&mut channel, &[status]).context("sender failed to send check status")?;

    println!("sender init (create + setup) time: {:?}", init_time);
    println!("sender extend_sender_batch(n={n}) time: {:?}", extend_time);
    println!("sender has {n} values x_i");
    println!("receiver has {n} values y_i and {n} values u_i");
    println!("relation y_i = x_i + delta * u_i: {}", if ok { "PASS" } else { "FAIL" });

    print_stats("sender", &channel, comm);
    Ok(())
}

fn run_receiver(n: usize, addr: &str) -> Result<()> {
    let mut channel = listen_to(addr).with_context(|| format!("failed to listen on {addr}"))?;
    let mut comm = 0u64;

    let init_start = Instant::now();
    let mut cope = Cope::new(1, FOURQ_SCALAR_BITS);
    cope.initialize_receiver(&mut channel, &mut comm);
    let init_time = init_start.elapsed();

    let u = random_fe_vec(n);
    let mut y = vec![FE::zero(); n];

    let extend_start = Instant::now();
    cope.extend_receiver_batch(&mut channel, &mut y, &u, n, &mut comm);
    let extend_time = extend_start.elapsed();

    comm += send_fe(&mut channel, &y).context("receiver failed to send y")?;
    comm += send_fe(&mut channel, &u).context("receiver failed to send u")?;

    let status = receive_u8(&mut channel).context("receiver failed to receive check status")?;
    let ok = status.first().copied() == Some(1u8);

    println!("receiver init (create + setup) time: {:?}", init_time);
    println!("receiver extend_receiver_batch(n={n}) time: {:?}", extend_time);
    println!("sender has {n} values x_i");
    println!("receiver has {n} values y_i and {n} values u_i");
    println!("relation y_i = x_i + delta * u_i: {}", if ok { "PASS" } else { "FAIL" });

    print_stats("receiver", &channel, comm);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!("usage: {} <sender|receiver> <n> [addr]", args[0]);
    }

    let role = parse_role(&args[1])?;
    let n: usize = args[2]
        .parse()
        .with_context(|| format!("invalid n '{}'", args[2]))?;
    if n == 0 {
        bail!("n must be > 0");
    }
    let addr = args.get(3).map(String::as_str).unwrap_or(DEFAULT_ADDR);

    match role {
        Role::Sender => run_sender(n, addr),
        Role::Receiver => run_receiver(n, addr),
    }
}
