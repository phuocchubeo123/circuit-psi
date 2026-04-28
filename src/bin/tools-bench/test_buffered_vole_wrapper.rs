use circuit_psi::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use clap::Parser;
use eyre::WrapErr;
use std::{net::TcpListener, thread, time::Instant};
use swanky_channel_legacy::AesRng;

const DEFAULT_EXTEND_CHUNK: usize = 10_000;
const DEFAULT_MATERIALIZE_1: usize = 6_000;
const DEFAULT_MATERIALIZE_2: usize = 11_000;

#[derive(Debug, Clone)]
struct OpStats {
    name: &'static str,
    elapsed_ms: f64,
    bytes_sent_delta: u64,
    bytes_received_delta: u64,
}

#[derive(Debug, Clone, Copy, Parser)]
#[command(name = "test_buffered_vole_wrapper")]
struct Args {
    #[arg(long, default_value_t = DEFAULT_EXTEND_CHUNK)]
    extend_chunk: usize,
    #[arg(long, default_value_t = DEFAULT_MATERIALIZE_1)]
    materialize_1: usize,
    #[arg(long, default_value_t = DEFAULT_MATERIALIZE_2)]
    materialize_2: usize,
}

#[derive(Debug, Clone, Copy)]
enum CommitMode {
    ReturnVec,
    InPlaceBuffer,
}

impl CommitMode {
    fn label(self) -> &'static str {
        match self {
            CommitMode::ReturnVec => "return_vec",
            CommitMode::InPlaceBuffer => "in_place_buffer",
        }
    }
}

struct SenderRun {
    random_out: Vec<BeDOZaSender>,
    out_1: Vec<BeDOZaSender>,
    out_2: Vec<BeDOZaSender>,
    stats: Vec<OpStats>,
    bytes_sent: u64,
    bytes_received: u64,
    random_left: usize,
}

struct ReceiverRun {
    random_out: Vec<BeDOZaReceiver>,
    out_1: Vec<BeDOZaReceiver>,
    out_2: Vec<BeDOZaReceiver>,
    stats: Vec<OpStats>,
    bytes_sent: u64,
    bytes_received: u64,
    random_left: usize,
}

fn make_inputs(offset: u64, n: usize) -> Vec<FE> {
    (0..n).map(|i| fq(offset + i as u64)).collect()
}

fn sender_party(
    addr: &str,
    extend_chunk: usize,
    materialize_1: usize,
    materialize_2: usize,
    mode: CommitMode,
) -> eyre::Result<SenderRun> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;

    let _rng = AesRng::new();
    let mut vole = BufferedVoleSender::init(&mut channel, LPN21)?;

    let random_count = extend_chunk;
    let mut stats = Vec::with_capacity(3);

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let random_out = vole.random_auth(&mut channel, random_count)?;
    stats.push(OpStats {
        name: "random_auth",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    let inputs_1 = make_inputs(1_000, materialize_1);
    let inputs_2 = make_inputs(50_000, materialize_2);

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let out_1 = match mode {
        CommitMode::ReturnVec => vole.commit_auth(&mut channel, &inputs_1)?,
        CommitMode::InPlaceBuffer => {
            let mut out = Vec::with_capacity(materialize_1);
            vole.commit_auth_into(&mut channel, &inputs_1, &mut out)?;
            out
        }
    };
    stats.push(OpStats {
        name: "commit_auth_1",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let out_2 = match mode {
        CommitMode::ReturnVec => vole.commit_auth(&mut channel, &inputs_2)?,
        CommitMode::InPlaceBuffer => {
            let mut out = Vec::with_capacity(materialize_2);
            vole.commit_auth_into(&mut channel, &inputs_2, &mut out)?;
            out
        }
    };
    stats.push(OpStats {
        name: "commit_auth_2",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    Ok(SenderRun {
        random_out,
        out_1,
        out_2,
        stats,
        bytes_sent: channel.bytes_sent(),
        bytes_received: channel.bytes_received(),
        random_left: vole.random_available(),
    })
}

fn receiver_party(
    addr: &str,
    delta: FE,
    extend_chunk: usize,
    materialize_1: usize,
    materialize_2: usize,
    mode: CommitMode,
) -> eyre::Result<ReceiverRun> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;

    let _rng = AesRng::new();
    let mut vole = BufferedVoleReceiver::init(&mut channel, delta, LPN21)?;

    let random_count = extend_chunk;
    let mut stats = Vec::with_capacity(3);

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let random_out = vole.random_auth(&mut channel, random_count)?;
    stats.push(OpStats {
        name: "random_auth",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let out_1 = match mode {
        CommitMode::ReturnVec => vole.commit_auth(&mut channel, materialize_1)?,
        CommitMode::InPlaceBuffer => {
            let mut out = Vec::with_capacity(materialize_1);
            vole.commit_auth_into(&mut channel, materialize_1, &mut out)?;
            out
        }
    };
    stats.push(OpStats {
        name: "commit_auth_1",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    let before_sent = channel.bytes_sent();
    let before_received = channel.bytes_received();
    let started = Instant::now();
    let out_2 = match mode {
        CommitMode::ReturnVec => vole.commit_auth(&mut channel, materialize_2)?,
        CommitMode::InPlaceBuffer => {
            let mut out = Vec::with_capacity(materialize_2);
            vole.commit_auth_into(&mut channel, materialize_2, &mut out)?;
            out
        }
    };
    stats.push(OpStats {
        name: "commit_auth_2",
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes_sent_delta: channel.bytes_sent() - before_sent,
        bytes_received_delta: channel.bytes_received() - before_received,
    });

    Ok(ReceiverRun {
        random_out,
        out_1,
        out_2,
        stats,
        bytes_sent: channel.bytes_sent(),
        bytes_received: channel.bytes_received(),
        random_left: vole.random_available(),
    })
}

fn verify_batch(delta: FE, sender_out: &[BeDOZaSender], receiver_out: &[BeDOZaReceiver]) {
    assert_eq!(sender_out.len(), receiver_out.len());
    for (sv, rv) in sender_out.iter().zip(receiver_out.iter()) {
        assert_eq!(sv.val() * delta - sv.pad(), rv.tag());
    }
}

fn print_op_stats(prefix: &str, mode: CommitMode, stats: &[OpStats]) {
    for stat in stats {
        println!(
            "{} mode={} op={} time_ms={:.3} bytes_sent_delta={} bytes_received_delta={}",
            prefix,
            mode.label(),
            stat.name,
            stat.elapsed_ms,
            stat.bytes_sent_delta,
            stat.bytes_received_delta
        );
    }
}

fn run_mode(args: &Args, delta: FE, mode: CommitMode) -> eyre::Result<()> {
    let extend_chunk = args.extend_chunk;
    let materialize_1 = args.materialize_1;
    let materialize_2 = args.materialize_2;

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr_str = listener
        .local_addr()
        .wrap_err("read listener address")?
        .to_string();
    drop(listener);

    let sender_addr = addr_str.clone();
    let sender_handle = thread::spawn(move || {
        sender_party(
            &sender_addr,
            extend_chunk,
            materialize_1,
            materialize_2,
            mode,
        )
    });

    let receiver_run = receiver_party(
        &addr_str,
        delta,
        extend_chunk,
        materialize_1,
        materialize_2,
        mode,
    )?;
    let sender_run = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender party failed")?;

    verify_batch(delta, &sender_run.random_out, &receiver_run.random_out);
    verify_batch(delta, &sender_run.out_1, &receiver_run.out_1);
    verify_batch(delta, &sender_run.out_2, &receiver_run.out_2);

    println!(
        "buffered VOLE wrapper check passed mode={} random_auth={} materialized=({}, {})",
        mode.label(),
        extend_chunk,
        sender_run.out_1.len(),
        sender_run.out_2.len(),
    );
    println!(
        "mode={} random buffer left: sender={} receiver={}",
        mode.label(),
        sender_run.random_left,
        receiver_run.random_left
    );
    println!(
        "mode={} sender bytes: sent={} received={} | receiver bytes: sent={} received={}",
        mode.label(),
        sender_run.bytes_sent,
        sender_run.bytes_received,
        receiver_run.bytes_sent,
        receiver_run.bytes_received
    );
    print_op_stats("sender", mode, &sender_run.stats);
    print_op_stats("receiver", mode, &receiver_run.stats);

    Ok(())
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let delta = fq(7);

    run_mode(&args, delta, CommitMode::ReturnVec)?;
    run_mode(&args, delta, CommitMode::InPlaceBuffer)?;

    Ok(())
}
