use anyhow::{Result, ensure};
use circuit_psi::{
    bedoza::{BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::defines::FE,
};
use clap::Parser;
use rand::{Rng, RngExt};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(name = "create_fake_triples")]
struct Args {
    #[arg(long)]
    n: usize,
    #[arg(long, default_value = "fake_triples_side0.csv")]
    side0_csv: PathBuf,
    #[arg(long, default_value = "fake_triples_side1.csv")]
    side1_csv: PathBuf,
    #[arg(long, default_value = "delta0.txt")]
    delta0_txt: PathBuf,
    #[arg(long, default_value = "delta1.txt")]
    delta1_txt: PathBuf,
}

fn fe_to_hex(value: FE) -> String {
    let bytes = value.to_bytes_le();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn sample_fe<R: Rng>(rng: &mut R) -> FE {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    FE::from_bytes_le_mod_order(&bytes)
}

fn make_cross_party_share<R: Rng>(
    total_value: FE,
    delta0: FE,
    delta1: FE,
    rng: &mut R,
) -> (BeDOZa, BeDOZa) {
    let share0_value = sample_fe(rng);
    let share1_value = total_value - share0_value;
    let share0_pad = sample_fe(rng);
    let share1_pad = sample_fe(rng);

    let party0 = BeDOZa::new(
        BeDOZaSender::new(share0_value, share0_pad),
        BeDOZaReceiver::new(delta0 * share1_value - share1_pad, delta0),
        false,
    );
    let party1 = BeDOZa::new(
        BeDOZaSender::new(share1_value, share1_pad),
        BeDOZaReceiver::new(delta1 * share0_value - share0_pad, delta1),
        true,
    );

    (party0, party1)
}

fn generate_fake_triples<R: Rng>(
    n: usize,
    delta0: FE,
    delta1: FE,
    rng: &mut R,
) -> (Vec<BeDOZaTriple>, Vec<BeDOZaTriple>) {
    let mut side0 = Vec::with_capacity(n);
    let mut side1 = Vec::with_capacity(n);

    for _ in 0..n {
        let a = sample_fe(rng);
        let b = sample_fe(rng);
        let c = a * b;

        let (a0, a1) = make_cross_party_share(a, delta0, delta1, rng);
        let (b0, b1) = make_cross_party_share(b, delta0, delta1, rng);
        let (c0, c1) = make_cross_party_share(c, delta0, delta1, rng);

        side0.push((a0, b0, c0));
        side1.push((a1, b1, c1));
    }

    (side0, side1)
}

fn write_share_columns(writer: &mut dyn Write, share: &BeDOZa) -> Result<()> {
    write!(
        writer,
        "{},{},{},{},{},{}",
        fe_to_hex(share.bedoza_sender().val()),
        fe_to_hex(share.bedoza_sender().pad()),
        share.side() as u8,
        fe_to_hex(share.bedoza_receiver().tag()),
        fe_to_hex(share.bedoza_receiver().key()),
        (!share.side()) as u8,
    )?;
    Ok(())
}

fn write_triples_csv(path: &Path, triples: &[BeDOZaTriple]) -> Result<()> {
    ensure_parent_dir(path)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "triple_index,\
         a_sender_val,a_sender_pad,a_sender_side,a_receiver_tag,a_receiver_key,a_receiver_side,\
         b_sender_val,b_sender_pad,b_sender_side,b_receiver_tag,b_receiver_key,b_receiver_side,\
         c_sender_val,c_sender_pad,c_sender_side,c_receiver_tag,c_receiver_key,c_receiver_side"
    )?;

    for (i, (a_share, b_share, c_share)) in triples.iter().enumerate() {
        write!(writer, "{i},")?;
        write_share_columns(&mut writer, a_share)?;
        write!(writer, ",")?;
        write_share_columns(&mut writer, b_share)?;
        write!(writer, ",")?;
        write_share_columns(&mut writer, c_share)?;
        writeln!(writer)?;
    }

    writer.flush()?;
    Ok(())
}

fn write_delta_txt(path: &Path, delta: FE) -> Result<()> {
    ensure_parent_dir(path)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", fe_to_hex(delta))?;
    writer.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.side0_csv != args.side1_csv,
        "side0 and side1 CSV outputs must be different files"
    );
    ensure!(
        args.delta0_txt != args.delta1_txt,
        "delta0 and delta1 txt outputs must be different files"
    );

    let mut rng = rand::rng();
    let delta0 = sample_fe(&mut rng);
    let delta1 = sample_fe(&mut rng);
    let (side0_triples, side1_triples) = generate_fake_triples(args.n, delta0, delta1, &mut rng);

    write_triples_csv(&args.side0_csv, &side0_triples)?;
    write_triples_csv(&args.side1_csv, &side1_triples)?;
    write_delta_txt(&args.delta0_txt, delta0)?;
    write_delta_txt(&args.delta1_txt, delta1)?;

    println!(
        "generated_fake_triples n={} side0_csv={} side1_csv={} delta0_txt={} delta1_txt={}",
        args.n,
        args.side0_csv.display(),
        args.side1_csv.display(),
        args.delta0_txt.display(),
        args.delta1_txt.display()
    );

    Ok(())
}
