use std::{fs, path::Path};

use eyre::Result;

use crate::{
    bedoza::{BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::defines::FE,
};

fn parse_u8_field(raw: &str, field_name: &str) -> Result<u8> {
    raw.parse::<u8>()
        .map_err(|e| eyre::eyre!("invalid {field_name} value `{raw}`: {e}"))
}

pub fn hex_to_fe(hex: &str) -> Result<FE> {
    let hex = hex.trim();
    eyre::ensure!(
        hex.len() == 64,
        "expected 64 hex chars for FE encoding, got {}",
        hex.len()
    );
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk)
            .map_err(|e| eyre::eyre!("invalid utf8 in FE hex encoding: {e}"))?;
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| eyre::eyre!("invalid FE hex byte `{part}`: {e}"))?;
    }
    FE::from_bytes_le(&bytes).map_err(|e| eyre::eyre!("invalid FE canonical encoding: {:?}", e))
}

fn parse_share(fields: &[&str], offset: usize) -> Result<BeDOZa> {
    eyre::ensure!(
        fields.len() >= offset + 6,
        "expected at least {} fields, got {}",
        offset + 6,
        fields.len()
    );

    let sender_val = hex_to_fe(fields[offset])?;
    let sender_pad = hex_to_fe(fields[offset + 1])?;
    let sender_side = parse_u8_field(fields[offset + 2], "sender_side")?;
    eyre::ensure!(sender_side <= 1, "sender_side must be 0 or 1");

    let receiver_tag = hex_to_fe(fields[offset + 3])?;
    let receiver_key = hex_to_fe(fields[offset + 4])?;
    let receiver_side = parse_u8_field(fields[offset + 5], "receiver_side")?;
    eyre::ensure!(receiver_side <= 1, "receiver_side must be 0 or 1");
    eyre::ensure!(
        receiver_side != sender_side,
        "expected sender_side and receiver_side to differ"
    );

    Ok(BeDOZa::new(
        BeDOZaSender::new(sender_val, sender_pad),
        BeDOZaReceiver::new(receiver_tag, receiver_key),
        sender_side == 1,
    ))
}

pub fn read_fe_txt(path: &Path, label: &str) -> Result<FE> {
    let content = fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read {label} txt {}: {e}", path.display()))?;
    let first_line = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| eyre::eyre!("{label} txt {} is empty", path.display()))?;
    hex_to_fe(first_line)
}

pub fn read_triples_csv(path: &Path) -> Result<Vec<BeDOZaTriple>> {
    let content = fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read triples csv {}: {e}", path.display()))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| eyre::eyre!("triples csv {} is empty", path.display()))?;
    eyre::ensure!(
        header.starts_with("triple_index,"),
        "unexpected triples csv header in {}",
        path.display()
    );

    let mut triples = Vec::new();
    for (line_no, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();
        eyre::ensure!(
            fields.len() == 19,
            "expected 19 csv fields at data line {}, got {}",
            line_no + 2,
            fields.len()
        );

        let _triple_index = fields[0]
            .parse::<usize>()
            .map_err(|e| eyre::eyre!("invalid triple_index at line {}: {}", line_no + 2, e))?;
        let a_share = parse_share(&fields, 1)?;
        let b_share = parse_share(&fields, 7)?;
        let c_share = parse_share(&fields, 13)?;
        triples.push((a_share, b_share, c_share));
    }

    Ok(triples)
}
