use ark::bitcoin::hashes::Hash;
use ark::encode::ProtocolEncoding;
use ark::vtxo::Vtxo;
use ark::VtxoPolicy;
use std::fs;

#[test]
fn decode_vtxo_with_arklib() {
    let data = fs::read("tests/vectors/bark_qa/vtxo_0.bin").expect("read vtxo_0");
    let vtxo: Vtxo<ark::vtxo::Full, VtxoPolicy> =
        Vtxo::deserialize(&data).expect("deserialize vtxo_0");

    println!("=== VTXO decoded successfully ===");
    println!("  amount:          {} sats", vtxo.amount().to_sat());
    println!("  expiry_height:   {}", vtxo.expiry_height());
    println!("  server_pubkey:   {:?}", vtxo.server_pubkey());
    println!("  exit_delta:      {}", vtxo.exit_delta());
    println!("  chain_anchor:    {}", vtxo.chain_anchor());
    println!("  id:              {}", vtxo.id());
    println!("  point:           {}", vtxo.point());
    println!("  policy_type:     {:?}", vtxo.policy_type());

    let output_spk = vtxo.output_script_pubkey();
    println!("  output_spk:      {}", hex::encode(output_spk.as_bytes()));

    let output_taproot = vtxo.output_taproot();
    println!(
        "  output_key_x:    {}",
        hex::encode(output_taproot.output_key().serialize())
    );
    println!(
        "  internal_key_x:  {}",
        hex::encode(output_taproot.internal_key().serialize())
    );
    let merkle_root = output_taproot.merkle_root();
    println!(
        "  merkle_root:     {:?}",
        merkle_root.map(|m| hex::encode(m.as_byte_array()))
    );

    let txs: Vec<_> = vtxo.transactions().collect();
    println!("\n  nb_exit_txs:     {}", txs.len());

    // Show first 3 and last 3 exit txs
    for i in 0..txs.len().min(3) {
        print_tx_info(i, &txs[i]);
    }
    if txs.len() > 6 {
        println!("  ... ({} more) ...", txs.len() - 6);
    }
    for i in txs.len().saturating_sub(3)..txs.len() {
        if i >= 3 {
            print_tx_info(i, &txs[i]);
        }
    }

    // Note: validate() needs the anchor tx, skip for now
}

fn print_tx_info(i: usize, item: &ark::vtxo::VtxoTxIterItem) {
    let tx = &item.tx;
    println!("  exit_tx[{i}]:");
    println!("    txid:    {}", tx.compute_txid());
    println!("    input:   {}", tx.input[0].previous_output);
    println!("    out_idx: {}", item.output_idx);
    for (j, out) in tx.output.iter().enumerate() {
        println!(
            "    out[{j}]: {} sats  spk={}",
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes())
        );
    }
}

#[test]
fn verify_all_vtxos() {
    let mut pass = 0;
    let mut fail = 0;
    for i in 0..100 {
        let path = format!("tests/vectors/bark_qa/vtxo_{i}.bin");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let vtxo: Vtxo<ark::vtxo::Full, VtxoPolicy> = match Vtxo::deserialize(&data) {
            Ok(v) => v,
            Err(e) => {
                println!("vtxo_{i}: DESERIALIZE FAILED: {e}");
                fail += 1;
                continue;
            }
        };
        let output_taproot = vtxo.output_taproot();
        let _output_spk = vtxo.output_script_pubkey();
        let txs: Vec<_> = vtxo.transactions().collect();
        println!(
            "vtxo_{i}: OK  amount={} sats  exit_txs={}  output_key={}",
            vtxo.amount().to_sat(),
            txs.len(),
            hex::encode(output_taproot.output_key().serialize()),
        );
        pass += 1;
    }
    println!("\n=== Results: {pass} passed, {fail} failed ===");
    assert_eq!(fail, 0, "some VTXOs failed validation");
}
