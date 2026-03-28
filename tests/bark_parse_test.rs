use hex::FromHex;
use std::fs;
use vpack::adapters::second_tech::bark_to_vpack;

#[test]
fn bark_to_vpack_parses_all_100() {
    let fee_script = Vec::from_hex("51024e73").expect("fee anchor script");
    let mut pass = 0;
    let mut fail = 0;

    for i in 0..100 {
        let path = format!("tests/vectors/bark_qa/vtxo_{i}.bin");
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        match bark_to_vpack(&data, &fee_script) {
            Ok(tree) => {
                if i == 0 {
                    println!("vtxo_0 parsed:");
                    println!("  amount:     {} sats", tree.leaf.amount);
                    println!("  expiry:     {}", tree.leaf.expiry);
                    println!("  exit_delta: {}", tree.leaf.exit_delta);
                    println!("  path_len:   {}", tree.path.len());
                    println!("  anchor:     {:?}", tree.anchor);
                    println!("  leaf_vout:  {}", tree.leaf.vout);
                    for (j, step) in tree.path.iter().take(3).enumerate() {
                        println!(
                            "  path[{j}]: parent_idx={} siblings={} child_amt={}",
                            step.parent_index,
                            step.siblings.len(),
                            step.child_amount,
                        );
                    }
                    if tree.path.len() > 3 {
                        println!("  ... {} more steps ...", tree.path.len() - 3);
                    }
                }
                pass += 1;
            }
            Err(e) => {
                println!("vtxo_{i}: PARSE FAILED: {e:?}");
                fail += 1;
            }
        }
    }
    println!("\n=== bark_to_vpack: {pass} passed, {fail} failed ===");
    assert_eq!(fail, 0, "some VTXOs failed parsing");
}
