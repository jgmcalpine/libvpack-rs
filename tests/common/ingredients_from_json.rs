//! Build typed export ingredients from reconstruction_ingredients JSON.
//! Used by export_tests and conformance so both use the public export API.

use vpack::export::{
    ArkLabsIngredients, ArkLabsOutput, ArkLabsSibling, SecondTechGenesisStep,
    SecondTechIngredients, SecondTechSibling,
};

const FEE_ANCHOR_SCRIPT_HEX: &str = "51024e73";

#[allow(dead_code)]
fn decode_hex_to_vec(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| e.to_string())
}

#[allow(dead_code)]
fn decode_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex_to_vec(hex_str)?;
    let mut arr = [0u8; 32];
    if bytes.len() < 32 {
        return Err("hash hex shorter than 32 bytes".into());
    }
    arr.copy_from_slice(&bytes[..32]);
    Ok(arr)
}

/// Build ArkLabsIngredients from gold-standard reconstruction_ingredients JSON.
#[allow(dead_code)]
pub fn ark_labs_ingredients_from_json(json: &serde_json::Value) -> Result<ArkLabsIngredients, String> {
    let anchor_str = json["parent_outpoint"]
        .as_str()
        .or_else(|| json["anchor_outpoint"].as_str())
        .ok_or("missing parent_outpoint or anchor_outpoint")?;
    let fee_hex = json["fee_anchor_script"]
        .as_str()
        .unwrap_or(FEE_ANCHOR_SCRIPT_HEX);
    let fee_anchor_script = decode_hex_to_vec(fee_hex)?;
    let n_sequence = json["nSequence"]
        .as_u64()
        .ok_or("missing nSequence")? as u32;

    let outputs: Vec<ArkLabsOutput> = if let Some(arr) = json["outputs"].as_array() {
        arr.iter()
            .map(|o| {
                let value = o["value"].as_u64().unwrap_or(0);
                let script_hex = o["script"].as_str().unwrap_or("");
                let script = decode_hex_to_vec(script_hex).unwrap_or_default();
                ArkLabsOutput { value, script }
            })
            .collect()
    } else {
        vec![]
    };
    let outputs = if outputs.is_empty() {
        // Branch-only vector: synthesize one output from child_output.
        if let Some(co) = json["child_output"].as_object() {
            let value = co["value"].as_u64().unwrap_or(0);
            let script = co["script"]
                .as_str()
                .and_then(|h| decode_hex_to_vec(h).ok())
                .unwrap_or_default();
            vec![ArkLabsOutput { value, script }]
        } else {
            return Err("missing outputs and no child_output".into());
        }
    } else {
        outputs
    };

    let siblings = if let Some(arr) = json["siblings"].as_array() {
        let mut list = Vec::new();
        for s in arr {
            let hash_hex = s["hash"].as_str().ok_or("sibling missing hash")?;
            let hash = decode_hex_32(hash_hex)?;
            let value = s["value"].as_u64().ok_or("sibling missing value")?;
            let script = decode_hex_to_vec(s["script"].as_str().ok_or("sibling missing script")?)?;
            list.push(ArkLabsSibling { hash, value, script });
        }
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    } else {
        None
    };

    let child_output = json["child_output"].as_object().map(|co| {
        let value = co["value"].as_u64().unwrap_or(0);
        let script = co["script"]
            .as_str()
            .and_then(|h| decode_hex_to_vec(h).ok())
            .unwrap_or_default();
        ArkLabsOutput { value, script }
    });

    Ok(ArkLabsIngredients {
        anchor_outpoint: anchor_str.to_string(),
        fee_anchor_script,
        n_sequence,
        outputs,
        siblings,
        child_output,
    })
}

/// Build SecondTechIngredients from gold-standard reconstruction_ingredients JSON.
#[allow(dead_code)]
pub fn second_tech_ingredients_from_json(
    json: &serde_json::Value,
) -> Result<SecondTechIngredients, String> {
    let anchor_str = json["anchor_outpoint"]
        .as_str()
        .or_else(|| json["parent_outpoint"].as_str())
        .ok_or("missing anchor_outpoint or parent_outpoint")?;
    let fee_hex = json["fee_anchor_script"]
        .as_str()
        .unwrap_or(FEE_ANCHOR_SCRIPT_HEX);
    let fee_anchor_script = decode_hex_to_vec(fee_hex)?;
    let amount = json["amount"].as_u64().ok_or("missing amount")?;
    let script_hex = json["script_pubkey_hex"]
        .as_str()
        .or_else(|| json["script"].as_str())
        .ok_or("missing script_pubkey_hex or script")?;
    let script_pubkey = decode_hex_to_vec(script_hex)?;
    let exit_delta = json["exit_delta"].as_u64().unwrap_or(0) as u16;
    let vout = json["vout"].as_u64().unwrap_or(0) as u32;
    let expiry_height = json["expiry_height"].as_u64().unwrap_or(0) as u32;

    let path_array = json["path"].as_array().or_else(|| json["genesis"].as_array());
    let path = if let Some(steps) = path_array {
        steps
            .iter()
            .map(|step| {
                let siblings_arr = step["siblings"].as_array().ok_or("step missing siblings")?;
                let siblings: Vec<SecondTechSibling> = siblings_arr
                    .iter()
                    .map(|s| {
                        let hash = decode_hex_32(s["hash"].as_str().ok_or("sibling hash")?)?;
                        let value = s["value"].as_u64().ok_or("sibling value")?;
                        let script = decode_hex_to_vec(
                            s["script"].as_str().ok_or("sibling script")?,
                        )?;
                        Ok(SecondTechSibling { hash, value, script })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let parent_index = step["parent_index"].as_u64().unwrap_or(0) as u32;
                let sequence = step["sequence"].as_u64().unwrap_or(0) as u32;
                let child_amount = step["child_amount"].as_u64().ok_or("child_amount")?;
                let child_script_hex = step["child_script_pubkey"]
                    .as_str()
                    .or_else(|| step["child_script"].as_str())
                    .ok_or("child_script_pubkey")?;
                let child_script_pubkey = decode_hex_to_vec(child_script_hex)?;
                Ok(SecondTechGenesisStep {
                    siblings,
                    parent_index,
                    sequence,
                    child_amount,
                    child_script_pubkey,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        vec![]
    };

    Ok(SecondTechIngredients {
        anchor_outpoint: anchor_str.to_string(),
        fee_anchor_script,
        amount,
        script_pubkey,
        exit_delta,
        vout,
        expiry_height,
        path,
    })
}
