/**
 * Gold Standard forensic vectors for the Educational Sandbox.
 * Lazy-loaded to avoid bloating the main bundle.
 */

export type VectorGroup = 'ark_labs' | 'second';

export interface VectorEntry {
  id: string;
  label: string;
  description: string;
  group: VectorGroup;
  /**
   * Anchor value (sats) for Green Audit in Test Mode.
   * Must match sum of outputs / amount for self-consistency.
   */
  anchorValue: number;
  /** JSON string — loaded on demand to keep bundle small */
  getJson: () => string;
}

const ARK_LABS_ROUND_LEAF = `{"meta":{"variant":"0x04","description":"Ark Labs Round Leaf (V3 Anchored) — Gold Standard from arkd"},"raw_evidence":{"expected_vtxo_id":"47ea55bcb18fe596e19e2ad50603216926d12b7f0498d5204abf5604d4a4bc7d"},"reconstruction_ingredients":{"topology":"Tree","tx_version":3,"nSequence":4294967295,"exit_delta":432,"parent_outpoint":"ecdeb06aa5a707d7d91177fd56dae8119d4e1b7505d197a765890ff346e6e3a4:0","fee_anchor_script":"51024e73","id_type":"Hash","outputs":[{"value":1100,"script":"512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"},{"value":0,"script":"51024e73","note":"Fee Anchor"}]}}`;

const ARK_LABS_ROUND_BRANCH = `{"meta":{"variant":"0x04","description":"Ark Labs Intermediate Branch Node (V3 Anchored)"},"raw_evidence":{"psbt_base64":"cHNidP8BAIkCAAAAAct6jsOLEICt1RuMeK6VPdHJkTFc5c00VUX+wmv1xLe3AAAAAAD/////AkwEAAAAAAAAIlEg+qxTOqDe9smxGW5QHZL8ftwZcpZHk71PoN3oNbH7muPoAwAAAAAAACJRICPeS+JBxJ9nwAPr8rA/kSEeHg9wCEMHPhcgiJyfB4r2AAAAAAABASDoAwAAAAAAABepFOqfSG6C77Pdg6af2W4/ARN1faA8hwAAAA==","expected_vtxo_id":"8ab0b71cc66c494ebef13b8b995e5ce5ab3d1b365b289761fefadb0ceb1baec5","unsigned_tx_json":{"Version":3,"TxIn":[{"PreviousOutPoint":{"Hash":"f60017a41c1fb808202c2781bfefc2d57b1aa85e6a473f2873d7c3b7cef2514e","Index":0},"SignatureScript":null,"Witness":null,"Sequence":4294967295}],"TxOut":[{"Value":600,"PkScript":"USD6rFM6oN72ybEZblAdkvx+3BlylkeTvU+g3eg1sfua4w=="},{"Value":500,"PkScript":"USD6rFM6oN72ybEZblAdkvx+3BlylkeTvU+g3eg1sfua4w=="},{"Value":0,"PkScript":"UQJOcw=="}],"LockTime":0}},"reconstruction_ingredients":{"topology":"Tree","tx_version":3,"nSequence":4294967295,"exit_delta":432,"fee_anchor_script":"51024e73","id_type":"Hash","anchor_outpoint":"f60017a41c1fb808202c2781bfefc2d57b1aa85e6a473f2873d7c3b7cef2514e:0","siblings":[{"hash":"25a89a946d6bf1b3d4c353bbcf0de80942cd00cab2bb2afd431f43a45bda2695","value":600,"script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3"},{"hash":"a531344d6f8f18d6ce6bff480149061c33792f4546d6414ea6fa0180aa132e06","value":500,"script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3"}],"child_output":{"value":600,"script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3"}}}`;

const ARK_LABS_OFF_CHAIN_FORFEIT = `{"meta":{"variant":"0x04","description":"Ark Labs OOR Forfeit Transaction (V3 Anchored)"},"raw_evidence":{"unsigned_tx_hex":"0300000001411d0d848ab79c0f7ae5a73742c4addd4e5b5646c2bc4bea854d287107825c750000000000feffffff02e803000000000000150014a1b2c3d4e5f6789012345678901234567890ab00000000000000000451024e7300000000","spending_vtxo_id":"755c820771284d85ea4bbcc246565b4eddadc44237a7e57a0f9cb78a840d1d41","expected_vtxo_id":"a976851480b800e56459a574b42b5c16ea521cac11b7ec9f7741e99d1d177419"},"reconstruction_ingredients":{"topology":"SingleSpend","tx_version":3,"nSequence":4294967294,"exit_delta":144,"fee_anchor_script":"51024e73","id_type":"Hash","parent_outpoint":"755c820771284d85ea4bbcc246565b4eddadc44237a7e57a0f9cb78a840d1d41:0","outputs":[{"value":1000,"script":"0014a1b2c3d4e5f6789012345678901234567890ab"},{"value":0,"script":"51024e73"}]}}`;

const SECOND_BOARDING = `{"meta":{"variant":"0x03","description":"Second Tech Boarding VTXO (Depth 0)"},"raw_evidence":{"expected_vtxo_id":"e06b44a1a628ebae79bdc79a3b6d7409dad40e18d144637c847f393bb2f5e917:0"},"reconstruction_ingredients":{"topology":"Chain","tx_version":3,"nSequence":0,"fee_anchor_script":"51024e73","id_type":"OutPoint","amount":10000,"exit_delta":2016,"script_pubkey_hex":"0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e0","anchor_outpoint":"0000000000000000000000000000000000000000000000000000000000000000:0","path":[]},"legacy_evidence":{"borsh_hex":"01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f200000000010102030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62655d61f465693e1fbf39814e9cb1d57d5eabc49548ed042626cc39c4d5fe5c1836c8c2fb634bceab363212ed4c6a8e78c9ff33884587830ffa2a1cbd84c95e77010000030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee4c99b744ad009b7070f330794bf003fa8e5cd46ea1a6eb854aaf469385e3080000000000"}}`;

const SECOND_RECURSIVE_ROUND = (() => {
  const path = [{"child_amount":12000,"child_script_pubkey":"5120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a8","parent_index":0,"sequence":0,"siblings":[{"hash":"a47f1e66d7dd10a9988172877d0952222d61a12039859bfec7eeadebf7568189","script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3","value":1000}]},{"child_amount":11000,"child_script_pubkey":"5120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a8","parent_index":0,"sequence":0,"siblings":[{"hash":"a47f1e66d7dd10a9988172877d0952222d61a12039859bfec7eeadebf7568189","script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3","value":1000}]},{"child_amount":10000,"child_script_pubkey":"5120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a8","parent_index":0,"sequence":0,"siblings":[{"hash":"a47f1e66d7dd10a9988172877d0952222d61a12039859bfec7eeadebf7568189","script":"5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3","value":1000}]}];
  return JSON.stringify({"meta":{"variant":"0x03","description":"Borsh-serialized Vtxo struct with OutPoint-based ID — 3-step path (forensic audit alignment)"},"raw_evidence":{"expected_vtxo_id":"25a9c204a375d4fc058e8c45ce2919c06324ee2fdf4726a2fd298904ddebe347:0"},"reconstruction_ingredients":{"topology":"Chain","tx_version":3,"nSequence":0,"fee_anchor_script":"51024e73","id_type":"OutPoint","amount":10000,"exit_delta":2016,"script_pubkey_hex":"5120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a8","anchor_outpoint":"0000000000000000000000000000000000000000000000000000000000000000:0","path":path}});
})();

const SECOND_CHAIN_PAYMENT = `{"meta":{"variant":"0x03","description":"Second Tech OOR VTXO (Recursive History)"},"raw_evidence":{"expected_vtxo_id":"495cf8fb8a8f45474304116ae7e63162a040385e4112769108c6b7d2326c467d:0"},"reconstruction_ingredients":{"topology":"Chain","tx_version":3,"nSequence":0,"fee_anchor_script":"51024e73","id_type":"OutPoint","amount":10000,"exit_delta":2016,"script_pubkey_hex":"51202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c","anchor_outpoint":"0000000000000000000000000000000000000000000000000000000000000000:0","path":[]},"legacy_evidence":{"borsh_hex":"01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab00000000050108039e8a040d9c1fba5b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743d272c99b53de1036c5d3f381a6d873a759707ffc98414634943e8568ff9ddf3b57e658e0a5e0ad82daf82e783c1863aff6bccded8569199c1213e8c51407c0f6040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a9510105036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743b707706c721f8b9172188c3a9fa2709a478d40c9a89537405a4ae21df94e90d8ec24d0caa098db3c31d3d25d5414a5febf0e039da137440fa9dd932d759d3646040110270000000000002251202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c8813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd0357ccc0a609082b767909f37a4acdf55d1467bcaab77926b4ffe93edf8f9e8c4ea30a1bb9d23f32ee1c22e12a03c81a58f2c6b0c745e916bcbb2f6b46ca94830061050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d010002010256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecda3f46c1fa220865803e80a3688630644317f8c0a85491d849b4ce7f33d133ccf093c49954b4028aa6d3765b7d07eb6b92649a81a862f8ad39b97278bdefafff3632ac1f2f353abd646ae7d79707ea9ff0144ba8425762145932daef6bd8855bd010002010256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd565b73d5325e68949a264159ea1da8a7d8ba8788f3f63a202d5f3047d2fe9428e63ea5bd23c4524f59efb7213b3cde26f2fb8279f35e0f5b95d74576daa1d8c827af2054c993ea76819668d9b3d184cd48c521f1254e7a0ebeaa2f1b99a6f15d01000002ed1334f116cea9128e1f59f1d5a431cb4f338f0998e2b32f654c310bf7831f97016422a562a4826f26ff351ecb5b1122e0d27958053fd6595a9424a0305fad0700000000"}}`;

const createVector = (
  id: string,
  label: string,
  description: string,
  group: VectorGroup,
  anchorValue: number,
  getJson: () => string,
): VectorEntry => ({
  id,
  label,
  description,
  group,
  anchorValue,
  getJson,
});

export const VECTORS: VectorEntry[] = [
  createVector(
    'round-leaf',
    'Round Leaf',
    'The basic unit. A single user\'s coin inside a communal round.',
    'ark_labs',
    1100,
    () => ARK_LABS_ROUND_LEAF,
  ),
  createVector(
    'intermediate-branch',
    'Intermediate Branch',
    'The \'hallway\' of a tree. A transaction that connects the anchor to the users.',
    'ark_labs',
    1700,
    () => ARK_LABS_ROUND_BRANCH,
  ),
  createVector(
    'off-chain-forfeit',
    'Off-chain Forfeit',
    'An instant payment. A transaction that spends a coin without waiting for a round.',
    'ark_labs',
    1000,
    () => ARK_LABS_OFF_CHAIN_FORFEIT,
  ),
  createVector(
    'boarding-utxo',
    'Boarding UTXO',
    'The entry point. A new coin entering the Ark from the Bitcoin blockchain.',
    'second',
    10000,
    () => SECOND_BOARDING,
  ),
  createVector(
    'recursive-round',
    'Round VTXO',
    'Gold Standard. A coin in a batch. Proves ownership through a shared transaction history.',
    'second',
    13000,
    () => SECOND_RECURSIVE_ROUND,
  ),
  createVector(
    'chain-payment',
    'Chain Payment',
    'A deep-history coin. Proves ownership through a series of previous spends.',
    'second',
    10000,
    () => SECOND_CHAIN_PAYMENT,
  ),
];

export const ARK_LABS_VECTORS = VECTORS.filter((v) => v.group === 'ark_labs');
export const SECOND_VECTORS = VECTORS.filter((v) => v.group === 'second');

/** Selection card content for the "Execution vs. Velocity" narrative. */
export interface ScenarioCardContent {
  headline: string;
  subHeadline: string;
  description: string;
  badge: string;
}

export const SCENARIO_CARD_ARK_LABS: ScenarioCardContent = {
  headline: 'The Virtual Network',
  subHeadline: 'OPTIMIZED FOR SCALE & DEFI',
  description:
    'Processes thousands of transactions in parallel using a **Virtual Mempool**. It aggregates off-chain operations into a **Global State Batch**, enabling complex applications and smart contracts at massive scale.',
  badge: 'Identity: Whole-Transaction Hash (32B)',
};

export const SCENARIO_CARD_SECOND_TECH: ScenarioCardContent = {
  headline: 'The Fluid Chain',
  subHeadline: 'OPTIMIZED FOR VELOCITY & UX',
  description:
    'Uses **Recursive Chaining** to allow money to move instantly from person to person. Coins carry their own history (a **"biography of signatures"**), ensuring seamless payments without waiting for blocks.',
  badge: 'Identity: Individual OutPoint (36B)',
};
