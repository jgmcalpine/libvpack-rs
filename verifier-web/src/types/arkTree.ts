import type { PathDetail } from './verification';

export type NodeStatus = 'verified' | 'pending' | 'failed';

export interface ArkNode {
  id: string;
  type: 'vtxo' | 'branch' | 'anchor';
  amountSats?: number;
  timelock?: string;
  vBytes: number;
  hex: string;
  status: NodeStatus;
  /** Original PathDetail for modal/details */
  pathDetail: PathDetail;
}

export interface TreeData {
  l1Anchor: ArkNode;
  branches: ArkNode[];
  userVtxo: ArkNode;
}

function truncateId(id: string): string {
  if (!id || id.length < 12) return id;
  return `${id.slice(0, 4)}...${id.slice(-4)}`;
}

export function pathDetailsToTreeData(
  pathDetails: PathDetail[],
  anchorTxid: string,
  finalVtxoId: string,
  status: NodeStatus = 'verified'
): TreeData | null {
  const safe = Array.isArray(pathDetails) ? pathDetails : [];
  if (safe.length === 0) return null;

  const anchor = safe[0];
  const branches = safe.slice(1, -1);
  const leaf = safe[safe.length - 1];

  const l1Anchor: ArkNode = {
    id: anchorTxid || anchor.txid || 'L1',
    type: 'anchor',
    amountSats: anchor.amount,
    vBytes: anchor.exit_weight_vb,
    hex: '',
    status,
    pathDetail: anchor,
  };

  const branchNodes: ArkNode[] = branches.map((p) => ({
    id: truncateId(p.txid),
    type: 'branch' as const,
    amountSats: p.amount,
    timelock: '24 hours',
    vBytes: p.exit_weight_vb,
    hex: p.signed_tx_hex ?? p.tx_preimage_hex ?? '',
    status,
    pathDetail: p,
  }));

  const userVtxo: ArkNode = {
    id: truncateId(finalVtxoId),
    type: 'vtxo' as const,
    amountSats: leaf.amount,
    vBytes: leaf.exit_weight_vb,
    hex: leaf.signed_tx_hex ?? leaf.tx_preimage_hex ?? '',
    status,
    pathDetail: leaf,
  };

  return { l1Anchor, branches: branchNodes, userVtxo };
}
