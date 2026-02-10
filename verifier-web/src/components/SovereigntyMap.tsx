import { useState } from 'react';
import { Link2, GitBranch, Coins, Ghost } from 'lucide-react';
import type { PathDetail } from '../types/verification';
import NodeDetailModal from './NodeDetailModal';

interface SovereigntyMapProps {
  pathDetails: PathDetail[];
  anchorTxid: string;
  finalVtxoId: string;
  variant: string;
  siblingCount?: number;
}

function SovereigntyMap({ pathDetails, anchorTxid, finalVtxoId, variant, siblingCount }: SovereigntyMapProps) {
  const [selectedNode, setSelectedNode] = useState<PathDetail | null>(null);

  const safePathDetails = Array.isArray(pathDetails) ? pathDetails : [];
  const anchorNode = safePathDetails[0];
  const intermediateNodes = safePathDetails.slice(1, -1);
  const leafNode = safePathDetails[safePathDetails.length - 1];

  const truncateTxid = (txid: string, length: number = 16) => {
    if (!txid || txid.length <= length * 2) return txid;
    return `${txid.slice(0, length)}...${txid.slice(-length)}`;
  };

  const displayAnchorTxid = anchorTxid || anchorNode?.txid || '';

  return (
    <div className="w-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Your Sovereignty Path</h2>
        {siblingCount !== undefined && siblingCount > 0 && (
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <Ghost className="w-5 h-5" />
            <span className="text-sm">Other Siblings</span>
          </div>
        )}
      </div>

      {/* Vertical Tree */}
      <div className="flex flex-col items-center space-y-6">
        {/* Anchor Node */}
        {anchorNode && (
          <div className="relative w-full max-w-md">
            <button
              onClick={() => setSelectedNode(anchorNode)}
              className="w-full p-6 bg-gradient-to-br from-amber-50 to-amber-100 dark:from-amber-900/20 dark:to-amber-800/20 border-2 border-amber-300 dark:border-amber-700 rounded-lg shadow-lg hover:shadow-xl transition-all hover:scale-105 cursor-pointer group"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-amber-200 dark:bg-amber-800/40 rounded-lg group-hover:bg-amber-300 dark:group-hover:bg-amber-700/40 transition-colors">
                  <Link2 className="w-6 h-6 text-amber-800 dark:text-amber-200" />
                </div>
                <div className="flex-1 text-left">
                  <div className="text-xs font-semibold text-amber-700 dark:text-amber-300 uppercase tracking-wide mb-1">
                    Anchor (L1)
                  </div>
                  <div className="font-mono text-sm text-gray-900 dark:text-gray-100 mb-2 break-all">
                    {displayAnchorTxid ? truncateTxid(displayAnchorTxid) : 'Anchor (L1)'}
                  </div>
                  <div className="flex items-center gap-4 text-xs text-gray-600 dark:text-gray-400">
                    <span>{anchorNode.amount.toLocaleString()} sats</span>
                    <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                      Exit: ~{anchorNode.exit_weight_vb} vB
                    </span>
                  </div>
                </div>
              </div>
            </button>
            {/* Connector - green if next node has verified signature */}
            {intermediateNodes.length > 0 || leafNode ? (
              <div
                className={`absolute left-1/2 transform -translate-x-1/2 w-0.5 h-6 mt-2 ${
                  (intermediateNodes.length > 0 && intermediateNodes[0]?.has_signature) ||
                  (intermediateNodes.length === 0 && leafNode?.has_signature)
                    ? 'bg-green-500 dark:bg-green-400'
                    : 'bg-gray-300 dark:bg-gray-600'
                }`}
              />
            ) : null}
          </div>
        )}

        {/* Intermediate Nodes */}
        {intermediateNodes.map((node, index) => {
          const nextNode = index + 1 < intermediateNodes.length ? intermediateNodes[index + 1] : leafNode;
          const connectorColor =
            node.has_signature || nextNode?.has_signature
              ? 'bg-green-500 dark:bg-green-400'
              : 'bg-gray-300 dark:bg-gray-600';

          return (
            <div key={index} className="relative w-full max-w-md">
              <div className={`absolute left-1/2 transform -translate-x-1/2 w-0.5 h-6 ${connectorColor} -top-6`} />
              <button
                onClick={() => setSelectedNode(node)}
                className="w-full p-6 bg-white dark:bg-gray-800 border-2 border-gray-300 dark:border-gray-600 rounded-lg shadow-md hover:shadow-lg transition-all hover:scale-105 cursor-pointer group"
              >
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg group-hover:bg-blue-200 dark:group-hover:bg-blue-800/40 transition-colors">
                    <GitBranch className="w-6 h-6 text-blue-700 dark:text-blue-300" />
                  </div>
                  <div className="flex-1 text-left">
                    <div className="text-xs font-semibold text-blue-700 dark:text-blue-300 uppercase tracking-wide mb-1">
                      Branch {index + 1}
                      {node.has_signature && (
                        <span className="ml-2 text-green-600 dark:text-green-400">✓ Verified</span>
                      )}
                    </div>
                    <div className="font-mono text-sm text-gray-900 dark:text-gray-100 mb-2 break-all">
                      {truncateTxid(node.txid)}
                    </div>
                    <div className="flex items-center gap-4 text-xs text-gray-600 dark:text-gray-400">
                      <span>{node.amount.toLocaleString()} sats</span>
                      <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                        Exit: ~{node.exit_weight_vb} vB
                      </span>
                    </div>
                  </div>
                </div>
              </button>
              {/* Connector - green if this node or next has verified signature */}
              {index < intermediateNodes.length - 1 || leafNode ? (
                <div className={`absolute left-1/2 transform -translate-x-1/2 w-0.5 h-6 ${connectorColor} mt-2`} />
              ) : null}
            </div>
          );
        })}

        {/* Leaf Node */}
        {leafNode && (
          <div className="relative w-full max-w-md">
            {intermediateNodes.length > 0 && (
              <div
                className={`absolute left-1/2 transform -translate-x-1/2 w-0.5 h-6 -top-6 ${
                  leafNode.has_signature || intermediateNodes[intermediateNodes.length - 1]?.has_signature
                    ? 'bg-green-500 dark:bg-green-400'
                    : 'bg-gray-300 dark:bg-gray-600'
                }`}
              />
            )}
            <button
              onClick={() => setSelectedNode(leafNode)}
              className="w-full p-6 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 border-2 border-green-300 dark:border-green-700 rounded-lg shadow-lg hover:shadow-xl transition-all hover:scale-105 cursor-pointer group"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-green-200 dark:bg-green-800/40 rounded-lg group-hover:bg-green-300 dark:group-hover:bg-green-700/40 transition-colors">
                  <Coins className="w-6 h-6 text-green-800 dark:text-green-200" />
                </div>
                <div className="flex-1 text-left">
                  <div className="text-xs font-semibold text-green-700 dark:text-green-300 uppercase tracking-wide mb-1">
                    Leaf (VTXO)
                  </div>
                  <div className="font-mono text-sm text-gray-900 dark:text-gray-100 mb-2 break-all">
                    {truncateTxid(finalVtxoId)}
                  </div>
                  <div className="flex items-center gap-4 text-xs text-gray-600 dark:text-gray-400">
                    <span>{leafNode.amount.toLocaleString()} sats</span>
                    <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                      Exit: ~{leafNode.exit_weight_vb} vB
                    </span>
                  </div>
                </div>
              </div>
            </button>
          </div>
        )}
      </div>

      {/* Modal */}
      {selectedNode && (
        <NodeDetailModal node={selectedNode} variant={variant} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
}

export default SovereigntyMap;
