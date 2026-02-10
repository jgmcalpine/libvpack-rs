import { X, CheckCircle2, Shield, Scale } from 'lucide-react';
import type { PathDetail } from '../types/verification';

interface NodeDetailModalProps {
  node: PathDetail;
  variant: string;
  onClose: () => void;
}

function NodeDetailModal({ node, variant, onClose }: NodeDetailModalProps) {
  const isV3Anchored = variant === '0x04';
  const topologyText = isV3Anchored ? 'V3/TRUC Anchored transaction' : 'V3/TRUC Plain transaction';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 p-6 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Node Details</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-6 h-6 text-gray-600 dark:text-gray-400" />
          </button>
        </div>

        <div className="space-y-6">
          {/* Transaction ID */}
          <div>
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Transaction ID</h3>
            <p className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{node.txid}</p>
          </div>

          {/* Topology */}
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Topology</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                This is a {topologyText}. {isV3Anchored && 'It includes a mandatory Fee Anchor for pinning protection.'}
              </p>
            </div>
          </div>

          {/* Security */}
          {node.has_fee_anchor && (
            <div className="flex items-start gap-3">
              <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Security</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Fee Anchor present. Provides pinning protection during unilateral exit.
                </p>
              </div>
            </div>
          )}

          {/* Auth */}
          {node.has_signature && (
            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Auth</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Signature verified via k256 (Pure-Rust Schnorr). This transaction is cryptographically authenticated.
                </p>
              </div>
            </div>
          )}

          {/* Exit Weight */}
          <div className="flex items-start gap-3">
            <Scale className="w-5 h-5 text-orange-600 dark:text-orange-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Exit Weight</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                Exit Weight: ~{node.exit_weight_vb} vB. Each level requires one Bitcoin transaction to exit.
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                <strong>Trade-off:</strong> Deeper trees provide more privacy/scale but increase sovereignty cost (more
                transactions = more fees). This node is level {node.is_leaf ? 'leaf' : 'intermediate'} in your path.
              </p>
            </div>
          </div>

          {/* Amount and Vout */}
          <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-200 dark:border-gray-700">
            <div>
              <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Amount</h3>
              <p className="text-sm text-gray-900 dark:text-gray-100">{node.amount.toLocaleString()} sats</p>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Vout</h3>
              <p className="text-sm text-gray-900 dark:text-gray-100">{node.vout}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default NodeDetailModal;
