import { useCallback, useState } from 'react';
import { X, Landmark, GitBranch, User, Shield, Scale, Copy, ChevronDown, ChevronUp } from 'lucide-react';
import type { PathDetail } from '../types/verification';
import { getMempoolExplorerUrl } from '../utils/mempoolUrl';
import type { Network } from '../types/network';

type NodePersona = 'anchor' | 'branch' | 'leaf';

function resolvePersona(node: PathDetail, nodeType?: 'anchor' | 'branch' | 'vtxo'): NodePersona {
  if (nodeType === 'anchor') return 'anchor';
  if (nodeType === 'vtxo') return 'leaf';
  if (nodeType === 'branch') return 'branch';
  if (node.is_anchor === true) return 'anchor';
  if (node.is_leaf) return 'leaf';
  if (!node.tx_preimage_hex?.length && !node.is_leaf) return 'anchor';
  return 'branch';
}

const rawHexClasses = {
  container: 'pt-4 border-t border-gray-200 dark:border-gray-700',
  label: 'text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2',
  pre: 'font-mono text-xs text-gray-900 dark:text-gray-100 break-all bg-gray-100 dark:bg-gray-900 p-3 rounded-lg overflow-x-auto max-h-32 overflow-y-auto',
  copyBtn:
    'mt-2 flex items-center gap-2 px-3 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-300 transition-colors',
  copyBroadcastBtn:
    'mt-2 flex items-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition-colors',
  warning: 'text-amber-600 dark:text-amber-400 text-xs mt-2',
};

const storyHeaderClasses = 'text-sm font-bold text-gray-800 dark:text-gray-200 uppercase tracking-wide mt-4 mb-2';

const RBF_SEQUENCE = 0xfffffffe;
const SEQUENCE_ZERO = 0x00000000;
const SEQUENCE_MAX = 0xffffffff;

const unsignedTooltip =
  'This transaction is missing signatures. It can be viewed in a decoder but cannot be broadcast until co-signed by your keys and the ASP.';

function truncateHexDisplay(hex: string): string {
  if (hex.length <= 24) return hex;
  return `${hex.slice(0, 12)}...${hex.slice(-12)}`;
}

function SignedHexSection({ hex, hasSignature }: { hex: string; hasSignature: boolean }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(hex);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  }, [hex]);

  const copyLabel = hasSignature ? 'Copy for Broadcast' : 'Copy Unsigned Template';
  const sectionTitle = hasSignature ? 'Signed Transaction Hex' : 'Unsigned Transaction Hex';
  const displayHex = hasSignature ? hex : truncateHexDisplay(hex);

  return (
    <div className={rawHexClasses.container}>
      <h3 className={rawHexClasses.label}>{sectionTitle}</h3>
      {hasSignature ? (
        <p className={rawHexClasses.warning}>
          ⚠️ This is a fully signed SegWit transaction. Broadcasting this to the network will initiate a unilateral exit.
        </p>
      ) : (
        <p className={rawHexClasses.warning} title={unsignedTooltip}>
          {unsignedTooltip}
        </p>
      )}
      <pre className={rawHexClasses.pre}>{displayHex}</pre>
      <button
        type="button"
        onClick={handleCopy}
        className={hasSignature ? rawHexClasses.copyBroadcastBtn : rawHexClasses.copyBtn}
        title={hasSignature ? undefined : unsignedTooltip}
      >
        <Copy className="w-4 h-4" />
        {copied ? 'Copied' : copyLabel}
      </button>
    </div>
  );
}

function TechnicalDetailsAccordion({
  signedTxHex,
  hasSignature,
  vout,
  sequence,
  showVout,
  showSequence,
  variant,
}: {
  signedTxHex: string | undefined;
  hasSignature: boolean;
  vout: number;
  sequence?: number;
  showVout: boolean;
  showSequence: boolean;
  variant: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasContent = (signedTxHex && signedTxHex.length > 0) || showVout || showSequence;

  if (!hasContent) return null;

  return (
    <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="flex items-center gap-2 text-sm font-semibold text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 transition-colors"
      >
        {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        Show Technical Details
      </button>
      {expanded && (
        <div className="mt-3 space-y-3">
          {showSequence && sequence !== undefined && (
            <div>
              <h3 className={rawHexClasses.label}>nSequence</h3>
              <p className="text-sm text-gray-900 dark:text-gray-100 font-mono">
                0x{sequence.toString(16).padStart(8, '0').toUpperCase()}
              </p>
              {sequence === RBF_SEQUENCE && (
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  RBF enabled for fee bumping.
                </p>
              )}
              {variant === '0x03' && sequence === SEQUENCE_ZERO && (
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  Sequence: ZERO (Timelocks enabled for exit safety).
                </p>
              )}
              {variant === '0x04' && sequence === SEQUENCE_MAX && (
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                  Sequence: MAX (Industry default, replacements disabled).
                </p>
              )}
            </div>
          )}
          {signedTxHex && signedTxHex.length > 0 && (
            <SignedHexSection hex={signedTxHex} hasSignature={hasSignature} />
          )}
          {showVout && (
            <div>
              <h3 className={rawHexClasses.label}>Vout</h3>
              <p className="text-sm text-gray-900 dark:text-gray-100">{vout}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface NodeDetailModalProps {
  node: PathDetail;
  variant: string;
  onClose: () => void;
  network?: Network;
  blockHeight?: number;
  /** Override when path_details lack is_anchor (e.g. from ArkNode.type) */
  nodeType?: 'anchor' | 'branch' | 'vtxo';
}

function NodeDetailModal({ node, variant, onClose, network = 'bitcoin', blockHeight, nodeType }: NodeDetailModalProps) {
  const persona = resolvePersona(node, nodeType);
  const siblingCount = node.sibling_count ?? 0;
  const isV3Anchored = variant === '0x04';
  const scalingFactor = siblingCount + 1;

  const explorerBase = getMempoolExplorerUrl(network);
  const mempoolTxUrl = `${explorerBase}/tx/${node.txid}`;

  const exitWeightLabel = persona === 'anchor' ? 'Cost to Open' : 'Cost to Exit this level';
  const exitWeightText =
    persona === 'anchor'
      ? `~${node.exit_weight_vb} vB. This is the on-chain transaction that opens the vault.`
      : `~${node.exit_weight_vb} vB. Each level requires one Bitcoin transaction to exit.`;

  const personaConfig = {
    anchor: {
      title: 'L1 Root Anchor',
      icon: Landmark,
      iconBg: 'bg-amber-100 dark:bg-amber-900/40',
      iconColor: 'text-amber-600 dark:text-amber-400',
    },
    branch: {
      title: 'Virtual Branch',
      icon: GitBranch,
      iconBg: 'bg-blue-100 dark:bg-blue-900/40',
      iconColor: 'text-blue-600 dark:text-blue-400',
    },
    leaf: {
      title: 'Your Sovereign Leaf',
      icon: User,
      iconBg: 'bg-emerald-100 dark:bg-emerald-900/40',
      iconColor: 'text-emerald-600 dark:text-emerald-400',
    },
  };

  const config = personaConfig[persona];
  const IconComponent = config.icon;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 p-6 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg ${config.iconBg} ${config.iconColor}`}>
              <IconComponent className="w-6 h-6" />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{config.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-6 h-6 text-gray-600 dark:text-gray-400" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Auditor context (TxVariant-specific) */}
          {variant === '0x04' && (
            <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
              <p className="text-sm text-gray-700 dark:text-gray-300">
                Auditing a <strong>Virtual Network</strong> node. This transaction uses BIP-431 (TRUC) and a
                mandatory Fee Anchor to ensure your exit cannot be &quot;pinned&quot; or blocked in the Bitcoin
                mempool, even during high network congestion.
              </p>
            </div>
          )}
          {variant === '0x03' && (
            <div className="p-3 rounded-lg bg-cyan-50 dark:bg-cyan-900/20 border border-cyan-200 dark:border-cyan-800">
              <p className="text-sm text-gray-700 dark:text-gray-300">
                Auditing a <strong>Fluid Chain</strong> link. This step represents a private, off-chain handoff of
                ownership. By carrying the full &quot;biography of signatures&quot; of this chain, your wallet remains autonomous
                and ready for an emergency exit without server assistance.
              </p>
            </div>
          )}

          {/* What is this? */}
          <h3 className={storyHeaderClasses}>What is this?</h3>
          {persona === 'anchor' && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              This is the &quot;Soil.&quot; It is a physical transaction recorded on the Bitcoin blockchain. It acts as
              the communal vault that secures every coin in this tree.
            </p>
          )}
          {persona === 'branch' && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              This is a &quot;Hallway&quot; inside the vault. It is a virtual transaction signed by the ASP that splits
              the larger pool into smaller segments.
            </p>
          )}
          {persona === 'leaf' && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {variant === '0x03'
                ? 'This is a V3/TRUC Sequential Chain link. The final output that belongs exclusively to your private key.'
                : variant === '0x04'
                  ? 'This is a V3/TRUC Fanned-out Tree node. The final output that belongs exclusively to your private key.'
                  : 'This is the &quot;Fruit.&quot; It is the final output that belongs exclusively to your private key.'}
            </p>
          )}

          {/* Why is it secure? */}
          <h3 className={storyHeaderClasses}>Why is it secure?</h3>
          {persona === 'anchor' && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Proof of Work secures the Bitcoin blockchain. Once buried in a block, the anchor is immutable.
            </p>
          )}
          {persona === 'branch' && (
            <div className="space-y-2">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {variant === '0x03'
                  ? 'This is a V3/TRUC Sequential Chain link.'
                  : variant === '0x04'
                    ? 'This is a V3/TRUC Fanned-out Tree node.'
                    : 'Signed by ASP. V3/TRUC protection ensures cryptographic authenticity.'}
              </p>
              {node.has_fee_anchor && (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Fee Anchor present. Provides pinning protection during unilateral exit.
                </p>
              )}
            </div>
          )}
          {persona === 'leaf' && (
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Only your key can spend this output. The exit path is verifiable and time-locked.
            </p>
          )}

          {/* Key Data */}
          <h3 className={storyHeaderClasses}>Key Data</h3>

          {persona === 'anchor' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">On-Chain TxID</h4>
                <a
                  href={mempoolTxUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm text-blue-600 dark:text-blue-400 hover:underline break-all"
                >
                  {node.txid}
                </a>
              </div>
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Total Vault Value</h4>
                <p className="text-sm text-gray-900 dark:text-gray-100">{node.amount.toLocaleString()} sats</p>
              </div>
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Status</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {blockHeight !== undefined
                    ? `Buried in Block #${blockHeight.toLocaleString()}`
                    : 'Proof of Work'}
                </p>
              </div>
            </div>
          )}

          {persona === 'branch' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Virtual TxID</h4>
                <p className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">{node.txid}</p>
              </div>
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Scaling Factor</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  This branch supports <strong>{scalingFactor}</strong> user{scalingFactor !== 1 ? 's' : ''}.
                </p>
              </div>
              {variant === '0x03' && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Identity Model</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    OutPoint (32-byte TxID + 4-byte Index). Used to uniquely identify individual outputs in batched
                    transactions.
                  </p>
                </div>
              )}
              {variant === '0x04' && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Identity Model</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    32-byte Hash (TxID). The unique fingerprint of this specific virtual transaction.
                  </p>
                </div>
              )}
              <div className="flex items-start gap-3">
                <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Signed by ASP. {isV3Anchored ? 'V3/TRUC Anchored' : 'V3/TRUC Plain'} protection.
                  </p>
                </div>
              </div>
            </div>
          )}

          {persona === 'leaf' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">VTXO ID</h4>
                <p className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">
                  {node.txid}:{node.vout}
                </p>
              </div>
              {variant === '0x03' && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Identity Model</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    OutPoint (32-byte TxID + 4-byte Index). Used to uniquely identify individual outputs in batched
                    transactions.
                  </p>
                </div>
              )}
              {variant === '0x04' && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Identity Model</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    32-byte Hash (TxID). The unique fingerprint of this specific virtual transaction.
                  </p>
                </div>
              )}
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">Your Balance</h4>
                <p className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">
                  {node.amount.toLocaleString()} sats
                </p>
              </div>
              {(node.exit_delta ?? 0) > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">The Fire Escape</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Time to Exit: <strong>{node.exit_delta}</strong> blocks.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Exit Weight */}
          <div className="flex items-start gap-3 pt-2">
            <Scale className="w-5 h-5 text-orange-600 dark:text-orange-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">{exitWeightLabel}</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {exitWeightText}
              </p>
            </div>
          </div>

          {/* Technical Details Accordion */}
          <TechnicalDetailsAccordion
            signedTxHex={node.signed_tx_hex}
            hasSignature={node.has_signature ?? false}
            vout={node.vout}
            sequence={node.sequence}
            showVout={persona !== 'anchor'}
            showSequence={persona !== 'anchor'}
            variant={variant}
          />
        </div>
      </div>
    </div>
  );
}

export default NodeDetailModal;
