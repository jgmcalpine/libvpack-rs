/**
 * Human-readable story titles and descriptions for each scenario.
 * Shown above the JSON input to explain what the user is looking at.
 */

export interface ScenarioStory {
  title: string;
  description: string;
}

export const SCENARIO_STORIES: Record<string, ScenarioStory> = {
  'round-leaf': {
    title: 'Standard User Exit',
    description:
      'The default method for a user to unilaterally claim their funds from the network.',
  },
  'intermediate-branch': {
    title: 'Liquidity Bridge',
    description:
      'Connects the user\'s funds to the main Bitcoin blockchain. Holds the funds for the timelock duration.',
  },
  'off-chain-forfeit': {
    title: 'Instant Payment',
    description:
      'An off-chain transfer that instantly moves ownership of funds to the service provider.',
  },
  'boarding-utxo': {
    title: 'Onboarding Transaction',
    description:
      'Simulates the initial funding event where a user enters the Ark protocol.',
  },
  'recursive-round': {
    title: 'Round VTXO',
    description:
      'A coin in a batch proving ownership through shared transaction history.',
  },
  'chain-payment': {
    title: 'Chain Payment',
    description:
      'A deep-history coin proving ownership through a series of previous spends.',
  },
};
