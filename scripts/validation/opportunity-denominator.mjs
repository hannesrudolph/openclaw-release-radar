import {
  buildReleaseValidationOpportunityDenominatorLedger,
} from '../../src/lib/releaseValidationOpportunityDenominator.ts';

export function buildPersistedOpportunityDenominator(input) {
  return buildReleaseValidationOpportunityDenominatorLedger({
    asOf: input.asOf,
    enrollments: input.enrollments,
    forecasts: input.forecasts,
    operationLedger: {
      attempts: input.attempts,
      stageEvents: input.stageEvents,
      receipts: input.receipts,
      leases: input.leases,
      auditHistory: input.auditHistory,
    },
  });
}
