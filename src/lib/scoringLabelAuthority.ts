import {
  labelAuthorityEvidenceForEvent,
  latestIssueLabelEventAt,
} from './db';
import {
  buildScoreAuthorityReference,
  buildScoreAuthorityResolution,
  scoreAuthorityReferenceProblems,
  type ScoreAuthorityReference,
} from './scoreAuthorityResolution';
import { labelUsesScoreAuthority } from './labelOverrides';

const HUMAN_PRIORITY_LABELS = new Set(['P0', 'P1', 'beta-blocker', 'regression']);

function labelRequiresScoreAuthority(label: string): boolean {
  return HUMAN_PRIORITY_LABELS.has(label) || labelUsesScoreAuthority(label);
}

export interface ScoringLabelInfoAtCutoff {
  labels: string[];
  authorizedScoringLabels: string[];
  labelActors: Record<string, string | null>;
  authorityReferences: Record<string, ScoreAuthorityReference>;
}

type LabelEventAuthorityDecision = ScoreAuthorityReference | null;

export function scoringLabelInfoAtCutoff(
  issueNumber: number,
  labels: string[],
  cutoff: string | null,
  eventAuthorizedForScoring: (
    eventId: string,
  ) => LabelEventAuthorityDecision = labelEventAuthorityReference,
  labelEventResolver: typeof latestIssueLabelEventAt =
    latestIssueLabelEventAt,
): ScoringLabelInfoAtCutoff {
  const authorizedScoringLabels = new Set<string>();
  const labelActors: Record<string, string | null> = {};
  const authorityReferences: Record<string, ScoreAuthorityReference> = {};
  for (const label of labels) {
    const event = labelEventResolver(issueNumber, label, cutoff);
    labelActors[label] = event?.action === 'labeled'
      ? event.actor_login
      : null;
    const decision = event?.action === 'labeled' &&
        labelRequiresScoreAuthority(label)
      ? eventAuthorizedForScoring(event.event_id)
      : null;
    const reference = decision != null &&
        scoreAuthorityReferenceProblems(decision).length === 0 &&
        decision.subjectKind === 'label_event' &&
        decision.subjectIdentity === event?.event_id
      ? decision
      : null;
    if (event?.action === 'labeled' && reference) {
      authorizedScoringLabels.add(label);
      authorityReferences[label] = reference;
    }
  }
  return {
    labels: labels.filter((label) =>
      !labelRequiresScoreAuthority(label) ||
      authorizedScoringLabels.has(label)),
    authorizedScoringLabels: [...authorizedScoringLabels].sort(),
    labelActors,
    authorityReferences,
  };
}

export function scoringLabelsAtCutoff(
  issueNumber: number,
  labels: string[],
  cutoff: string | null,
  eventAuthorizedForScoring: (
    eventId: string,
  ) => LabelEventAuthorityDecision = labelEventAuthorityReference,
): string[] {
  return scoringLabelInfoAtCutoff(
    issueNumber,
    labels,
    cutoff,
    eventAuthorizedForScoring,
  ).labels;
}

export function labelEventAuthorizedForScoring(eventId: string): boolean {
  return labelEventAuthorityReference(eventId) != null;
}

export function labelEventAuthorityReference(
  eventId: string,
): ScoreAuthorityReference | null {
  try {
    const resolution = buildScoreAuthorityResolution(
      labelAuthorityEvidenceForEvent(eventId),
    );
    return resolution.authorizedForScoring
      ? buildScoreAuthorityReference('label_event', eventId, resolution)
      : null;
  } catch {
    return null;
  }
}
