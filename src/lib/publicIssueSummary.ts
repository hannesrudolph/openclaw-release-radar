import { labelsForIssueAt, type JoinedIssue } from './db';
import { classifyIssueRowWithLabels } from './releaseScoring';
import { scoringLabelInfoAtCutoff } from './scoringLabelAuthority';
import { surfaceOf } from './surfaces';
import { isFeltSignal } from './score';

export const PUBLIC_ISSUES_PER_RELEASE = 25;

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SENTIMENT_RANK: Record<string, number> = { negative: 0, positive: 1, neutral: 2 };
const SCOPE_RANK: Record<string, number> = { broad: 0, moderate: 1, niche: 2 };
const USERS_RANK: Record<string, number> = { many: 0, some: 1, few: 2, unknown: 3 };

export function publicIssueSummariesForRelease({
  issues,
  openedIssues,
  labelCutoff,
  labelsForIssue = labelsForIssueAt,
}: {
  issues: JoinedIssue[];
  openedIssues: JoinedIssue[];
  labelCutoff: string | null;
  labelsForIssue?: typeof labelsForIssueAt;
}) {
  const classified = issues.map((issue) => classifyPublicIssue(issue, labelCutoff, labelsForIssue));
  const topIssues = classified.sort(comparePublicIssueSignal)
    .slice(0, PUBLIC_ISSUES_PER_RELEASE)
    .map(issueSummary);
  const watchIssues = openedIssues
    .map((issue) => classifyPublicIssue(issue, labelCutoff, labelsForIssue))
    .filter(({ issue, classification, labels }) => issue.state === 'open' && isFeltSignal({
      ...classification,
      issueNumber: issue.number,
      title: issue.title,
      duplicateCluster: issue.duplicate_cluster,
      author: issue.author,
      authorAssociation: issue.author_association,
      isBot: issue.is_bot,
      comments: issue.comments,
      uniqueHumanCommenterCount: issue.unique_human_commenters,
      maintainerCommenterCount: issue.maintainer_commenters,
      contributorCommenterCount: issue.contributor_commenters,
      commenterScanTruncated: issue.commenter_scan_truncated,
      reactionTotal: issue.reaction_total,
      positiveReactionCount: issue.positive_reactions,
      labels,
    }))
    .sort(comparePublicIssueSignal)
    .slice(0, PUBLIC_ISSUES_PER_RELEASE)
    .map(issueSummary);
  return { topIssues, watchIssues };
}

function classifyPublicIssue(
  issue: JoinedIssue,
  labelCutoff: string | null,
  labelResolver: typeof labelsForIssueAt,
) {
  const labelsAtCutoff = labelResolver(issue.number, parseJson(issue.labels, [] as string[]), labelCutoff, {
    useFallbackWhenNoEvents: labelCutoff == null,
    useSnapshotWhenNoEvents: labelCutoff != null,
  });
  const labelInfo = scoringLabelInfoAtCutoff(
    issue.number,
    labelsAtCutoff,
    labelCutoff,
  );
  return {
    issue,
    classification: classifyIssueRowWithLabels(issue, labelInfo.labels, labelInfo),
    labels: labelInfo.labels,
  };
}

function comparePublicIssueSignal(
  a: ReturnType<typeof classifyPublicIssue>,
  b: ReturnType<typeof classifyPublicIssue>,
): number {
  const sentiment = (SENTIMENT_RANK[a.classification.sentiment] ?? 9) - (SENTIMENT_RANK[b.classification.sentiment] ?? 9);
  if (sentiment !== 0) return sentiment;
  const severity = (SEVERITY_RANK[a.classification.severity] ?? 9) - (SEVERITY_RANK[b.classification.severity] ?? 9);
  if (severity !== 0) return severity;
  const scope = (SCOPE_RANK[a.classification.scope] ?? 9) - (SCOPE_RANK[b.classification.scope] ?? 9);
  if (scope !== 0) return scope;
  const affectedUsers = (USERS_RANK[a.classification.affectedUsers] ?? 9) -
    (USERS_RANK[b.classification.affectedUsers] ?? 9);
  if (affectedUsers !== 0) return affectedUsers;
  return b.issue.number - a.issue.number;
}

function issueSummary({ issue, classification }: ReturnType<typeof classifyPublicIssue>) {
  const surface = surfaceOf(issue.title);
  return {
    number: issue.number,
    title: issue.title,
    url: issue.html_url,
    state: issue.state,
    closedAt: issue.closed_at,
    surface: surface ? { label: surface.label, icon: surface.icon } : null,
    sentiment: classification.sentiment,
    severity: classification.severity,
    scope: classification.scope,
    affectedUsers: classification.affectedUsers,
    hasWorkaround: classification.workaroundStatus === 'confirmed' || issue.has_workaround === 1,
  };
}

function parseJson<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}
