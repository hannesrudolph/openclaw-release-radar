export const CLOSURE_COMMENT_PR_MENTION_SOURCE = 'ClosureComment.prMention';
export const CLOSURE_COMMENT_FIX_PROOF_SOURCE = 'ClosureComment.fixProof';

export const CREDITED_FIX_LINK_SOURCES = [
  'closedByPullRequestsReferences',
  'ClosedEvent.closer',
  CLOSURE_COMMENT_FIX_PROOF_SOURCE,
] as const;

export function creditedFixLinkSql(alias = 'l'): string {
  const sources = CREDITED_FIX_LINK_SOURCES.map((source) => `'${source}'`).join(', ');
  return `(${alias}.will_close_target = 1 OR ${alias}.source IN (${sources}))`;
}
