import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-closure-authority-test-'))
  : null;
if (ownedTestDir !== null) {
  const emptyDotenvPath = join(ownedTestDir, 'empty.env');
  process.env.DB_PATH = join(ownedTestDir, 'radar.db');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

let authority: typeof import('./closureClaimAuthorityEvaluation.ts');
let radarDb: typeof import('./db.ts');

before(async () => {
  authority = await import('./closureClaimAuthorityEvaluation.ts');
  radarDb = await import('./db.ts');
});

after(() => {
  radarDb.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

function binding(input: {
  candidateId: string;
  issueNumber: number;
  claim: Record<string, unknown>;
}) {
  return {
    candidate: {
      candidateId: input.candidateId,
      repository: {
        nameWithOwner: 'openclaw/openclaw',
      },
      issue: {
        number: input.issueNumber,
      },
      source: {
        kind: 'comment',
        nodeId: `COMMENT_${input.candidateId}`,
        createdAt: '2026-07-04T00:00:00Z',
        updatedAt: '2026-07-04T00:00:00Z',
      },
      claim: input.claim,
    },
    resolution: {
      candidateId: input.candidateId,
      issueNumber: input.issueNumber,
      authorizedForScoring: true,
    },
  } as any;
}

const sourceTo20 = binding({
  candidateId: 'source-to-20',
  issueNumber: 10,
  claim: {
    kind: 'duplicate_or_superseded',
    relation: 'duplicate',
    target: {
      resource: 'issue',
      repositoryNameWithOwner: 'openclaw/openclaw',
      number: 20,
    },
  },
});
const sourceTo21 = binding({
  candidateId: 'source-to-21',
  issueNumber: 10,
  claim: {
    kind: 'duplicate_or_superseded',
    relation: 'duplicate',
    target: {
      resource: 'issue',
      repositoryNameWithOwner: 'openclaw/openclaw',
      number: 21,
    },
  },
});
const terminal30 = binding({
  candidateId: 'terminal-30',
  issueNumber: 30,
  claim: {
    kind: 'closure_rationale',
    rationale: 'not_reproducible',
  },
});
const terminal40 = binding({
  candidateId: 'terminal-40',
  issueNumber: 40,
  claim: {
    kind: 'closure_rationale',
    rationale: 'out_of_scope',
  },
});
const evidenceJson = JSON.stringify({
  canonicalResolution: {
    branches: [
      {
        path: [10, 20, 30],
        terminalIssue: {
          number: 30,
          url: 'https://github.com/openclaw/openclaw/issues/30',
        },
        terminalProof: {
          status: 'not_planned',
          concreteNonActionableRationale: true,
        },
      },
      {
        path: [10, 21, 40],
        terminalIssue: {
          number: 40,
          url: 'https://github.com/openclaw/openclaw/issues/40',
        },
        terminalProof: {
          status: 'reporter_withdrawn',
        },
      },
    ],
  },
});

describe('closure claim authority evaluation', () => {
  it('requires authority for every non-actionable canonical branch', () => {
    const incomplete = authority.selectClosureDispositionAuthority({
      status: 'duplicate_to_non_actionable_canonical',
      sourceIssueNumber: 10,
      canonicalIssueNumbers: [20, 21, 30, 40],
      evidenceJson,
      claimsByIssue: new Map([
        [10, [sourceTo20, sourceTo21]],
        [30, [terminal30]],
      ]),
    });
    assert.deepEqual(incomplete, {
      required: true,
      satisfied: false,
      claims: [],
    });

    const complete = authority.selectClosureDispositionAuthority({
      status: 'duplicate_to_non_actionable_canonical',
      sourceIssueNumber: 10,
      canonicalIssueNumbers: [20, 21, 30, 40],
      evidenceJson,
      claimsByIssue: new Map([
        [10, [sourceTo20, sourceTo21]],
        [30, [terminal30]],
        [40, [terminal40]],
      ]),
    });
    assert.equal(complete.required, true);
    assert.equal(complete.satisfied, true);
    assert.deepEqual(
      complete.claims.map((claim) => claim.candidate.candidateId),
      [
        sourceTo20.candidate.candidateId,
        terminal30.candidate.candidateId,
        sourceTo21.candidate.candidateId,
        terminal40.candidate.candidateId,
      ],
    );
  });
});
