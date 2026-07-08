import { isMainThread, workerData } from 'node:worker_threads';

export const API_READ_WORKER_DATABASE_CONTEXT =
  'openclaw-release-radar-api-read-worker-v1' as const;
export const RELEASE_API_WORKER_TASK = 'build-release-api-payloads' as const;
export const PUBLIC_PAYLOAD_WORKER_TASK = 'build-public-payload' as const;
export const SCORE_READ_WORKER_TASK = 'build-score-read-payload' as const;

const apiReadWorkerTasks = new Set<string>([
  RELEASE_API_WORKER_TASK,
  PUBLIC_PAYLOAD_WORKER_TASK,
  SCORE_READ_WORKER_TASK,
]);

export interface ApiReadWorkerDatabaseIdentity {
  dev: number;
  ino: number;
}

export function apiReadWorkerExpectedDatabaseIdentity():
  ApiReadWorkerDatabaseIdentity | null {
  if (
    isMainThread ||
    !process.env.DB_PATH ||
    process.env.DB_PATH.trim() !== process.env.DB_PATH ||
    process.env.DB_PATH.length === 0
  ) {
    return null;
  }
  const dotenvOverride =
    process.env.DOTENV_CONFIG_OVERRIDE?.trim().toLowerCase();
  if (dotenvOverride === '1' || dotenvOverride === 'true') return null;
  const candidate = workerData as {
    databaseContext?: unknown;
    task?: unknown;
    databaseIdentity?: {
      dev?: unknown;
      ino?: unknown;
    };
  } | null;
  if (
    candidate?.databaseContext === API_READ_WORKER_DATABASE_CONTEXT &&
    typeof candidate.task === 'string' &&
    apiReadWorkerTasks.has(candidate.task)
  ) {
    const dev = candidate.databaseIdentity?.dev;
    const ino = candidate.databaseIdentity?.ino;
    if (
      Number.isSafeInteger(dev) &&
      Number(dev) >= 0 &&
      Number.isSafeInteger(ino) &&
      Number(ino) > 0
    ) {
      return { dev: Number(dev), ino: Number(ino) };
    }
  }
  return null;
}

export function runningInTrustedApiReadWorkerContext(): boolean {
  return apiReadWorkerExpectedDatabaseIdentity() !== null;
}
