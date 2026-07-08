import { createRequire } from 'node:module';

const installation =
  createRequire(import.meta.url)('./database-guard-runtime.cjs');

export function assertDatabaseGuardInstalled(options) {
  return installation.assertActive(options);
}
