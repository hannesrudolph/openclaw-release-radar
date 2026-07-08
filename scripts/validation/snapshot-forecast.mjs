import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

process.env.RADAR_DB_READ_ONLY = '1';

const outputPath = parseOutputPath(process.argv.slice(2));
const { listReleaseValidationForecasts } = await import('../../src/lib/db.ts');
const { buildReleaseValidationForecastSnapshot } = await import('../../src/lib/releaseValidation.ts');

const snapshot = buildReleaseValidationForecastSnapshot(listReleaseValidationForecasts());
const serialized = `${JSON.stringify(snapshot, null, 2)}\n`;
if (outputPath) {
  mkdirSync(dirname(outputPath), { recursive: true });
  const temporaryPath = `${outputPath}.tmp-${process.pid}`;
  writeFileSync(temporaryPath, serialized);
  renameSync(temporaryPath, outputPath);
}
console.log(serialized.trimEnd());

function parseOutputPath(args) {
  if (args.length === 0) return null;
  if (args.length !== 2 || args[0] !== '--output' || !args[1]) {
    throw new Error('Usage: validation:snapshot [--output <snapshot.json>]');
  }
  return resolve(args[1]);
}
