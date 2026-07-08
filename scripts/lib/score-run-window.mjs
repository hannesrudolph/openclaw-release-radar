import {
  getMeta,
  getRelease,
  listActiveReleaseCatalogDb,
  listReleasesDb,
} from '../../src/lib/db.ts';
import { createScoreRunWindowHelpers } from './score-run-window-core.mjs';

const helpers = createScoreRunWindowHelpers({
  getMeta,
  getRelease,
  listActiveReleaseCatalogDb,
  listReleasesDb,
});

export const latestScoreRunWindowOptions = helpers.latestScoreRunWindowOptions;
export const monitoredScoreWindowReleases = helpers.monitoredScoreWindowReleases;
export const scoreRunWindowOptions = helpers.scoreRunWindowOptions;
