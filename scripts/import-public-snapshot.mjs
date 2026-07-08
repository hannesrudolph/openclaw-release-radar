throw new Error(
  'Public snapshot import is permanently disabled. ' +
  'External comparison or snapshot data may never write or replace the ' +
  'authoritative GitHub release catalog in any configured or live database. ' +
  'Use `npm run scrape:upstream` for comparison-only upstream data.',
);
