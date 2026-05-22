import express from 'express';
import cron from 'node-cron';
import { join } from 'node:path';
import { config } from './config';
import { api } from './routes/api';
import { refresh } from './lib/refresh';

const app = express();
app.use(express.json());
app.use('/api', api);
app.use(express.static(join(__dirname, '..', 'public')));

app.listen(config.server.port, () => {
  console.log(`[radar] listening on http://localhost:${config.server.port}`);
  console.log(`[radar] watching ${config.github.owner}/${config.github.repo}`);
});

// Cron — fire and forget; refresh() guards against overlap.
if (cron.validate(config.cron.schedule)) {
  cron.schedule(config.cron.schedule, () => {
    refresh()
      .then((r) =>
        console.log(
          `[cron] refreshed: ${r.classifiedCount} classified, ${r.releaseCount} releases, ${r.durationMs}ms`,
        ),
      )
      .catch((e) => console.error('[cron] refresh failed:', (e as Error).message));
  });
  console.log(`[cron] schedule: ${config.cron.schedule}`);
} else {
  console.warn(`[cron] invalid schedule, skipping: ${config.cron.schedule}`);
}

// Initial refresh on startup (non-blocking).
refresh()
  .then((r) =>
    console.log(
      `[startup] refreshed: ${r.classifiedCount} classified, ${r.releaseCount} releases, ${r.durationMs}ms`,
    ),
  )
  .catch((e) => console.error('[startup] refresh failed:', (e as Error).message));
