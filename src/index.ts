import express from 'express';
import { join } from 'node:path';
import { config } from './config';
import { api } from './routes/api';
import { refresh } from './lib/refresh';

const app = express();
app.use(express.json());
app.use('/api', api);
app.use(express.static(join(__dirname, '..', 'public')));

app.listen(config.server.port, '127.0.0.1', () => {
  console.log(`[radar] listening on http://127.0.0.1:${config.server.port}`);
  console.log(`[radar] watching ${config.github.owner}/${config.github.repo}`);
});

// Periodic refresh is deliberately optional while the scoring model is being
// calibrated. A slow full backfill must not overlap with another refresh.
if (config.refresh.intervalMinutes > 0) {
  const intervalMs = config.refresh.intervalMinutes * 60_000;
  setInterval(() => {
    refresh()
      .then((r) =>
        console.log(
          `[refresh] ${r.classifiedCount} classified, ${r.releaseCount} releases, ${r.durationMs}ms`,
        ),
      )
      .catch((e) => console.error('[refresh] failed:', (e as Error).message));
  }, intervalMs);
  console.log(`[refresh] every ${config.refresh.intervalMinutes} min`);
} else {
  console.log('[refresh] automatic refresh disabled');
}

// Initial refresh on startup (non-blocking).
refresh()
  .then((r) =>
    console.log(
      `[startup] refreshed: ${r.classifiedCount} classified, ${r.releaseCount} releases, ${r.durationMs}ms`,
    ),
  )
  .catch((e) => console.error('[startup] refresh failed:', (e as Error).message));
