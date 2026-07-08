const { DatabaseSync } = require('node:sqlite');

const mode = process.argv[2];
switch (mode) {
  case 'noop':
    process.exit(0);
    break;
  case 'open':
    withDatabase(process.env.TARGET_DATABASE, (database) => {
      database.exec(
        'CREATE TABLE IF NOT EXISTS child_probe (id INTEGER PRIMARY KEY)',
      );
    });
    break;
  case 'open-db-path':
    withDatabase(process.env.DB_PATH, (database) => {
      database.exec(
        'CREATE TABLE IF NOT EXISTS child_probe_db_path (id INTEGER PRIMARY KEY)',
      );
    });
    break;
  case 'constructor-open':
    {
      const safe = new DatabaseSync(process.env.DB_PATH);
      const RecoveredDatabaseSync = safe.constructor;
      safe.close();
      const target = new RecoveredDatabaseSync(process.env.TARGET_DATABASE);
      target.close();
    }
    break;
  case 'attach-exec':
    withDatabase(process.env.DB_PATH, (database) => {
      database.exec(
        `ATTACH DATABASE '${sqlLiteral(process.env.TARGET_DATABASE)}' AS bypass`,
      );
    });
    break;
  case 'attach-prepare':
    withDatabase(process.env.DB_PATH, (database) => {
      database.prepare('ATTACH DATABASE ? AS bypass');
    });
    break;
  case 'vacuum-exec':
    withDatabase(process.env.DB_PATH, (database) => {
      database.exec(
        `VACUUM main INTO '${sqlLiteral(process.env.TARGET_DATABASE)}'`,
      );
    });
    break;
  case 'vacuum-prepare':
    withDatabase(process.env.DB_PATH, (database) => {
      database.prepare('VACUUM main INTO ?');
    });
    break;
  case 'vacuum-main-exec':
    withDatabase(process.env.DB_PATH, (database) => {
      database.exec('VACUUM main');
    });
    break;
  case 'vacuum-main-prepare':
    withDatabase(process.env.DB_PATH, (database) => {
      database.prepare('VACUUM main');
    });
    break;
  case 'weaken-max-page-count':
    withDatabase(process.env.DB_PATH, (database) => {
      database.exec('PRAGMA main.max_page_count = 2147483646');
    });
    break;
  case 'weaken-journal-size-limit':
    withDatabase(process.env.DB_PATH, (database) => {
      database.prepare('PRAGMA "journal_size_limit" = -1');
    });
    break;
  default:
    throw new Error(`Unknown database guard child probe mode: ${String(mode)}`);
}

function withDatabase(path, callback) {
  const database = new DatabaseSync(path);
  try {
    callback(database);
  } finally {
    database.close();
  }
}

function sqlLiteral(value) {
  return String(value).replaceAll("'", "''");
}
