#!/usr/bin/env bash
set -euo pipefail

startup_injection_environment_names=(
  BASH_ENV
  ENV
  NODE_OPTIONS
  NODE_PATH
  DOTENV_CONFIG_PATH
  DOTENV_CONFIG_OVERRIDE
  LD_PRELOAD
  LD_LIBRARY_PATH
  LD_AUDIT
  DYLD_INSERT_LIBRARIES
  DYLD_LIBRARY_PATH
  DYLD_FRAMEWORK_PATH
  DYLD_FALLBACK_LIBRARY_PATH
  DYLD_FALLBACK_FRAMEWORK_PATH
  OPENSSL_CONF
  OPENSSL_MODULES
  NODE_EXTRA_CA_CERTS
  NODE_TLS_REJECT_UNAUTHORIZED
  SSL_CERT_FILE
  SSL_CERT_DIR
  NPM_CONFIG_NODE_OPTIONS
  npm_config_node_options
  NPM_CONFIG_SCRIPT_SHELL
  npm_config_script_shell
  PS4
  BASH_XTRACEFD
  CDPATH
  GLOBIGNORE
  POSIXLY_CORRECT
)

scrub_startup_injection_environment() {
  local name
  for name in "${startup_injection_environment_names[@]}"; do
    unset "$name"
  done
  export -n SHELLOPTS BASHOPTS 2>/dev/null || true
}

scrub_startup_injection_environment

action="${1:-}"
base="${RADAR_INSTALL_BASE:-/opt/openclaw-release-radar}"
shared="$base/shared"
releases="$base/releases"
current="$base/current"
pending_dir="$base/.pending-deploy"
intent_dir=
installer_protocol=5
pending_state_schema_version=4
pending_state_hash_domain="installer-pending-promotion-v2"
lock_file="${RADAR_DEPLOY_LOCK_PATH:-$shared/deploy-promotion.lock}"
unset RADAR_DEPLOY_LOCK_HELD RADAR_DEPLOY_LOCK_PATH
node_bin="${RADAR_INSTALL_NODE_BIN:-/opt/node-v24/bin/node}"
npm_bin="${RADAR_INSTALL_NPM_BIN:-/opt/node-v24/bin/npm}"
systemctl_bin="${RADAR_INSTALL_SYSTEMCTL_BIN:-systemctl}"
curl_bin="${RADAR_INSTALL_CURL_BIN:-curl}"
runuser_bin="${RADAR_INSTALL_RUNUSER_BIN:-runuser}"
journalctl_bin="${RADAR_INSTALL_JOURNALCTL_BIN:-journalctl}"
flock_bin="${RADAR_INSTALL_FLOCK_BIN:-flock}"
lsof_bin="${RADAR_INSTALL_LSOF_BIN:-lsof}"
getfacl_bin="${RADAR_INSTALL_GETFACL_BIN:-getfacl}"
getfattr_bin="${RADAR_INSTALL_GETFATTR_BIN:-getfattr}"
cp_bin="${RADAR_INSTALL_CP_BIN:-/bin/cp}"
service_name="${RADAR_INSTALL_SERVICE_NAME:-openclaw-release-radar.service}"
verifier_key_path="${RADAR_INSTALL_VERIFIER_KEY_PATH:-/etc/openclaw-release-radar/deploy-verifier.key}"
health_url="${RADAR_INSTALL_HEALTH_URL:-}"
manifest_url="${RADAR_INSTALL_MANIFEST_URL:-}"
provenance_url="${RADAR_INSTALL_PROVENANCE_URL:-}"
status_url="${RADAR_INSTALL_STATUS_URL:-}"
receipt_url_base="${RADAR_INSTALL_RECEIPT_URL_BASE:-}"
runtime_user="${RADAR_INSTALL_RUNTIME_USER:-www-data}"
runtime_group="${RADAR_INSTALL_RUNTIME_GROUP:-www-data}"
release_owner="${RADAR_INSTALL_RELEASE_OWNER:-root}"
release_group="${RADAR_INSTALL_RELEASE_GROUP:-root}"
shared_env_owner="${RADAR_INSTALL_SHARED_ENV_OWNER:-root}"
shared_env_group="${RADAR_INSTALL_SHARED_ENV_GROUP:-$runtime_group}"
shared_env_mode="${RADAR_INSTALL_SHARED_ENV_MODE:-640}"
readiness_attempts="${RADAR_INSTALL_READINESS_ATTEMPTS:-30}"
readiness_sleep_seconds="${RADAR_INSTALL_READINESS_SLEEP_SECONDS:-1}"
probe_connect_timeout_seconds="${RADAR_INSTALL_PROBE_CONNECT_TIMEOUT_SECONDS:-2}"
probe_max_time_seconds="${RADAR_INSTALL_PROBE_MAX_TIME_SECONDS:-5}"
lock_timeout_seconds="${RADAR_INSTALL_LOCK_TIMEOUT_SECONDS:-120}"
pending_timeout_seconds="${RADAR_INSTALL_PENDING_TIMEOUT_SECONDS:-2400}"
watchdog_ready_attempts="${RADAR_INSTALL_WATCHDOG_READY_ATTEMPTS:-50}"
watchdog_ready_sleep_seconds="${RADAR_INSTALL_WATCHDOG_READY_SLEEP_SECONDS:-0.1}"
manifest_relative="public/release-manifest.json"
runtime_env_dir="$shared/runtime-env"
backup_root="$shared/deploy-backups"
watchdog_log_dir="$shared/deploy-logs"
smoke_dir="$shared/install-smoke"
completion_root="$shared/deploy-completions"
artifact_root="$shared/deploy-artifacts"
startup_authorization_dir="$shared/startup-authorization"
startup_authorization_path="$startup_authorization_dir/active.json"
verification_id=
verification_attestation=
promotion_runtime_relative="promotion-runtime"

release_name=
expected_sha=
expected_digest=
upload_tarball=
tarball=
tarball_sha256=
tarball_size_bytes=
release_dir=
staging_dir=
next_link=
runtime_env_path=
database_path=
db_snapshot_dir=
db_snapshot_path=
db_snapshot_metadata_path=
db_snapshot_sha256=
quality_database_path=
required_score_receipt_id=
transaction_id=
pending_state_hash=
pending_deadline_epoch=
promotion_report_path=
promotion_dotenv_path=
promotion_required=0
promotion_completed=0
service_stopped_for_promotion=0
release_created=0
runtime_env_created=0
db_snapshot_created=0
activation_pending_created=0
activation_switched=0
activation_handoff_complete=0
activation_intent_created=0
finalized_state_dir=
recovered_finalization=0
recovered_finalization_outcome=
recovered_completion=0
recovered_completion_outcome=
deploy_lock_held=0
watchdog_terminal_recorded=0
watchdog_terminal_outcome=
reconcile_boot_mode=0
rollback_readiness_transaction_id=
rollback_readiness_pending_state_hash=
deferred_state_dir=

usage() {
  cat >&2 <<'EOF'
Usage:
  openclaw-release-radar-install-release protocol [expected-protocol]
  openclaw-release-radar-install-release activate <tarball> <release-name> <github-sha> <artifact-digest> <transaction-id> <quality-db> <score-receipt-id>
  openclaw-release-radar-install-release authorize <release-name> <github-sha> <artifact-digest> <transaction-id> <verification-id> <verifier-attestation>
  openclaw-release-radar-install-release status <release-name> <github-sha> <artifact-digest> <transaction-id>
  openclaw-release-radar-install-release commit <release-name> <github-sha> <artifact-digest> <transaction-id>
  openclaw-release-radar-install-release rollback <release-name> <github-sha> <artifact-digest> <transaction-id>
  openclaw-release-radar-install-release reconcile [--boot]
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

resolve_group_id() {
  local group="$1"
  local resolved=
  if [[ "$group" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$group" || return 1
    return 0
  fi
  if command -v getent >/dev/null 2>&1; then
    resolved="$(getent group "$group" | awk -F: 'NR == 1 { print $3 }')" ||
      return 1
    [[ "$resolved" =~ ^[0-9]+$ ]] || {
      echo "cannot resolve group ID for $group" >&2
      return 1
    }
    printf '%s\n' "$resolved" || return 1
    return 0
  fi
  if command -v dscl >/dev/null 2>&1; then
    resolved="$(
      dscl . -read "/Groups/$group" PrimaryGroupID |
        awk 'NR == 1 { print $2 }'
    )" || return 1
    [[ "$resolved" =~ ^[0-9]+$ ]] || {
      echo "cannot resolve group ID for $group" >&2
      return 1
    }
    printf '%s\n' "$resolved" || return 1
    return 0
  fi
  echo "cannot resolve group ID for $group" >&2
  return 1
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    echo "invalid $label: $value" >&2
    exit 1
  }
}

validate_nonnegative_number() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
    echo "invalid $label: $value" >&2
    exit 1
  }
}

trigger_test_sigkill() {
  local flag_name="$1"
  local checkpoint="$2"
  if [ "${!flag_name:-0}" != "1" ]; then
    return 0
  fi
  if [ "${RADAR_INSTALL_TEST_MODE:-0}" != "1" ] ||
    [[ ! "${RADAR_INSTALL_TEST_NONCE:-}" =~ ^[0-9a-f]{64}$ ]]; then
    echo \
      "refusing test crash checkpoint $checkpoint without explicit test mode and nonce" \
      >&2
    exit 70
  fi
  kill -KILL "${BASHPID:-$$}" || return 1
}

protocol_release() {
  local expected="${2:-}"
  if [ -n "$expected" ] && [ "$expected" != "$installer_protocol" ]; then
    echo "installer protocol mismatch: expected $expected, installed $installer_protocol" >&2
    exit 1
  fi
  printf '%s\n' "$installer_protocol" || return 1
}

validate_release_identity_values() {
  local identity_release_name="$1"
  local identity_sha="$2"
  local identity_digest="$3"
  if [[
    ! "$identity_release_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ||
    "$identity_release_name" == *".."* ||
    "$identity_release_name" == *"/"* ||
    "$identity_release_name" == *"\\"*
  ]]; then
    echo "invalid release name: expected one safe basename" >&2
    return 1
  fi
  [[ "$identity_sha" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || {
    echo "invalid GitHub SHA: expected a lowercase full object ID" >&2
    return 1
  }
  [[ "$identity_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "invalid artifact digest: expected sha256:<64 lowercase hex characters>" >&2
    return 1
  }
}

validate_transaction_id() {
  local identity_transaction_id="$1"
  [[ "$identity_transaction_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    echo "invalid deployment transaction ID" >&2
    return 1
  }
}

transaction_tarball_path() {
  printf '%s/%s.tar.gz\n' "$artifact_root" "$1" || return 1
}

validate_transaction_tarball_path_value() {
  local identity_tarball="$1"
  local identity_transaction_id="$2"
  local context="${3:-deployment}"
  local expected_tarball
  validate_transaction_id "$identity_transaction_id" || return 1
  expected_tarball="$(transaction_tarball_path "$identity_transaction_id")" || return 1
  [ "$identity_tarball" = "$expected_tarball" ] || {
    echo "$context tarball path is not owned by its transaction: $identity_tarball" >&2
    return 1
  }
}

inspect_upload_tarball() {
  local source_path="$1"
  "$node_bin" - "$source_path" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const sourcePath = process.argv[2];
if (!path.isAbsolute(sourcePath)) {
  throw new Error('release upload path must be absolute');
}
const info = fs.lstatSync(sourcePath, { bigint: true });
if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) {
  throw new Error('release upload must be one regular non-symlink file with one link');
}
if (info.size <= 0n || info.size > BigInt(Number.MAX_SAFE_INTEGER)) {
  throw new Error('release upload size is invalid');
}
const fd = fs.openSync(
  sourcePath,
  fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
);
try {
  const opened = fs.fstatSync(fd, { bigint: true });
  if (
    opened.dev !== info.dev ||
    opened.ino !== info.ino ||
    opened.nlink !== 1n ||
    !opened.isFile()
  ) {
    throw new Error('release upload changed while it was opened');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  for (;;) {
    const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
    if (bytes === 0) break;
    hash.update(buffer.subarray(0, bytes));
    offset += bytes;
  }
  if (BigInt(offset) !== opened.size) {
    throw new Error('release upload changed while it was hashed');
  }
  process.stdout.write(`${hash.digest('hex')} ${offset}\n`);
} finally {
  fs.closeSync(fd);
}
NODE
}

adopt_upload_tarball() {
  local expected_uid expected_gid
  expected_uid="$(id -u "$release_owner")" || return 1
  expected_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$upload_tarball" \
    "$tarball" \
    "$artifact_root" \
    "$tarball_sha256" \
    "$tarball_size_bytes" \
    "$expected_uid" \
    "$expected_gid" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  sourcePath,
  destinationPath,
  artifactRoot,
  expectedSha256,
  expectedSizeText,
  expectedUidText,
  expectedGidText,
] = process.argv.slice(2);
const expectedSize = Number(expectedSizeText);
const expectedUid = Number(expectedUidText);
const expectedGid = Number(expectedGidText);
if (
  !path.isAbsolute(sourcePath) ||
  destinationPath !== path.join(artifactRoot, path.basename(destinationPath)) ||
  !/^[0-9a-f]{64}$/.test(expectedSha256) ||
  !Number.isSafeInteger(expectedSize) ||
  expectedSize <= 0 ||
  !Number.isSafeInteger(expectedUid) ||
  !Number.isSafeInteger(expectedGid)
) {
  throw new Error('release upload adoption identity is invalid');
}
const rootInfo = fs.lstatSync(artifactRoot, { bigint: true });
if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
  throw new Error('deployment artifact root must be a regular directory');
}
if (fs.existsSync(destinationPath)) {
  throw new Error('transaction-owned release artifact already exists');
}
const sourceInfo = fs.lstatSync(sourcePath, { bigint: true });
if (
  !sourceInfo.isFile() ||
  sourceInfo.isSymbolicLink() ||
  sourceInfo.nlink !== 1n ||
  sourceInfo.size !== BigInt(expectedSize)
) {
  throw new Error('release upload changed before adoption');
}
if (sourceInfo.dev !== rootInfo.dev) {
  throw new Error('release upload and deployment artifact root must share one filesystem');
}
const fd = fs.openSync(
  sourcePath,
  fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
);
try {
  const opened = fs.fstatSync(fd, { bigint: true });
  if (
    !opened.isFile() ||
    opened.dev !== sourceInfo.dev ||
    opened.ino !== sourceInfo.ino ||
    opened.nlink !== 1n ||
    opened.size !== BigInt(expectedSize)
  ) {
    throw new Error('release upload changed while adoption began');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  for (;;) {
    const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
    if (bytes === 0) break;
    hash.update(buffer.subarray(0, bytes));
    offset += bytes;
  }
  if (offset !== expectedSize || hash.digest('hex') !== expectedSha256) {
    throw new Error('release upload content changed before adoption');
  }
  if (Number(opened.uid) !== expectedUid || Number(opened.gid) !== expectedGid) {
    fs.fchownSync(fd, expectedUid, expectedGid);
  }
  fs.fchmodSync(fd, 0o600);
  fs.fsyncSync(fd);
  const beforeRename = fs.lstatSync(sourcePath, { bigint: true });
  const owned = fs.fstatSync(fd, { bigint: true });
  if (
    beforeRename.dev !== owned.dev ||
    beforeRename.ino !== owned.ino ||
    beforeRename.nlink !== 1n
  ) {
    throw new Error('release upload path changed before atomic adoption');
  }
  fs.renameSync(sourcePath, destinationPath);
  const destinationInfo = fs.lstatSync(destinationPath, { bigint: true });
  if (
    !destinationInfo.isFile() ||
    destinationInfo.isSymbolicLink() ||
    destinationInfo.dev !== owned.dev ||
    destinationInfo.ino !== owned.ino ||
    destinationInfo.nlink !== 1n ||
    destinationInfo.size !== BigInt(expectedSize) ||
    Number(destinationInfo.uid) !== expectedUid ||
    Number(destinationInfo.gid) !== expectedGid ||
    Number(destinationInfo.mode & 0o777n) !== 0o600
  ) {
    throw new Error('transaction-owned release artifact identity is invalid after adoption');
  }
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
for (const directory of new Set([path.dirname(sourcePath), artifactRoot])) {
  const directoryFd = fs.openSync(directory, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
}
NODE
}

validate_owned_tarball_file() {
  local target="$1"
  local expected_sha="$2"
  local expected_size="$3"
  local owner_uid owner_gid
  validate_transaction_tarball_path_value "$target" "$4" "${5:-deployment}" || return 1
  owner_uid="$(id -u "$release_owner")" || return 1
  owner_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$target" \
    "$expected_sha" \
    "$expected_size" \
    "$owner_uid" \
    "$owner_gid" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const [target, expectedSha256, expectedSizeText, expectedUidText, expectedGidText] =
  process.argv.slice(2);
const expectedSize = Number(expectedSizeText);
const expectedUid = Number(expectedUidText);
const expectedGid = Number(expectedGidText);
if (
  !/^[0-9a-f]{64}$/.test(expectedSha256) ||
  !Number.isSafeInteger(expectedSize) ||
  expectedSize <= 0
) {
  throw new Error('transaction-owned release artifact digest identity is invalid');
}
const info = fs.lstatSync(target, { bigint: true });
if (
  !info.isFile() ||
  info.isSymbolicLink() ||
  info.nlink !== 1n ||
  info.size !== BigInt(expectedSize) ||
  Number(info.uid) !== expectedUid ||
  Number(info.gid) !== expectedGid ||
  Number(info.mode & 0o777n) !== 0o600
) {
  throw new Error('transaction-owned release artifact metadata is invalid');
}
const fd = fs.openSync(
  target,
  fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
);
try {
  const opened = fs.fstatSync(fd, { bigint: true });
  if (opened.dev !== info.dev || opened.ino !== info.ino || opened.nlink !== 1n) {
    throw new Error('transaction-owned release artifact changed while it was opened');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  for (;;) {
    const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
    if (bytes === 0) break;
    hash.update(buffer.subarray(0, bytes));
    offset += bytes;
  }
  if (offset !== expectedSize || hash.digest('hex') !== expectedSha256) {
    throw new Error('transaction-owned release artifact content is invalid');
  }
} finally {
  fs.closeSync(fd);
}
NODE
}

validate_pending_state_hash_value() {
  local identity_pending_state_hash="$1"
  [[ "$identity_pending_state_hash" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid deployment pending-state hash" >&2
    return 1
  }
}

validate_verification_id() {
  local identity_verification_id="$1"
  [[ "$identity_verification_id" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ]] || {
    echo "invalid deployment verification ID: expected <run-id>:<run-attempt>" >&2
    return 1
  }
}

validate_release_identity() {
  validate_release_identity_values "$release_name" "$expected_sha" "$expected_digest" || exit 1
  release_dir="$releases/$release_name"
  runtime_env_path="$runtime_env_dir/$release_name.env"
  if [ -n "$transaction_id" ]; then
    intent_dir="$base/.deploy-intent-$transaction_id"
    db_snapshot_dir="$backup_root/${release_name}-${transaction_id}"
  else
    intent_dir=
    db_snapshot_dir="$backup_root/$release_name"
  fi
  db_snapshot_path="$db_snapshot_dir/pre-migration.sqlite"
  db_snapshot_metadata_path="$db_snapshot_path.metadata.json"
  promotion_report_path="$pending_dir/promotion-report.json"
  if [ "$promotion_required" -eq 1 ]; then
    [[ "$required_score_receipt_id" =~ ^[0-9a-f]{64}$ ]] || {
      echo "invalid score receipt ID: expected 64 lowercase hexadecimal characters" >&2
      exit 1
    }
  fi
}

validate_common_runtime() {
  [ -d "$releases" ] || { echo "missing releases directory: $releases" >&2; exit 1; }
  [ -x "$node_bin" ] || { echo "node runtime not found: $node_bin" >&2; exit 1; }
  require_command "$flock_bin"
  [ -x "$cp_bin" ] || {
    echo "metadata-preserving copy runtime not found: $cp_bin" >&2
    exit 1
  }
  require_command mktemp
  case "$("$node_bin" -p 'process.platform')" in
    linux)
      require_command "$getfacl_bin"
      require_command "$getfattr_bin"
      ;;
    darwin)
      [ -x /bin/ls ] && [ -x /usr/bin/xattr ] || {
        echo "required macOS ACL/xattr metadata tooling is unavailable" >&2
        exit 1
      }
      ;;
    *)
      echo "database metadata preservation is unsupported on this platform" >&2
      exit 1
      ;;
  esac
  validate_shared_env || return 1
  validate_owner_separation || return 1
  resolve_probe_urls || return 1
  validate_positive_integer "readiness attempt count" "$readiness_attempts" || return 1
  validate_nonnegative_number "readiness sleep" "$readiness_sleep_seconds" || return 1
  validate_positive_integer "probe connect timeout" "$probe_connect_timeout_seconds" || return 1
  validate_positive_integer "probe max time" "$probe_max_time_seconds" || return 1
  validate_positive_integer "deployment lock timeout" "$lock_timeout_seconds" || return 1
  validate_positive_integer "pending deployment timeout" "$pending_timeout_seconds" || return 1
  validate_positive_integer "watchdog readiness attempt count" "$watchdog_ready_attempts" ||
    return 1
  validate_nonnegative_number "watchdog readiness sleep" "$watchdog_ready_sleep_seconds" ||
    return 1
  prepare_control_directories || return 1
}

validate_promotion_preflight() {
  local required
  [ "$promotion_required" -eq 1 ] || return 0
  for required in "$lsof_bin" "$getfacl_bin" "$getfattr_bin"; do
    require_command "$required"
  done
}

validate_shared_env() {
  local expected_uid expected_gid
  expected_uid="$(id -u "$shared_env_owner")" || return 1
  expected_gid="$(resolve_group_id "$shared_env_group")" || return 1
  "$node_bin" - "$shared/.env" "$expected_uid" "$expected_gid" "$shared_env_mode" <<'NODE' || return 1
const fs = require('node:fs');
const [path, expectedUid, expectedGid, expectedMode] = process.argv.slice(2);
let info;
try {
  info = fs.lstatSync(path);
} catch {
  throw new Error(`missing shared env: ${path}`);
}
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error(`shared env must be a regular non-symlink file: ${path}`);
}
const actualMode = (info.mode & 0o777).toString(8).padStart(3, '0');
const normalizedExpectedMode = expectedMode.replace(/^0+/, '').padStart(3, '0');
if (
  String(info.uid) !== expectedUid ||
  String(info.gid) !== expectedGid ||
  actualMode !== normalizedExpectedMode
) {
  throw new Error(
    `shared env owner/mode mismatch: expected ${expectedUid}:${expectedGid} ` +
    `${normalizedExpectedMode}, got ${info.uid}:${info.gid} ${actualMode}`,
  );
}
NODE
}

validate_owner_separation() {
  local runtime_uid release_uid
  runtime_uid="$(id -u "$runtime_user")" || return 1
  release_uid="$(id -u "$release_owner")" || return 1
  if [ "$runtime_uid" = "$release_uid" ] &&
    [ "${RADAR_INSTALL_ALLOW_OWNER_RUNTIME_MATCH:-0}" != "1" ]; then
    echo "release owner must differ from runtime user so deployed code remains runtime-read-only" >&2
    return 1
  fi
}

ensure_control_directory() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"
  if [ -L "$path" ]; then
    echo "control directory must not be a symlink: $path" >&2
    return 1
  fi
  install -d -m "$mode" -o "$owner" -g "$group" "$path" || return 1
  "$node_bin" - "$path" <<'NODE' || return 1
const fs = require('node:fs');
const path = process.argv[2];
const info = fs.lstatSync(path);
if (!info.isDirectory() || info.isSymbolicLink()) {
  throw new Error(`control path must be a non-symlink directory: ${path}`);
}
NODE
}

prepare_control_directories() {
  ensure_control_directory "$runtime_env_dir" 750 "$release_owner" "$runtime_group" ||
    return 1
  ensure_control_directory "$backup_root" 700 "$release_owner" "$release_group" ||
    return 1
  ensure_control_directory "$watchdog_log_dir" 750 "$release_owner" "$runtime_group" ||
    return 1
  ensure_control_directory "$smoke_dir" 700 "$runtime_user" "$runtime_group" ||
    return 1
  ensure_control_directory "$completion_root" 750 "$release_owner" "$runtime_group" ||
    return 1
  ensure_control_directory "$artifact_root" 700 "$release_owner" "$release_group" ||
    return 1
  ensure_control_directory \
    "$startup_authorization_dir" \
    750 \
    "$release_owner" \
    "$runtime_group" || return 1
  "$node_bin" - "$base" "$completion_root" <<'NODE' || return 1
const fs = require('node:fs');
const [base, completionRoot] = process.argv.slice(2);
const baseInfo = fs.statSync(base, { bigint: true });
const completionInfo = fs.statSync(completionRoot, { bigint: true });
if (baseInfo.dev !== completionInfo.dev) {
  throw new Error(
    'deployment pending state and completion receipts must share one filesystem',
  );
}
NODE
}

validate_auto_refresh_disabled() {
  "$node_bin" - "$shared/.env" <<'NODE' || return 1
const fs = require('node:fs');
const path = process.argv[2];
const assignments = new Map();
for (const line of fs.readFileSync(path, 'utf8').split(/\r?\n/)) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
  if (!match) continue;
  let value = match[2].trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  } else {
    value = value.replace(/\s+#.*$/, '').trim();
  }
  assignments.set(match[1], value);
}
const startup = String(assignments.get('REFRESH_ON_STARTUP') ?? '').toLowerCase();
const minutes = String(assignments.get('REFRESH_MINUTES') ?? '');
if (!['false', '0', 'no', 'off'].includes(startup) || minutes !== '0') {
  throw new Error(
    'production shared .env must explicitly disable REFRESH_ON_STARTUP and REFRESH_MINUTES',
  );
}
for (const key of [
  'RADAR_CODE_REVISION',
  'CODE_REVISION',
  'RADAR_DB_READ_ONLY',
  'RADAR_DB_BOOTSTRAP_MODE',
]) {
  if (assignments.has(key)) {
    throw new Error(
      `production shared .env must not define ${key}; the installer binds it per release`,
    );
  }
}
NODE
}

shared_env_value() {
  local key="$1"
  "$node_bin" - "$shared/.env" "$key" <<'NODE' || return 1
const fs = require('node:fs');
const [path, key] = process.argv.slice(2);
let found = null;
for (const line of fs.readFileSync(path, 'utf8').split(/\r?\n/)) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
  if (!match || match[1] !== key) continue;
  let value = match[2].trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  } else {
    value = value.replace(/\s+#.*$/, '').trim();
  }
  found = value;
}
if (found == null || found.length === 0) {
  throw new Error(`production shared .env must define ${key}`);
}
process.stdout.write(found);
NODE
}

resolve_probe_urls() {
  local configured_port origin
  if [ -z "$health_url" ] ||
    [ -z "$manifest_url" ] ||
    [ -z "$provenance_url" ] ||
    [ -z "$status_url" ] ||
    [ -z "$receipt_url_base" ]; then
    configured_port="$(shared_env_value PORT)" || {
      echo \
        "production probe URL overrides are incomplete and shared PORT is unavailable" \
        >&2
      return 1
    }
    if [[ ! "$configured_port" =~ ^[1-9][0-9]{0,4}$ ]] ||
      ((10#$configured_port > 65535)); then
      echo "production shared PORT must be an integer from 1 through 65535" >&2
      return 1
    fi
    origin="http://127.0.0.1:$configured_port"
    [ -n "$health_url" ] || health_url="$origin/api/health"
    [ -n "$manifest_url" ] || manifest_url="$origin/release-manifest.json"
    [ -n "$provenance_url" ] ||
      provenance_url="$origin/api/validation/opportunities"
    [ -n "$status_url" ] || status_url="$origin/api/status"
    [ -n "$receipt_url_base" ] || receipt_url_base="$origin/api/receipts"
  fi
  "$node_bin" - \
    "$health_url" \
    "$manifest_url" \
    "$provenance_url" \
    "$status_url" \
    "$receipt_url_base" <<'NODE' || return 1
const labels = [
  'health',
  'manifest',
  'provenance',
  'status',
  'receipt base',
];
for (const [index, value] of process.argv.slice(2).entries()) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`production ${labels[index]} probe URL is invalid: ${value}`);
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error(
      `production ${labels[index]} probe URL must be an absolute HTTP(S) URL without credentials or a fragment`,
    );
  }
}
NODE
}

resolve_database_path() {
  local configured
  configured="$(shared_env_value DB_PATH)" || return 1
  case "$configured" in
    /*) ;;
    *)
      echo "production DB_PATH must be absolute and outside the release tree: $configured" >&2
      exit 1
      ;;
  esac
  database_path="$("$node_bin" - "$configured" "$releases" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [dbPath, releasesPath] = process.argv.slice(2);
const info = fs.lstatSync(dbPath);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error(`production DB_PATH must be a regular non-symlink file: ${dbPath}`);
}
const resolved = fs.realpathSync(dbPath);
const releaseRoot = `${fs.realpathSync(releasesPath)}${path.sep}`;
if (resolved.startsWith(releaseRoot)) {
  throw new Error(`production DB_PATH must remain outside deployed releases: ${resolved}`);
}
process.stdout.write(resolved);
NODE
)" || return 1
}

resolve_quality_database_path() {
  local configured="$1"
  case "$configured" in
    /*) ;;
    *)
      echo "quality database path must be absolute: $configured" >&2
      exit 1
      ;;
  esac
  quality_database_path="$("$node_bin" - "$configured" "$database_path" "$releases" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [qualityPath, productionPath, releasesPath] = process.argv.slice(2);
const info = fs.lstatSync(qualityPath);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error(`quality database must be a regular non-symlink file: ${qualityPath}`);
}
const resolved = fs.realpathSync(qualityPath);
if (resolved === fs.realpathSync(productionPath)) {
  throw new Error('quality and production databases must be distinct files');
}
const releaseRoot = `${fs.realpathSync(releasesPath)}${path.sep}`;
if (resolved.startsWith(releaseRoot)) {
  throw new Error(`quality database must remain outside deployed releases: ${resolved}`);
}
process.stdout.write(resolved);
NODE
)" || return 1
}

write_runtime_env() {
  local tmp
  if [ -e "$runtime_env_path" ] || [ -L "$runtime_env_path" ]; then
    validate_runtime_env_file "$runtime_env_path" || return 1
    return 0
  fi
  tmp="$(mktemp "$runtime_env_dir/.${release_name}.env.XXXXXX")" || return 1
  {
    cat "$shared/.env" &&
    printf \
      '\n# Bound by installer protocol %s.\nRADAR_CODE_REVISION=%s\nRADAR_DB_READ_ONLY=1\nRADAR_DB_BOOTSTRAP_MODE=existing\n' \
      "$installer_protocol" "$expected_sha"
  } > "$tmp" || {
    rm -f "$tmp"
    return 1
  }
  chown "$release_owner:$runtime_group" "$tmp" || {
    rm -f "$tmp"
    return 1
  }
  chmod 640 "$tmp" || {
    rm -f "$tmp"
    return 1
  }
  fsync_file "$tmp" || {
    rm -f "$tmp"
    return 1
  }
  mv "$tmp" "$runtime_env_path" || {
    rm -f "$tmp"
    return 1
  }
  runtime_env_created=1
  fsync_directory "$runtime_env_dir" || return 1
  validate_runtime_env_file "$runtime_env_path" || return 1
}

validate_runtime_env_file() {
  local path="$1"
  local expected_uid expected_gid
  expected_uid="$(id -u "$release_owner")" || return 1
  expected_gid="$(resolve_group_id "$runtime_group")" || return 1
  "$node_bin" - \
    "$path" \
    "$expected_sha" \
    "$expected_uid" \
    "$expected_gid" \
    "$shared/.env" \
    "$installer_protocol" <<'NODE' || return 1
const fs = require('node:fs');
const [
  path,
  expectedRevision,
  expectedUid,
  expectedGid,
  sharedEnvPath,
  installerProtocol,
] = process.argv.slice(2);
const info = fs.lstatSync(path);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error(`release runtime env must be a regular non-symlink file: ${path}`);
}
if (
  String(info.uid) !== expectedUid ||
  String(info.gid) !== expectedGid ||
  (info.mode & 0o777) !== 0o640
) {
  throw new Error(`release runtime env has invalid owner or mode: ${path}`);
}
const contents = fs.readFileSync(path, 'utf8');
const expectedContents =
  `${fs.readFileSync(sharedEnvPath, 'utf8')}\n` +
  `# Bound by installer protocol ${installerProtocol}.\n` +
  `RADAR_CODE_REVISION=${expectedRevision}\n` +
  'RADAR_DB_READ_ONLY=1\n' +
  'RADAR_DB_BOOTSTRAP_MODE=existing\n';
if (contents !== expectedContents) {
  throw new Error(
    `release runtime env does not exactly propagate the current shared env: ${path}`,
  );
}
const assignments = new Map();
for (const line of contents.split(/\r?\n/)) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
  if (!match) continue;
  let value = match[2].trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) value = value.slice(1, -1);
  else value = value.replace(/\s+#.*$/, '').trim();
  assignments.set(match[1], value);
}
if (assignments.get('RADAR_CODE_REVISION') !== expectedRevision) {
  throw new Error(`release runtime env does not bind RADAR_CODE_REVISION=${expectedRevision}`);
}
if (assignments.get('RADAR_DB_READ_ONLY') !== '1') {
  throw new Error('release runtime env does not bind RADAR_DB_READ_ONLY=1');
}
if (assignments.get('RADAR_DB_BOOTSTRAP_MODE') !== 'existing') {
  throw new Error(
    'release runtime env does not bind RADAR_DB_BOOTSTRAP_MODE=existing',
  );
}
NODE
}

validate_runtime_env_link() {
  local root="$1"
  local link_target
  [ -L "$root/.env" ] || {
    echo "release runtime env is not a release-specific symlink: $root/.env" >&2
    return 1
  }
  link_target="$(readlink "$root/.env")" || {
    echo "failed to read release runtime env symlink: $root/.env" >&2
    return 1
  }
  [ "$link_target" = "$runtime_env_path" ] || {
    echo "release runtime env does not target $runtime_env_path" >&2
    return 1
  }
  validate_runtime_env_file "$runtime_env_path"
}

acquire_deploy_lock() {
  [ "$deploy_lock_held" -eq 0 ] || return 0
  exec 9>"$lock_file"
  "$flock_bin" -w "$lock_timeout_seconds" 9 || {
    exec 9>&-
    echo "timed out waiting for deployment lock: $lock_file" >&2
    exit 1
  }
  deploy_lock_held=1
}

release_deploy_lock() {
  [ "$deploy_lock_held" -eq 1 ] || return 0
  exec 9>&-
  deploy_lock_held=0
}

restart_service_outside_deploy_lock() {
  local restart_status=0
  [ "$deploy_lock_held" -eq 1 ] || {
    echo "service restart requires the deployment lock before handoff" >&2
    return 1
  }
  release_deploy_lock || return 1
  "$systemctl_bin" restart "$service_name" || restart_status=$?
  acquire_deploy_lock || return 1
  return "$restart_status"
}

run_as_runtime() {
  local current_user
  current_user="$(id -un)" || return 1
  if [ "$current_user" = "$runtime_user" ]; then
    "$@"
  else
    "$runuser_bin" -u "$runtime_user" -- "$@"
  fi
}

read_current_target() {
  if [ -L "$current" ]; then
    readlink "$current" || {
      echo "failed to read current release symlink: $current" >&2
      return 2
    }
    return 0
  fi
  if [ -e "$current" ]; then
    echo "current release path is not a symbolic link: $current" >&2
    return 2
  fi
  return 1
}

current_target_matches() {
  local expected_target="$1"
  local actual_target current_status
  if actual_target="$(read_current_target)"; then
    [ "$actual_target" = "$expected_target" ] && return 0
    return 1
  fi
  current_status=$?
  [ "$current_status" -eq 1 ] && return 1
  return 2
}

validate_release_archive() {
  local archive="$1"
  "$node_bin" - "$archive" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { pipeline } = require('node:stream/promises');
const { Writable } = require('node:stream');

const archivePath = process.argv[2];
const members = new Map();
const symlinks = new Map();
let globalPax = {};
let nextPax = {};
let nextLongName = null;
let nextLongLink = null;
let zeroBlocks = 0;
let pending = Buffer.alloc(0);
let currentEntry = null;

function fieldText(buffer, start, length) {
  const field = buffer.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString('utf8');
}

function tarNumber(buffer) {
  if (buffer.length === 0) return 0;
  if ((buffer[0] & 0x80) !== 0) {
    const bytes = Buffer.from(buffer);
    bytes[0] &= 0x7f;
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('release archive member size is too large');
    }
    return Number(value);
  }
  const text = buffer.toString('ascii').replace(/\0.*$/, '').trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) {
    throw new Error('release archive contains an invalid numeric header');
  }
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('release archive member size is invalid');
  }
  return value;
}

function validateChecksum(header) {
  const recorded = tarNumber(header.subarray(148, 156));
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  let computed = 0;
  for (const byte of copy) computed += byte;
  if (recorded !== computed) {
    throw new Error('release archive header checksum is invalid');
  }
}

function normalizeMemberPath(raw, label = 'member') {
  if (typeof raw !== 'string' || !raw || raw.includes('\0')) {
    throw new Error(`release archive ${label} path is invalid`);
  }
  if (
    path.posix.isAbsolute(raw) ||
    raw.startsWith('\\') ||
    /^[A-Za-z]:[\\/]/.test(raw)
  ) {
    throw new Error(`release archive ${label} path is absolute: ${raw}`);
  }
  const parts = [];
  for (const part of raw.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      throw new Error(`release archive ${label} path escapes the release root: ${raw}`);
    }
    parts.push(part);
  }
  const normalized = parts.join('/');
  if (!normalized) return '';
  if (normalized === '.env' || normalized.startsWith('.env/')) {
    throw new Error('release archive must not provide the managed .env path');
  }
  return normalized;
}

function resolveRelativeTarget(memberPath, rawTarget) {
  if (
    typeof rawTarget !== 'string' ||
    !rawTarget ||
    rawTarget.includes('\0') ||
    path.posix.isAbsolute(rawTarget) ||
    rawTarget.startsWith('\\') ||
    /^[A-Za-z]:[\\/]/.test(rawTarget)
  ) {
    throw new Error(`release archive link target is absolute or invalid: ${rawTarget}`);
  }
  const parts = path.posix.dirname(memberPath) === '.'
    ? []
    : path.posix.dirname(memberPath).split('/');
  for (const part of rawTarget.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (parts.length === 0) {
        throw new Error(
          `release archive link target escapes the release root: ${memberPath} -> ${rawTarget}`,
        );
      }
      parts.pop();
    } else {
      parts.push(part);
    }
  }
  return parts.join('/');
}

function parsePax(data) {
  const values = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) throw new Error('release archive PAX record is malformed');
    const lengthText = data.subarray(offset, space).toString('ascii');
    if (!/^[1-9][0-9]*$/.test(lengthText)) {
      throw new Error('release archive PAX record length is invalid');
    }
    const length = Number(lengthText);
    if (!Number.isSafeInteger(length) || length <= 0 || offset + length > data.length) {
      throw new Error('release archive PAX record exceeds its payload');
    }
    const record = data.subarray(space + 1, offset + length - 1).toString('utf8');
    const equals = record.indexOf('=');
    if (equals <= 0) throw new Error('release archive PAX record is invalid');
    values[record.slice(0, equals)] = record.slice(equals + 1);
    offset += length;
  }
  return values;
}

function registerMember(header) {
  validateChecksum(header);
  const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
  const prefix = fieldText(header, 345, 155);
  const headerName = fieldText(header, 0, 100);
  const headerLink = fieldText(header, 157, 100);
  const headerSize = tarNumber(header.subarray(124, 136));
  const rawName = nextLongName ?? nextPax.path ??
    (prefix ? `${prefix}/${headerName}` : headerName);
  const rawLink = nextLongLink ?? nextPax.linkpath ?? headerLink;
  const effectivePax = { ...globalPax, ...nextPax };
  const name = effectivePax.path ?? rawName;
  const linkName = effectivePax.linkpath ?? rawLink;
  const size = effectivePax.size == null
    ? headerSize
    : Number(effectivePax.size);
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error('release archive PAX member size is invalid');
  }
  nextPax = {};
  nextLongName = null;
  nextLongLink = null;

  if (['x', 'g', 'L', 'K'].includes(type)) {
    if (size > 1024 * 1024) {
      throw new Error('release archive metadata member is unreasonably large');
    }
    currentEntry = {
      type,
      size,
      padded: Math.ceil(size / 512) * 512,
      consumed: 0,
      chunks: [],
    };
    return;
  }

  const normalized = normalizeMemberPath(name);
  if (!normalized) {
    if (type !== '5') {
      throw new Error('release archive root entry must be a directory');
    }
  } else {
    if (members.has(normalized)) {
      throw new Error(`release archive contains duplicate member path: ${normalized}`);
    }
    if (type === '1') {
      throw new Error(`release archive hard links are unsupported: ${normalized}`);
    }
    if (!['', '0', '2', '5'].includes(type)) {
      throw new Error(`release archive contains unsupported member type: ${normalized}`);
    }
    const kind = type === '2'
      ? 'symlink'
      : type === '5'
        ? 'directory'
        : 'file';
    members.set(normalized, { kind, linkName });
    if (kind === 'symlink') {
      symlinks.set(normalized, resolveRelativeTarget(normalized, linkName));
    }
  }
  currentEntry = {
    type,
    size,
    padded: Math.ceil(size / 512) * 512,
    consumed: 0,
    chunks: null,
  };
}

function finishEntry(entry, data) {
  if (entry.type === 'x') nextPax = parsePax(data);
  if (entry.type === 'g') globalPax = { ...globalPax, ...parsePax(data) };
  if (entry.type === 'L') nextLongName = data.toString('utf8').replace(/\0.*$/, '');
  if (entry.type === 'K') nextLongLink = data.toString('utf8').replace(/\0.*$/, '');
}

function resolveSymlinkChain(input) {
  let parts = input ? input.split('/') : [];
  const visited = new Set();
  for (let pass = 0; pass < 256; pass += 1) {
    let replaced = false;
    for (let index = 0; index < parts.length; index += 1) {
      const prefix = parts.slice(0, index + 1).join('/');
      if (!symlinks.has(prefix)) continue;
      const key = `${prefix}\0${parts.slice(index + 1).join('/')}`;
      if (visited.has(key)) {
        throw new Error(`release archive contains a symlink cycle at ${prefix}`);
      }
      visited.add(key);
      const target = symlinks.get(prefix);
      parts = [
        ...(target ? target.split('/') : []),
        ...parts.slice(index + 1),
      ];
      replaced = true;
      break;
    }
    if (!replaced) return parts.join('/');
  }
  throw new Error('release archive symlink resolution exceeded its safety bound');
}

async function main() {
  const gunzip = zlib.createGunzip();
  const parser = new Writable({
    write(chunk, _encoding, callback) {
      try {
        pending = pending.length === 0
          ? Buffer.from(chunk)
          : Buffer.concat([pending, chunk]);
        for (;;) {
          if (currentEntry) {
            const remaining = currentEntry.padded - currentEntry.consumed;
            if (remaining === 0) {
              finishEntry(
                currentEntry,
                currentEntry.chunks
                  ? Buffer.concat(currentEntry.chunks, currentEntry.size)
                  : Buffer.alloc(0),
              );
              currentEntry = null;
              continue;
            }
            if (pending.length === 0) break;
            const consumedNow = Math.min(remaining, pending.length);
            if (
              currentEntry.chunks &&
              currentEntry.consumed < currentEntry.size
            ) {
              const payloadBytes = Math.min(
                consumedNow,
                currentEntry.size - currentEntry.consumed,
              );
              currentEntry.chunks.push(pending.subarray(0, payloadBytes));
            }
            currentEntry.consumed += consumedNow;
            pending = pending.subarray(consumedNow);
            continue;
          }
          if (pending.length < 512) break;
          const header = pending.subarray(0, 512);
          pending = pending.subarray(512);
          if (header.every((byte) => byte === 0)) {
            zeroBlocks += 1;
            continue;
          }
          if (zeroBlocks > 0) {
            throw new Error('release archive contains data after its end marker');
          }
          registerMember(header);
        }
        callback();
      } catch (error) {
        callback(error);
      }
    },
    final(callback) {
      try {
        if (currentEntry || pending.length !== 0) {
          throw new Error('release archive is truncated');
        }
        if (zeroBlocks < 2) {
          throw new Error('release archive is missing its end marker');
        }
        for (const [member, record] of members) {
          const parent = path.posix.dirname(member);
          if (parent !== '.') resolveSymlinkChain(parent);
          if (record.kind === 'symlink') {
            resolveSymlinkChain(symlinks.get(member));
          }
        }
        callback();
      } catch (error) {
        callback(error);
      }
    },
  });
  await pipeline(fs.createReadStream(archivePath), gunzip, parser);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
NODE
}

validate_release_tree_containment() {
  local root="$1"
  local allow_managed_env="${2:-0}"
  local managed_env_target="${3:-}"
  "$node_bin" - \
    "$root" \
    "$allow_managed_env" \
    "$managed_env_target" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const [root, allowManagedEnvText, managedEnvTarget] = process.argv.slice(2);
const allowManagedEnv = allowManagedEnvText === '1';
const rootInfo = fs.lstatSync(root);
if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
  throw new Error(`release root must be a regular directory: ${root}`);
}
const rootReal = fs.realpathSync(root);
const rootPrefix = `${rootReal}${path.sep}`;

function contained(realPath) {
  return realPath === rootReal || realPath.startsWith(rootPrefix);
}

function visit(target, relative) {
  const info = fs.lstatSync(target);
  if (info.isSymbolicLink()) {
    const linkTarget = fs.readlinkSync(target);
    if (relative === '.env') {
      if (!allowManagedEnv || !managedEnvTarget || linkTarget !== managedEnvTarget) {
        throw new Error('release .env is not the exact installer-managed runtime link');
      }
      const targetInfo = fs.lstatSync(managedEnvTarget);
      if (!targetInfo.isFile() || targetInfo.isSymbolicLink()) {
        throw new Error('release .env target is not a validated regular runtime env');
      }
      if (fs.realpathSync(target) !== fs.realpathSync(managedEnvTarget)) {
        throw new Error('release .env does not resolve to its exact managed runtime env');
      }
      return;
    }
    if (path.isAbsolute(linkTarget)) {
      throw new Error(`release symlink target must be relative: ${relative}`);
    }
    let resolved;
    try {
      resolved = fs.realpathSync(target);
    } catch {
      throw new Error(`release symlink is dangling or cyclic: ${relative}`);
    }
    if (!contained(resolved)) {
      throw new Error(`release symlink escapes the release root: ${relative}`);
    }
    return;
  }
  if (!info.isDirectory() && !info.isFile()) {
    throw new Error(`release tree contains an unsupported entry: ${relative || '.'}`);
  }
  if (!contained(fs.realpathSync(target))) {
    throw new Error(`release entry escapes the release root: ${relative || '.'}`);
  }
  if (info.isFile() && info.nlink !== 1) {
    throw new Error(`release tree contains a hard-linked file: ${relative}`);
  }
  if (info.isDirectory()) {
    for (const entry of fs.readdirSync(target)) {
      visit(
        path.join(target, entry),
        relative ? path.join(relative, entry) : entry,
      );
    }
  }
}

visit(root, '');
NODE
}

release_digest() {
  validate_release_tree_containment "$1" 1 "$runtime_env_path" || return 1
  "$node_bin" - "$1" "$manifest_relative" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = process.argv[2];
const manifestRelative = process.argv[3];
const excluded = new Set(['.env', manifestRelative]);
const hash = createHash('sha256');

function visit(relative) {
  const absolute = path.join(root, relative);
  const entries = fs.readdirSync(absolute, { withFileTypes: true })
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const entry of entries) {
    const child = relative ? path.join(relative, entry.name) : entry.name;
    if (excluded.has(child)) continue;
    const childPath = path.join(root, child);
    const info = fs.lstatSync(childPath);
    if (info.isDirectory()) {
      hash.update(`D\0${child}\0`);
      visit(child);
    } else if (info.isSymbolicLink()) {
      hash.update(`L\0${child}\0${fs.readlinkSync(childPath)}\0`);
    } else if (info.isFile()) {
      hash.update(`F\0${child}\0${info.size}\0`);
      hash.update(fs.readFileSync(childPath));
      hash.update('\0');
    } else {
      throw new Error(`unsupported release artifact entry: ${child}`);
    }
  }
}

visit('');
process.stdout.write(`sha256:${hash.digest('hex')}`);
NODE
}

validate_manifest_file() {
  local root="$1"
  local computed_digest="${2:-}"
  validate_release_tree_containment "$root" 1 "$runtime_env_path" || return 1
  [ -f "$root/$manifest_relative" ] || {
    echo "release artifact is missing $manifest_relative" >&2
    return 1
  }
  "$node_bin" - \
    "$root/$manifest_relative" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$installer_protocol" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  manifestPath,
  releaseName,
  githubSha,
  artifactDigest,
  installerProtocol,
] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const expectedKeys = [
  'artifactDigest',
  'controlPlane',
  'githubSha',
  'installerProtocol',
  'releaseName',
  'runtimeCodeRevision',
  'schemaVersion',
];
const actualKeys = Object.keys(manifest).sort();
if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
  throw new Error(`release manifest keys are invalid: ${actualKeys.join(', ')}`);
}
const expectedControlPlane = {
  installer: 'ops/viralo/openclaw-release-radar-install-release.sh',
  applicationService: 'ops/viralo/openclaw-release-radar.service',
  reconcileBootService: 'ops/viralo/openclaw-release-radar-reconcile-boot.service',
  reconcileService: 'ops/viralo/openclaw-release-radar-reconcile.service',
  reconcileTimer: 'ops/viralo/openclaw-release-radar-reconcile.timer',
  serviceDropIn: 'ops/viralo/openclaw-release-radar.service.d/10-deploy-reconcile.conf',
};
if (
  manifest.schemaVersion !== 4 ||
  manifest.releaseName !== releaseName ||
  manifest.githubSha !== githubSha ||
  manifest.runtimeCodeRevision !== githubSha ||
  manifest.artifactDigest !== artifactDigest ||
  manifest.installerProtocol !== Number(installerProtocol)
) {
  throw new Error('release manifest identity does not match activation arguments');
}
if (
  !manifest.controlPlane ||
  Array.isArray(manifest.controlPlane) ||
  typeof manifest.controlPlane !== 'object' ||
  JSON.stringify(Object.keys(manifest.controlPlane).sort()) !==
    JSON.stringify(Object.keys(expectedControlPlane).sort())
) {
  throw new Error('release manifest controlPlane keys are invalid');
}
for (const [name, expectedPath] of Object.entries(expectedControlPlane)) {
  const entry = manifest.controlPlane[name];
  if (
    !entry ||
    Array.isArray(entry) ||
    typeof entry !== 'object' ||
    JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(['path', 'sha256']) ||
    entry.path !== expectedPath ||
    typeof entry.sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(entry.sha256)
  ) {
    throw new Error(`release manifest controlPlane entry is invalid: ${name}`);
  }
  const target = path.join(path.dirname(path.dirname(manifestPath)), expectedPath);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`release control-plane file is not a regular file: ${expectedPath}`);
  }
  const actual = createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  if (actual !== entry.sha256) {
    throw new Error(`release control-plane digest mismatch: ${name}`);
  }
}
NODE
  if [ -z "$computed_digest" ]; then
    computed_digest="$(release_digest "$root")" || return 1
  fi
  [ "$computed_digest" = "$expected_digest" ] || {
    echo "release artifact digest mismatch: expected $expected_digest, got $computed_digest" >&2
    return 1
  }
}

validate_runtime() {
  local root="$1"
  local smoke_db="$smoke_dir/${release_name}.$$.$RANDOM.sqlite"
  local required smoke_status=0
  validate_release_tree_containment "$root" 1 "$runtime_env_path" || return 1
  for required in \
    dist/index.js \
    dist/routes/api.js \
    dist/lib/releaseValidationOpportunityStatus.js \
    dist/lib/startupAuthorization.js \
    node_modules/express/package.json \
    node_modules/dotenv/package.json
  do
    [ -f "$root/$required" ] || {
      echo "release artifact is missing production runtime file: $required" >&2
      return 1
    }
  done
  if [ "$promotion_required" -eq 1 ] &&
    [ -z "${RADAR_INSTALL_PROMOTION_BIN:-}" ]; then
    for required in \
      "$promotion_runtime_relative/package.json" \
      "$promotion_runtime_relative/scripts/promote-quality-db.mjs" \
      "$promotion_runtime_relative/scripts/run-promote-quality-db.sh" \
      "$promotion_runtime_relative/scripts/validation/record-promotion.mjs" \
      "$promotion_runtime_relative/src/lib/db.ts" \
      "$promotion_runtime_relative/node_modules/tsx/package.json" \
      "$promotion_runtime_relative/node_modules/dotenv/package.json" \
      "$promotion_runtime_relative/node_modules/esbuild/package.json"
    do
      [ -f "$root/$required" ] || {
        echo "release artifact is missing promotion runtime file: $required" >&2
        return 1
      }
    done
    [ -f "$root/$promotion_runtime_relative/node_modules/tsx/dist/cli.mjs" ] || {
      echo "release artifact is missing the promotion runtime tsx CLI" >&2
      return 1
    }
    "$node_bin" - "$root/$promotion_runtime_relative/package.json" <<'NODE' || return 1
const fs = require('node:fs');
const packagePath = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
if (
  !pkg ||
  Array.isArray(pkg) ||
  typeof pkg !== 'object' ||
  pkg.scripts?.['promote:quality-db'] !== 'sh scripts/run-promote-quality-db.sh'
) {
  throw new Error(
    'promotion runtime package must expose the supported promote:quality-db lifecycle',
  );
}
NODE
  fi
  [ ! -e "$root/node_modules/tsx" ] || {
    echo "release artifact unexpectedly contains dev-only tsx" >&2
    return 1
  }

  "$node_bin" --check "$root/dist/index.js" || return 1
  "$node_bin" --check "$root/dist/routes/api.js" || return 1
  run_as_runtime env \
    RELEASE_ROOT="$root" \
    DB_PATH="$smoke_db" \
    RADAR_CODE_REVISION="$expected_sha" \
    RADAR_DB_READ_ONLY=0 \
    REFRESH_ON_STARTUP=false \
    REFRESH_MINUTES=0 \
    "$node_bin" <<'NODE' || smoke_status=$?
const { api } = require(`${process.env.RELEASE_ROOT}/dist/routes/api.js`);
const paths = new Set(
  api.stack
    .filter((layer) => layer.route)
    .map((layer) => layer.route.path),
);
for (const path of ['/live', '/health', '/validation/opportunities']) {
  if (!paths.has(path)) throw new Error(`production API is missing ${path}`);
}
NODE
  rm -f "$smoke_db" "$smoke_db-wal" "$smoke_db-shm" "$smoke_db-journal" || return 1
  [ "$smoke_status" -eq 0 ] || return "$smoke_status"
}

curl_probe() {
  "$curl_bin" \
    --fail \
    --silent \
    --show-error \
    --connect-timeout "$probe_connect_timeout_seconds" \
    --max-time "$probe_max_time_seconds" \
    "$@"
}

semantic_ready() {
  local payload
  payload="$(curl_probe "$health_url")" || return 1
  "$node_bin" -e '
    const payload = JSON.parse(process.argv[1]);
    const expectedChecks = [
      "closureProof",
      "database",
      "ingestion",
      "recommendation",
      "releaseWindow",
      "scoreAudit",
      "sourceIdentity",
    ];
    const checks = payload.checks;
    if (
      payload.schemaVersion !== 1 ||
      payload.ok !== true ||
      payload.status !== "ready" ||
      !Array.isArray(payload.failures) ||
      payload.failures.length !== 0 ||
      !checks ||
      Array.isArray(checks) ||
      typeof checks !== "object" ||
      JSON.stringify(Object.keys(checks).sort()) !== JSON.stringify(expectedChecks) ||
      expectedChecks.some((name) => checks[name]?.ok !== true)
    ) process.exit(1);
  ' "$payload"
}

served_manifest_matches() {
  local expected_root="${1:-$release_dir}"
  local payload
  payload="$(curl_probe -H 'Cache-Control: no-cache' "$manifest_url")" || return 1
  "$node_bin" - "$payload" "$expected_root/$manifest_relative" <<'NODE' || return 1
    const { isDeepStrictEqual } = require("node:util");
    const fs = require("node:fs");
    const payload = JSON.parse(process.argv[2]);
    const expected = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
    const expectedKeys = [
      "artifactDigest",
      "controlPlane",
      "githubSha",
      "installerProtocol",
      "releaseName",
      "runtimeCodeRevision",
      "schemaVersion",
    ];
    if (
      JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(expectedKeys) ||
      !isDeepStrictEqual(payload, expected)
    ) process.exit(1);
NODE
}

served_api_provenance_matches() {
  local expected_revision="${1:-$expected_sha}"
  local payload
  payload="$(curl_probe -H 'Cache-Control: no-cache' "$provenance_url")" || return 1
  "$node_bin" -e '
    const payload = JSON.parse(process.argv[1]);
    if (
      payload?.schemaVersion !== 2 ||
      payload?.currentSeries?.codeRevision !== process.argv[2]
    ) process.exit(1);
  ' "$payload" "$expected_revision" || return 1
}

served_score_receipt_matches() {
  [ "$promotion_required" -eq 1 ] || return 0
  local status_payload receipt_payload
  status_payload="$(curl_probe -H 'Cache-Control: no-cache' "$status_url")" || return 1
  receipt_payload="$(
    curl_probe -H 'Cache-Control: no-cache' \
      "$receipt_url_base/$required_score_receipt_id"
  )" || return 1
  "$node_bin" -e '
    const status = JSON.parse(process.argv[1]);
    const receipt = JSON.parse(process.argv[2]);
    const expectedReceiptId = process.argv[3];
    const expectedRevision = process.argv[4];
    if (
      status?.schemaVersion !== 1 ||
      status?.refreshing !== false ||
      status?.lastError !== null ||
      status?.currentScoreAuthorizationStatus !== "authorized" ||
      status?.currentScoreReceiptStatus !== "success" ||
      status?.currentScoreReceiptId !== expectedReceiptId ||
      receipt?.schemaVersion !== 1 ||
      receipt?.receipt?.receiptId !== expectedReceiptId ||
      receipt?.receipt?.outcome !== "success" ||
      receipt?.receipt?.attempt?.codeRevision !== expectedRevision ||
      receipt?.receipt?.terminal?.payload?.codeRevision !== expectedRevision ||
      receipt?.receipt?.verification?.verified !== true
    ) process.exit(1);
  ' "$status_payload" "$receipt_payload" "$required_score_receipt_id" "$expected_sha" ||
    return 1
}

manifest_runtime_revision() {
  local root="$1"
  local previous_runtime_env="$runtime_env_dir/$(basename "$root").env"
  validate_release_tree_containment "$root" 1 "$previous_runtime_env" || return 1
  "$node_bin" - "$root/$manifest_relative" "$root" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [manifestPath, root] = process.argv.slice(2);
const info = fs.lstatSync(manifestPath);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error('previous release manifest must be a regular non-symlink file');
}
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const expectedKeys = [
  'artifactDigest',
  'controlPlane',
  'githubSha',
  'installerProtocol',
  'releaseName',
  'runtimeCodeRevision',
  'schemaVersion',
];
const legacyControlPlane = {
  installer: 'ops/viralo/openclaw-release-radar-install-release.sh',
  reconcileBootService: 'ops/viralo/openclaw-release-radar-reconcile-boot.service',
  reconcileService: 'ops/viralo/openclaw-release-radar-reconcile.service',
  reconcileTimer: 'ops/viralo/openclaw-release-radar-reconcile.timer',
  serviceDropIn: 'ops/viralo/openclaw-release-radar.service.d/10-deploy-reconcile.conf',
};
const currentControlPlane = {
  ...legacyControlPlane,
  applicationService: 'ops/viralo/openclaw-release-radar.service',
};
if (
  !manifest ||
  Array.isArray(manifest) ||
  typeof manifest !== 'object' ||
  JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expectedKeys)
) {
  throw new Error('previous release manifest shape is invalid');
}
const expectedControlPlane =
  manifest.schemaVersion === 3 && manifest.installerProtocol === 4
    ? legacyControlPlane
    : manifest.schemaVersion === 4 && manifest.installerProtocol === 5
      ? currentControlPlane
      : null;
if (
  expectedControlPlane === null ||
  manifest.releaseName !== path.basename(root) ||
  !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(manifest.githubSha) ||
  manifest.runtimeCodeRevision !== manifest.githubSha ||
  !/^sha256:[0-9a-f]{64}$/.test(manifest.artifactDigest)
) {
  throw new Error('previous release manifest identity is invalid');
}
if (
  !manifest.controlPlane ||
  Array.isArray(manifest.controlPlane) ||
  typeof manifest.controlPlane !== 'object' ||
  JSON.stringify(Object.keys(manifest.controlPlane).sort()) !==
    JSON.stringify(Object.keys(expectedControlPlane).sort())
) {
  throw new Error('previous release manifest controlPlane keys are invalid');
}
for (const [name, expectedPath] of Object.entries(expectedControlPlane)) {
  const entry = manifest.controlPlane[name];
  if (
    !entry ||
    Array.isArray(entry) ||
    typeof entry !== 'object' ||
    JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(['path', 'sha256']) ||
    entry.path !== expectedPath ||
    typeof entry.sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(entry.sha256)
  ) {
    throw new Error(`previous release controlPlane entry is invalid: ${name}`);
  }
  const target = path.join(root, expectedPath);
  const targetInfo = fs.lstatSync(target);
  if (!targetInfo.isFile() || targetInfo.isSymbolicLink()) {
    throw new Error(`previous release control-plane file is invalid: ${expectedPath}`);
  }
  const actual = createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  if (actual !== entry.sha256) {
    throw new Error(`previous release control-plane digest mismatch: ${name}`);
  }
}
process.stdout.write(manifest.runtimeCodeRevision);
NODE
}

wait_until_ready() {
  local require_manifest="${1:-0}"
  local expected_root="${2:-$release_dir}"
  local expected_revision="${3:-$expected_sha}"
  local require_score_receipt="${4:-$require_manifest}"
  local attempt
  for ((attempt = 1; attempt <= readiness_attempts; attempt += 1)); do
    if semantic_ready &&
      {
        [ "$require_manifest" != "1" ] ||
          {
            served_manifest_matches "$expected_root" &&
              served_api_provenance_matches "$expected_revision" &&
              {
                [ "$require_score_receipt" != "1" ] ||
                  served_score_receipt_matches
              }
          }
      }; then
      return 0
    fi
    sleep "$readiness_sleep_seconds" || return 1
  done
  return 1
}

switch_current() {
  local target="$1"
  next_link="$base/.current.${release_name}.$$.$RANDOM"
  ln -s "$target" "$next_link" || return 1
  chown -h "$release_owner:$release_group" "$next_link" || true
  "$node_bin" - "$next_link" "$current" <<'NODE' || return 1
const fs = require('node:fs');
fs.renameSync(process.argv[2], process.argv[3]);
NODE
  next_link=
  fsync_directory "$base" || return 1
}

show_diagnostics() {
  "$systemctl_bin" --no-pager --full status "$service_name" || true
  "$journalctl_bin" -u "$service_name" -n 100 --no-pager || true
  curl_probe "$health_url" || true
  curl_probe -H 'Cache-Control: no-cache' "$manifest_url" || true
  curl_probe -H 'Cache-Control: no-cache' "$provenance_url" || true
  if [ "$promotion_required" -eq 1 ]; then
    curl_probe -H 'Cache-Control: no-cache' "$status_url" || true
    curl_probe -H 'Cache-Control: no-cache' \
      "$receipt_url_base/$required_score_receipt_id" || true
  fi
}

seal_release_tree() {
  local root="$1"
  local expected_uid expected_gid
  validate_release_tree_containment "$root" 1 "$runtime_env_path" || return 1
  expected_uid="$(id -u "$release_owner")" || return 1
  expected_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$root" \
    "$expected_uid" \
    "$expected_gid" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const [root, expectedUid, expectedGid] = process.argv.slice(2);
function visit(target) {
  let info = fs.lstatSync(target);
  if (info.isSymbolicLink()) {
    fs.lchownSync(target, Number(expectedUid), Number(expectedGid));
  } else {
    fs.chownSync(target, Number(expectedUid), Number(expectedGid));
    fs.chmodSync(
      target,
      info.isDirectory() || (info.mode & 0o111) !== 0 ? 0o755 : 0o644,
    );
    if (info.isDirectory()) {
      for (const entry of fs.readdirSync(target)) visit(path.join(target, entry));
    }
  }
  info = fs.lstatSync(target);
  if (String(info.uid) !== expectedUid || String(info.gid) !== expectedGid) {
    throw new Error(`release entry has invalid owner: ${target}`);
  }
  if (!info.isSymbolicLink() && (info.mode & 0o022) !== 0) {
    throw new Error(`release entry is writable by group or other users: ${target}`);
  }
}
visit(root);
NODE
}

snapshot_database() {
  [ ! -e "$db_snapshot_dir" ] && [ ! -L "$db_snapshot_dir" ] || {
    echo "pre-migration snapshot path already exists: $db_snapshot_dir" >&2
    return 1
  }
  install -d -m 700 -o "$release_owner" -g "$release_group" "$db_snapshot_dir" ||
    return 1
  local expected_key_uid sidecar_uid sidecar_gid
  expected_key_uid="$(id -u "$release_owner")" || return 1
  sidecar_uid="$expected_key_uid"
  sidecar_gid="$(resolve_group_id "$release_group")" || return 1
  db_snapshot_sha256="$("$node_bin" - \
    "$database_path" \
    "$db_snapshot_path" \
    "$db_snapshot_metadata_path" \
    "$transaction_id" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$verifier_key_path" \
    "$expected_key_uid" \
    "$sidecar_uid" \
    "$sidecar_gid" \
    "$cp_bin" <<'NODE'
const { createHash, createHmac } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync, backup } = require('node:sqlite');
const [
  sourcePath,
  snapshotPath,
  metadataPath,
  transactionId,
  releaseName,
  releaseSha,
  artifactDigest,
  verifierKeyPath,
  expectedKeyUid,
  sidecarUidText,
  sidecarGidText,
  cpBin,
] = process.argv.slice(2);

function run(command, args, action) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `could not ${action}: ${result.error?.message ?? String(result.stderr ?? '').trim() ?? `exit ${result.status}`}`,
    );
  }
  return String(result.stdout ?? '').trimEnd();
}

function readAcl(target) {
  if (process.platform === 'linux') {
    return {
      format: 'posix-getfacl',
      entries: run(
        'getfacl',
        ['-c', '--absolute-names', '--', target],
        'read database ACLs',
      ).split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')),
    };
  }
  if (process.platform === 'darwin') {
    return {
      format: 'darwin-ls-le',
      entries: run('/bin/ls', ['-lde', target], 'read database ACLs')
        .split('\n')
        .slice(1)
        .map((line) => line.trim())
        .filter(Boolean),
    };
  }
  throw new Error(`database ACL preservation is unsupported on ${process.platform}`);
}

function readXattrs(target) {
  if (process.platform === 'linux') {
    return {
      format: 'linux-getfattr-hex',
      entries: run(
        'getfattr',
        ['--absolute-names', '-d', '-m', '-', '-e', 'hex', '--', target],
        'read database extended attributes and security labels',
      ).split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
        .sort(),
    };
  }
  if (process.platform === 'darwin') {
    const names = run('/usr/bin/xattr', [target], 'list database extended attributes')
      .split('\n')
      .map((name) => name.trim())
      .filter(Boolean)
      .sort();
    return {
      format: 'darwin-xattr-hex',
      entries: names.map((name) => [
        name,
        run(
          '/usr/bin/xattr',
          ['-px', name, target],
          `read database extended attribute ${name}`,
        ).replace(/\s+/g, '').toLowerCase(),
      ]),
    };
  }
  throw new Error(
    `database extended-attribute preservation is unsupported on ${process.platform}`,
  );
}

function securityLabels(xattrs) {
  return xattrs.entries.filter((entry) => {
    const name = Array.isArray(entry) ? entry[0] : String(entry).split('=', 1)[0];
    return name.startsWith('security.');
  });
}

function readMetadata(target) {
  const info = fs.lstatSync(target, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) {
    throw new Error(`database metadata source must be one regular file: ${target}`);
  }
  const xattrs = readXattrs(target);
  return {
    uid: String(info.uid),
    gid: String(info.gid),
    mode: Number(info.mode & 0o7777n),
    acl: readAcl(target),
    xattrs,
    securityLabels: securityLabels(xattrs),
  };
}

function cloneWithMetadata(source, destination) {
  fs.rmSync(destination, { force: true });
  if (process.platform === 'linux') {
    run(
      cpBin,
      ['--preserve=all', '--', source, destination],
      'clone database metadata with GNU cp',
    );
    return;
  }
  if (process.platform === 'darwin') {
    run(cpBin, ['-p', source, destination], 'clone database metadata');
    return;
  }
  throw new Error(`metadata-preserving copy is unsupported on ${process.platform}`);
}

function copyContents(source, destination) {
  const sourceFd = fs.openSync(source, 'r');
  const destinationFd = fs.openSync(destination, 'r+');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    fs.ftruncateSync(destinationFd, 0);
    for (;;) {
      const bytes = fs.readSync(sourceFd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      let written = 0;
      while (written < bytes) {
        written += fs.writeSync(
          destinationFd,
          buffer,
          written,
          bytes - written,
          null,
        );
      }
    }
    fs.fsyncSync(destinationFd);
  } finally {
    fs.closeSync(destinationFd);
    fs.closeSync(sourceFd);
  }
}

function restoreOwnerGroupAndMode(target, metadata) {
  let info = fs.statSync(target, { bigint: true });
  if (String(info.uid) !== metadata.uid || String(info.gid) !== metadata.gid) {
    fs.chownSync(target, Number(metadata.uid), Number(metadata.gid));
    info = fs.statSync(target, { bigint: true });
  }
  if (Number(info.mode & 0o7777n) !== metadata.mode) {
    fs.chmodSync(target, metadata.mode);
  }
}

function hashFile(target) {
  const hash = createHash('sha256');
  const fd = fs.openSync(target, 'r');
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function quickCheck(target, label) {
  const database = new DatabaseSync(target, { readOnly: true, timeout: 30_000 });
  try {
    const result = database.prepare('PRAGMA quick_check').get();
    if (!result || result.quick_check !== 'ok') {
      throw new Error(`${label} quick_check failed: ${JSON.stringify(result)}`);
    }
  } finally {
    database.close();
  }
}

function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}

async function main() {
  const sourceMetadata = readMetadata(sourcePath);
  const contentPath = `${snapshotPath}.content-${process.pid}-${Date.now()}`;
  const source = new DatabaseSync(sourcePath, { readOnly: true, timeout: 30_000 });
  try {
    await backup(source, contentPath);
  } finally {
    source.close();
  }
  try {
    quickCheck(contentPath, 'pre-migration snapshot content');
    cloneWithMetadata(sourcePath, snapshotPath);
    copyContents(contentPath, snapshotPath);
    restoreOwnerGroupAndMode(snapshotPath, sourceMetadata);
    const copiedMetadata = readMetadata(snapshotPath);
    if (JSON.stringify(copiedMetadata) !== JSON.stringify(sourceMetadata)) {
      throw new Error(
        'pre-migration snapshot could not preserve owner, group, mode, ACLs, xattrs, and security labels',
      );
    }
    quickCheck(snapshotPath, 'pre-migration snapshot');
  } finally {
    fs.rmSync(contentPath, { force: true });
  }
  const snapshotSha256 = hashFile(snapshotPath);
  const verifierKey = readVerifierKey();
  const verifierKeyId = createHash('sha256').update(verifierKey).digest('hex');
  const payload = {
    schemaVersion: 1,
    transactionId,
    releaseName,
    releaseSha,
    artifactDigest,
    databasePath: sourcePath,
    snapshotPath,
    snapshotSha256,
    metadata: sourceMetadata,
    verifierKeyId,
    recordedAt: new Date().toISOString(),
  };
  const contentHash = createHash('sha256')
    .update(`installer-db-snapshot-metadata-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
  const authenticationTag = createHmac('sha256', verifierKey)
    .update(`installer-db-snapshot-metadata-auth-v1\0${JSON.stringify({
      ...payload,
      contentHash,
    })}`)
    .digest('hex');
  const record = { ...payload, contentHash, authenticationTag };
  const temporaryMetadata = `${metadataPath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(
    temporaryMetadata,
    `${JSON.stringify(record, null, 2)}\n`,
    { mode: 0o600, flag: 'wx' },
  );
  let sidecarInfo = fs.statSync(temporaryMetadata, { bigint: true });
  if (
    String(sidecarInfo.uid) !== sidecarUidText ||
    String(sidecarInfo.gid) !== sidecarGidText
  ) {
    fs.chownSync(
      temporaryMetadata,
      Number(sidecarUidText),
      Number(sidecarGidText),
    );
  }
  fs.chmodSync(temporaryMetadata, 0o600);
  const metadataFd = fs.openSync(temporaryMetadata, 'r');
  try {
    fs.fsyncSync(metadataFd);
  } finally {
    fs.closeSync(metadataFd);
  }
  fs.renameSync(temporaryMetadata, metadataPath);
  const fd = fs.openSync(snapshotPath, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const directoryFd = fs.openSync(path.dirname(snapshotPath), 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
  process.stdout.write(snapshotSha256);
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
NODE
  )" || return 1
  fsync_directory "$backup_root" || return 1
  db_snapshot_created=1
}

validate_database_snapshot_metadata_at() {
  local state_root="$1"
  local state_snapshot state_snapshot_sha256 state_database
  local state_transaction_id state_release_name state_release_sha
  local state_artifact_digest metadata_path expected_key_uid sidecar_uid sidecar_gid
  state_snapshot="$(read_state_field "$state_root" db_snapshot_path)" || return 1
  state_snapshot_sha256="$(
    read_state_field "$state_root" db_snapshot_sha256
  )" || return 1
  state_database="$(read_state_field "$state_root" database_path)" || return 1
  state_transaction_id="$(read_state_field "$state_root" transaction_id)" ||
    return 1
  state_release_name="$(read_state_field "$state_root" release_name)" || return 1
  state_release_sha="$(read_state_field "$state_root" github_sha)" || return 1
  state_artifact_digest="$(
    read_state_field "$state_root" artifact_digest
  )" || return 1
  metadata_path="$state_snapshot.metadata.json"
  expected_key_uid="$(id -u "$release_owner")" || return 1
  sidecar_uid="$expected_key_uid"
  sidecar_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$state_snapshot" \
    "$metadata_path" \
    "$state_snapshot_sha256" \
    "$state_database" \
    "$state_transaction_id" \
    "$state_release_name" \
    "$state_release_sha" \
    "$state_artifact_digest" \
    "$verifier_key_path" \
    "$expected_key_uid" \
    "$sidecar_uid" \
    "$sidecar_gid" <<'NODE' || return 1
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const [
  snapshotPath,
  metadataPath,
  expectedSnapshotSha256,
  databasePath,
  transactionId,
  releaseName,
  releaseSha,
  artifactDigest,
  verifierKeyPath,
  expectedKeyUid,
  sidecarUid,
  sidecarGid,
] = process.argv.slice(2);

function run(command, args, action) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `could not ${action}: ${result.error?.message ?? String(result.stderr ?? '').trim() ?? `exit ${result.status}`}`,
    );
  }
  return String(result.stdout ?? '').trimEnd();
}
function readAcl(target) {
  if (process.platform === 'linux') {
    return {
      format: 'posix-getfacl',
      entries: run(
        'getfacl',
        ['-c', '--absolute-names', '--', target],
        'read database ACLs',
      ).split('\n').map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')),
    };
  }
  if (process.platform === 'darwin') {
    return {
      format: 'darwin-ls-le',
      entries: run('/bin/ls', ['-lde', target], 'read database ACLs')
        .split('\n').slice(1).map((line) => line.trim()).filter(Boolean),
    };
  }
  throw new Error(`database ACL preservation is unsupported on ${process.platform}`);
}
function readXattrs(target) {
  if (process.platform === 'linux') {
    return {
      format: 'linux-getfattr-hex',
      entries: run(
        'getfattr',
        ['--absolute-names', '-d', '-m', '-', '-e', 'hex', '--', target],
        'read database extended attributes and security labels',
      ).split('\n').map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')).sort(),
    };
  }
  if (process.platform === 'darwin') {
    const names = run('/usr/bin/xattr', [target], 'list database extended attributes')
      .split('\n').map((name) => name.trim()).filter(Boolean).sort();
    return {
      format: 'darwin-xattr-hex',
      entries: names.map((name) => [
        name,
        run('/usr/bin/xattr', ['-px', name, target], `read database xattr ${name}`)
          .replace(/\s+/g, '').toLowerCase(),
      ]),
    };
  }
  throw new Error(
    `database extended-attribute preservation is unsupported on ${process.platform}`,
  );
}
function readMetadata(target) {
  const info = fs.lstatSync(target, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) {
    throw new Error(`rollback snapshot must be one regular file: ${target}`);
  }
  const xattrs = readXattrs(target);
  return {
    uid: String(info.uid),
    gid: String(info.gid),
    mode: Number(info.mode & 0o7777n),
    acl: readAcl(target),
    xattrs,
    securityLabels: xattrs.entries.filter((entry) => {
      const name = Array.isArray(entry) ? entry[0] : String(entry).split('=', 1)[0];
      return name.startsWith('security.');
    }),
  };
}
function hashFile(target) {
  const hash = createHash('sha256');
  const fd = fs.openSync(
    target,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}
function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}

const metadataInfo = fs.lstatSync(metadataPath, { bigint: true });
if (
  !metadataInfo.isFile() ||
  metadataInfo.isSymbolicLink() ||
  metadataInfo.nlink !== 1n ||
  String(metadataInfo.uid) !== sidecarUid ||
  String(metadataInfo.gid) !== sidecarGid ||
  Number(metadataInfo.mode & 0o777n) !== 0o600
) {
  throw new Error('database snapshot metadata sidecar is missing or unprotected');
}
const record = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
const expectedKeys = [
  'artifactDigest',
  'authenticationTag',
  'contentHash',
  'databasePath',
  'metadata',
  'recordedAt',
  'releaseName',
  'releaseSha',
  'schemaVersion',
  'snapshotPath',
  'snapshotSha256',
  'transactionId',
  'verifierKeyId',
];
if (
  !record ||
  Array.isArray(record) ||
  typeof record !== 'object' ||
  JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
) {
  throw new Error('database snapshot metadata sidecar has unexpected fields');
}
const payload = {
  schemaVersion: record.schemaVersion,
  transactionId: record.transactionId,
  releaseName: record.releaseName,
  releaseSha: record.releaseSha,
  artifactDigest: record.artifactDigest,
  databasePath: record.databasePath,
  snapshotPath: record.snapshotPath,
  snapshotSha256: record.snapshotSha256,
  metadata: record.metadata,
  verifierKeyId: record.verifierKeyId,
  recordedAt: record.recordedAt,
};
const computedHash = createHash('sha256')
  .update(`installer-db-snapshot-metadata-v1\0${JSON.stringify(payload)}`)
  .digest('hex');
const verifierKey = readVerifierKey();
const verifierKeyId = createHash('sha256').update(verifierKey).digest('hex');
const expectedTag = createHmac('sha256', verifierKey)
  .update(`installer-db-snapshot-metadata-auth-v1\0${JSON.stringify({
    ...payload,
    contentHash: record.contentHash,
  })}`)
  .digest('hex');
if (
  record.schemaVersion !== 1 ||
  record.transactionId !== transactionId ||
  record.releaseName !== releaseName ||
  record.releaseSha !== releaseSha ||
  record.artifactDigest !== artifactDigest ||
  record.databasePath !== databasePath ||
  record.snapshotPath !== snapshotPath ||
  record.snapshotSha256 !== expectedSnapshotSha256 ||
  record.verifierKeyId !== verifierKeyId ||
  typeof record.recordedAt !== 'string' ||
  !Number.isFinite(Date.parse(record.recordedAt)) ||
  record.contentHash !== computedHash ||
  typeof record.authenticationTag !== 'string' ||
  !/^[0-9a-f]{64}$/.test(record.authenticationTag) ||
  !timingSafeEqual(
    Buffer.from(record.authenticationTag, 'hex'),
    Buffer.from(expectedTag, 'hex'),
  )
) {
  throw new Error('database snapshot metadata sidecar is invalid');
}
if (hashFile(snapshotPath) !== expectedSnapshotSha256) {
  throw new Error(`pre-promotion rollback snapshot digest changed: ${snapshotPath}`);
}
if (JSON.stringify(readMetadata(snapshotPath)) !== JSON.stringify(record.metadata)) {
  throw new Error(
    'database snapshot owner, group, mode, ACLs, xattrs, or security labels changed',
  );
}
NODE
}

restore_database_snapshot() {
  local pending_database pending_snapshot pending_snapshot_sha256
  local pending_transaction_id pending_release_name pending_release_sha
  local pending_artifact_digest metadata_path expected_key_uid sidecar_uid sidecar_gid
  validate_pending_state_hash || return 1
  pending_database="$(read_pending database_path)" || return 1
  pending_snapshot="$(read_pending db_snapshot_path)" || return 1
  pending_snapshot_sha256="$(read_pending db_snapshot_sha256)" || return 1
  pending_transaction_id="$(read_pending transaction_id)" || return 1
  pending_release_name="$(read_pending release_name)" || return 1
  pending_release_sha="$(read_pending github_sha)" || return 1
  pending_artifact_digest="$(read_pending artifact_digest)" || return 1
  [ "$pending_database" = "$database_path" ] || {
    echo "pending database path does not match current deployment database: $pending_database" >&2
    return 1
  }
  [ "$pending_snapshot" = "$db_snapshot_path" ] || {
    echo "pending snapshot path does not match rollback identity: $pending_snapshot" >&2
    return 1
  }
  metadata_path="$pending_snapshot.metadata.json"
  expected_key_uid="$(id -u "$release_owner")" || return 1
  sidecar_uid="$expected_key_uid"
  sidecar_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$pending_database" \
    "$pending_snapshot" \
    "$pending_snapshot_sha256" \
    "$metadata_path" \
    "$pending_transaction_id" \
    "$pending_release_name" \
    "$pending_release_sha" \
    "$pending_artifact_digest" \
    "$verifier_key_path" \
    "$expected_key_uid" \
    "$sidecar_uid" \
    "$sidecar_gid" \
    "$cp_bin" <<'NODE' || return 1
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const [
  destinationPath,
  snapshotPath,
  expectedSnapshotSha256,
  metadataPath,
  transactionId,
  releaseName,
  releaseSha,
  artifactDigest,
  verifierKeyPath,
  expectedKeyUid,
  sidecarUid,
  sidecarGid,
  cpBin,
] = process.argv.slice(2);

function run(command, args, action) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `could not ${action}: ${result.error?.message ?? String(result.stderr ?? '').trim() ?? `exit ${result.status}`}`,
    );
  }
  return String(result.stdout ?? '').trimEnd();
}
function readAcl(target) {
  if (process.platform === 'linux') {
    return {
      format: 'posix-getfacl',
      entries: run(
        'getfacl',
        ['-c', '--absolute-names', '--', target],
        'read database ACLs',
      ).split('\n').map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')),
    };
  }
  if (process.platform === 'darwin') {
    return {
      format: 'darwin-ls-le',
      entries: run('/bin/ls', ['-lde', target], 'read database ACLs')
        .split('\n').slice(1).map((line) => line.trim()).filter(Boolean),
    };
  }
  throw new Error(`database ACL preservation is unsupported on ${process.platform}`);
}
function readXattrs(target) {
  if (process.platform === 'linux') {
    return {
      format: 'linux-getfattr-hex',
      entries: run(
        'getfattr',
        ['--absolute-names', '-d', '-m', '-', '-e', 'hex', '--', target],
        'read database extended attributes and security labels',
      ).split('\n').map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')).sort(),
    };
  }
  if (process.platform === 'darwin') {
    const names = run('/usr/bin/xattr', [target], 'list database extended attributes')
      .split('\n').map((name) => name.trim()).filter(Boolean).sort();
    return {
      format: 'darwin-xattr-hex',
      entries: names.map((name) => [
        name,
        run('/usr/bin/xattr', ['-px', name, target], `read database xattr ${name}`)
          .replace(/\s+/g, '').toLowerCase(),
      ]),
    };
  }
  throw new Error(
    `database extended-attribute preservation is unsupported on ${process.platform}`,
  );
}
function readMetadata(target) {
  const info = fs.lstatSync(target, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) {
    throw new Error(`rollback snapshot must be one regular file: ${target}`);
  }
  const xattrs = readXattrs(target);
  return {
    uid: String(info.uid),
    gid: String(info.gid),
    mode: Number(info.mode & 0o7777n),
    acl: readAcl(target),
    xattrs,
    securityLabels: xattrs.entries.filter((entry) => {
      const name = Array.isArray(entry) ? entry[0] : String(entry).split('=', 1)[0];
      return name.startsWith('security.');
    }),
  };
}
function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}
function validateMetadataCommitment() {
  const metadataInfo = fs.lstatSync(metadataPath, { bigint: true });
  if (
    !metadataInfo.isFile() ||
    metadataInfo.isSymbolicLink() ||
    metadataInfo.nlink !== 1n ||
    String(metadataInfo.uid) !== sidecarUid ||
    String(metadataInfo.gid) !== sidecarGid ||
    Number(metadataInfo.mode & 0o777n) !== 0o600
  ) {
    throw new Error('database snapshot metadata sidecar is missing or unprotected');
  }
  const record = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  const expectedKeys = [
    'artifactDigest',
    'authenticationTag',
    'contentHash',
    'databasePath',
    'metadata',
    'recordedAt',
    'releaseName',
    'releaseSha',
    'schemaVersion',
    'snapshotPath',
    'snapshotSha256',
    'transactionId',
    'verifierKeyId',
  ];
  if (
    !record ||
    Array.isArray(record) ||
    typeof record !== 'object' ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error('database snapshot metadata sidecar has unexpected fields');
  }
  const payload = {
    schemaVersion: record.schemaVersion,
    transactionId: record.transactionId,
    releaseName: record.releaseName,
    releaseSha: record.releaseSha,
    artifactDigest: record.artifactDigest,
    databasePath: record.databasePath,
    snapshotPath: record.snapshotPath,
    snapshotSha256: record.snapshotSha256,
    metadata: record.metadata,
    verifierKeyId: record.verifierKeyId,
    recordedAt: record.recordedAt,
  };
  const computedHash = createHash('sha256')
    .update(`installer-db-snapshot-metadata-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
  const key = readVerifierKey();
  const keyId = createHash('sha256').update(key).digest('hex');
  const expectedTag = createHmac('sha256', key)
    .update(`installer-db-snapshot-metadata-auth-v1\0${JSON.stringify({
      ...payload,
      contentHash: record.contentHash,
    })}`)
    .digest('hex');
  if (
    record.schemaVersion !== 1 ||
    record.transactionId !== transactionId ||
    record.releaseName !== releaseName ||
    record.releaseSha !== releaseSha ||
    record.artifactDigest !== artifactDigest ||
    record.databasePath !== destinationPath ||
    record.snapshotPath !== snapshotPath ||
    record.snapshotSha256 !== expectedSnapshotSha256 ||
    record.verifierKeyId !== keyId ||
    typeof record.recordedAt !== 'string' ||
    !Number.isFinite(Date.parse(record.recordedAt)) ||
    record.contentHash !== computedHash ||
    typeof record.authenticationTag !== 'string' ||
    !/^[0-9a-f]{64}$/.test(record.authenticationTag) ||
    !timingSafeEqual(
      Buffer.from(record.authenticationTag, 'hex'),
      Buffer.from(expectedTag, 'hex'),
    )
  ) {
    throw new Error('database snapshot metadata sidecar is invalid');
  }
  return record.metadata;
}
function hashRegularFile(target, expectedIdentity = null) {
  const flags =
    fs.constants.O_RDONLY |
    (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(target, flags);
  try {
    const info = fs.fstatSync(fd, { bigint: true });
    if (!info.isFile() || info.nlink !== 1n) {
      throw new Error(`rollback snapshot must be one regular file: ${target}`);
    }
    if (
      expectedIdentity &&
      (
        info.dev !== expectedIdentity.dev ||
        info.ino !== expectedIdentity.ino ||
        info.nlink !== expectedIdentity.nlink
      )
    ) {
      throw new Error(
        'rollback snapshot changed path or inode while restore candidate was built',
      );
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
    return { digest: hash.digest('hex'), info };
  } finally {
    fs.closeSync(fd);
  }
}
function cloneWithMetadata(source, destination) {
  fs.rmSync(destination, { force: true });
  if (process.platform === 'linux') {
    run(
      cpBin,
      ['--preserve=all', '--', source, destination],
      'clone rollback database metadata with GNU cp',
    );
    return;
  }
  if (process.platform === 'darwin') {
    run(cpBin, ['-p', source, destination], 'clone rollback database metadata');
    return;
  }
  throw new Error(`metadata-preserving copy is unsupported on ${process.platform}`);
}
function restoreOwnerGroupAndMode(target, metadata) {
  let info = fs.statSync(target, { bigint: true });
  if (String(info.uid) !== metadata.uid || String(info.gid) !== metadata.gid) {
    fs.chownSync(target, Number(metadata.uid), Number(metadata.gid));
    info = fs.statSync(target, { bigint: true });
  }
  if (Number(info.mode & 0o7777n) !== metadata.mode) {
    fs.chmodSync(target, metadata.mode);
  }
}

function quickCheck(target, label) {
  const database = new DatabaseSync(target, {
    readOnly: true,
    timeout: 30_000,
  });
  try {
    const result = database.prepare('PRAGMA quick_check').get();
    if (!result || result.quick_check !== 'ok') {
      throw new Error(`${label} quick_check failed: ${JSON.stringify(result)}`);
    }
  } finally {
    database.close();
  }
}

const expectedMetadata = validateMetadataCommitment();
const initial = hashRegularFile(snapshotPath);
if (initial.digest !== expectedSnapshotSha256) {
  throw new Error(`rollback snapshot digest changed before clone: ${snapshotPath}`);
}
if (JSON.stringify(readMetadata(snapshotPath)) !== JSON.stringify(expectedMetadata)) {
  throw new Error(
    'rollback snapshot owner, group, mode, ACLs, xattrs, or security labels changed before clone',
  );
}
quickCheck(snapshotPath, 'rollback snapshot');

const directory = path.dirname(destinationPath);
const temporaryPath = path.join(
  directory,
  `.${path.basename(destinationPath)}.rollback-${process.pid}-${Date.now()}`,
);
let renamed = false;
try {
  cloneWithMetadata(snapshotPath, temporaryPath);
  restoreOwnerGroupAndMode(temporaryPath, expectedMetadata);

  if (
    process.env.RADAR_TEST_MUTATE_ROLLBACK_SNAPSHOT_AFTER_CLONE === '1'
  ) {
    if (
      process.env.RADAR_INSTALL_TEST_MODE !== '1' ||
      !/^[0-9a-f]{64}$/.test(process.env.RADAR_INSTALL_TEST_NONCE ?? '')
    ) {
      throw new Error(
        'refusing rollback snapshot mutation outside explicit installer test mode',
      );
    }
    fs.appendFileSync(snapshotPath, 'test-only rollback snapshot mutation');
  }

  const clone = hashRegularFile(temporaryPath);
  if (clone.digest !== expectedSnapshotSha256) {
    throw new Error('rollback restore candidate differs from the pending snapshot digest');
  }
  if (JSON.stringify(readMetadata(temporaryPath)) !== JSON.stringify(expectedMetadata)) {
    throw new Error(
      'rollback restore candidate did not preserve owner, group, mode, ACLs, xattrs, and security labels',
    );
  }
  quickCheck(temporaryPath, 'rollback restore candidate');

  const retained = hashRegularFile(snapshotPath, initial.info);
  if (retained.digest !== expectedSnapshotSha256) {
    throw new Error(
      'rollback snapshot changed while restore candidate was built',
    );
  }
  if (JSON.stringify(readMetadata(snapshotPath)) !== JSON.stringify(expectedMetadata)) {
    throw new Error(
      'rollback snapshot metadata changed while the restore candidate was built',
    );
  }
  quickCheck(snapshotPath, 'retained rollback snapshot');

  const fd = fs.openSync(temporaryPath, 'r+');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.rmSync(`${destinationPath}-wal`, { force: true });
  fs.rmSync(`${destinationPath}-shm`, { force: true });
  fs.rmSync(`${destinationPath}-journal`, { force: true });
  fs.renameSync(temporaryPath, destinationPath);
  renamed = true;
  if (JSON.stringify(readMetadata(destinationPath)) !== JSON.stringify(expectedMetadata)) {
    throw new Error(
      'restored database did not preserve owner, group, mode, ACLs, xattrs, and security labels',
    );
  }
  const directoryFd = fs.openSync(directory, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
} finally {
  if (!renamed) fs.rmSync(temporaryPath, { force: true });
}
NODE
  echo "pre-migration database snapshot restored" >&2 || return 1
}

read_state_field() {
  local state_root="$1"
  local field="$2"
  local contents read_status
  [ -d "$state_root" ] && [ ! -L "$state_root" ] || {
    echo "deployment state root is not a regular directory: $state_root" >&2
    return 1
  }
  [ -f "$state_root/$field" ] && [ ! -L "$state_root/$field" ] || {
    echo "deployment state is missing regular field $field: $state_root" >&2
    return 1
  }
  # Bash read returns success only when the requested NUL delimiter is present.
  if IFS= read -r -d '' contents < "$state_root/$field"; then
    echo "deployment field $field contains a NUL byte" >&2
    return 1
  else
    read_status=$?
  fi
  [ "$read_status" -eq 1 ] || {
    echo "deployment field $field could not be read" >&2
    return 1
  }
  if [[ "$contents" == *$'\n' ]]; then
    contents="${contents%$'\n'}"
  fi
  [[ "$contents" != *$'\n'* ]] || {
    echo "deployment field $field is not exactly one line" >&2
    return 1
  }
  printf '%s' "$contents"
}

read_pending() {
  read_state_field "$pending_dir" "$1"
}

state_matches_expected_at() {
  local state_root="$1"
  local state_release_name state_release_sha state_artifact_digest
  [ -d "$state_root" ] && [ ! -L "$state_root" ] || {
    echo "deployment state root is not a regular directory: $state_root" >&2
    return 2
  }
  validate_pending_state_hash_at "$state_root" || return 2
  state_release_name="$(read_state_field "$state_root" release_name)" || return 2
  state_release_sha="$(read_state_field "$state_root" github_sha)" || return 2
  state_artifact_digest="$(read_state_field "$state_root" artifact_digest)" ||
    return 2
  if [ "$state_release_name" = "$release_name" ] &&
    [ "$state_release_sha" = "$expected_sha" ] &&
    [ "$state_artifact_digest" = "$expected_digest" ]; then
    return 0
  fi
  return 1
}

pending_matches_expected() {
  state_matches_expected_at "$pending_dir"
}

pending_matches_requested_transaction() {
  local match_status state_transaction_id
  if pending_matches_expected; then
    :
  else
    match_status=$?
    return "$match_status"
  fi
  state_transaction_id="$(read_pending transaction_id)" || return 2
  [ "$state_transaction_id" = "$transaction_id" ] && return 0
  return 1
}

pending_matches_exact_transaction() {
  local match_status state_pending_hash
  validate_pending_state_hash_value "$pending_state_hash" || return 2
  if pending_matches_requested_transaction; then
    :
  else
    match_status=$?
    return "$match_status"
  fi
  state_pending_hash="$(read_pending pending_state_hash)" || return 2
  [ "$state_pending_hash" = "$pending_state_hash" ] && return 0
  return 1
}

compute_pending_state_hash() {
  "$node_bin" - \
    "$pending_state_hash_domain" \
    "$pending_state_schema_version" \
    "$promotion_required" \
    "$transaction_id" \
    "$pending_deadline_epoch" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$release_dir" \
    "$release_created" \
    "$1" \
    "$2" \
    "$tarball" \
    "$tarball_sha256" \
    "$tarball_size_bytes" \
    "$runtime_env_path" \
    "$runtime_env_created" \
    "$database_path" \
    "$db_snapshot_path" \
    "$db_snapshot_sha256" \
    "$quality_database_path" \
    "$required_score_receipt_id" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const [hashDomain, ...values] = process.argv.slice(2);
process.stdout.write(
  createHash('sha256')
    .update(`${hashDomain}\0${JSON.stringify(values)}`)
    .digest('hex'),
);
NODE
}

validate_pending_state_hash_at() {
  local state_root="$1"
  local recorded computed state_schema
  recorded="$(read_state_field "$state_root" pending_state_hash)" || return 1
  computed="$("$node_bin" - \
    "$state_root" \
    "$pending_state_hash_domain" \
    "$pending_state_schema_version" <<'NODE'
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [root, hashDomain, schemaVersion] = process.argv.slice(2);
const fields = [
  'pending_schema_version',
  'promotion_required',
  'transaction_id',
  'deadline_epoch',
  'release_name',
  'github_sha',
  'artifact_digest',
  'release_dir',
  'release_created',
  'previous_current_present',
  'previous_current_target',
  'tarball',
  'tarball_sha256',
  'tarball_size_bytes',
  'runtime_env_path',
  'runtime_env_created',
  'database_path',
  'db_snapshot_path',
  'db_snapshot_sha256',
  'quality_database_path',
  'required_score_receipt_id',
];
const values = fields.map((field) => {
  const fieldPath = path.join(root, field);
  const info = fs.lstatSync(fieldPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`pending field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(fieldPath, 'utf8');
  if (contents.includes('\0')) throw new Error(`pending field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`pending field ${field} is not exactly one line`);
  return lines[0];
});
if (values[0] !== schemaVersion) {
  throw new Error(
    `pending schema ${values[0]} does not match expected schema ${schemaVersion}`,
  );
}
process.stdout.write(
  createHash('sha256')
    .update(`${hashDomain}\0${JSON.stringify(values)}`)
    .digest('hex'),
);
NODE
)" || return 1
  [ "$recorded" = "$computed" ] || {
    echo "pending deployment identity hash mismatch" >&2
    return 1
  }
  state_schema="$(read_state_field "$state_root" pending_schema_version)" ||
    return 1
  [ "$state_schema" = "$pending_state_schema_version" ] || {
    echo "pending deployment has an unsupported schema" >&2
    return 1
  }
  local state_transaction_id state_tarball state_tarball_sha256 state_tarball_size_bytes
  state_transaction_id="$(read_state_field "$state_root" transaction_id)" ||
    return 1
  state_tarball="$(read_state_field "$state_root" tarball)" || return 1
  state_tarball_sha256="$(read_state_field "$state_root" tarball_sha256)" ||
    return 1
  state_tarball_size_bytes="$(
    read_state_field "$state_root" tarball_size_bytes
  )" || return 1
  validate_transaction_tarball_path_value \
    "$state_tarball" \
    "$state_transaction_id" \
    "pending deployment" || return 1
  [[ "$state_tarball_sha256" =~ ^[0-9a-f]{64}$ ]] &&
    [[ "$state_tarball_size_bytes" =~ ^[1-9][0-9]*$ ]] || {
    echo "pending deployment tarball digest identity is invalid" >&2
    return 1
  }
}

validate_pending_state_hash() {
  local state_tarball state_tarball_sha256 state_tarball_size_bytes state_transaction_id
  validate_pending_state_hash_at "$pending_dir" || return 1
  state_tarball="$(read_pending tarball)" || return 1
  state_tarball_sha256="$(read_pending tarball_sha256)" || return 1
  state_tarball_size_bytes="$(read_pending tarball_size_bytes)" || return 1
  state_transaction_id="$(read_pending transaction_id)" || return 1
  [ -e "$state_tarball" ] || [ -L "$state_tarball" ] || {
    echo "pending deployment is missing its transaction-owned release artifact" >&2
    return 1
  }
  validate_owned_tarball_file \
    "$state_tarball" \
    "$state_tarball_sha256" \
    "$state_tarball_size_bytes" \
    "$state_transaction_id" \
    "pending deployment" || return 1
  validate_database_snapshot_metadata_at "$pending_dir"
}

load_pending_transaction() {
  promotion_required="$(read_pending promotion_required)" || return 1
  case "$promotion_required" in
    0|1) ;;
    *)
      echo "pending deployment has invalid promotion_required value" >&2
      return 1
      ;;
  esac
  transaction_id="$(read_pending transaction_id)" || return 1
  pending_state_hash="$(read_pending pending_state_hash)" || return 1
  pending_deadline_epoch="$(read_pending deadline_epoch)" || return 1
  [[ "$transaction_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    echo "pending deployment has an invalid transaction ID" >&2
    return 1
  }
  [[ "$pending_state_hash" =~ ^[0-9a-f]{64}$ ]] || {
    echo "pending deployment has an invalid state hash" >&2
    return 1
  }
  [[ "$pending_deadline_epoch" =~ ^[1-9][0-9]*$ ]] || {
    echo "pending deployment has an invalid deadline" >&2
    return 1
  }
  db_snapshot_sha256="$(read_pending db_snapshot_sha256)" || return 1
  tarball="$(read_pending tarball)" || return 1
  tarball_sha256="$(read_pending tarball_sha256)" || return 1
  tarball_size_bytes="$(read_pending tarball_size_bytes)" || return 1
  quality_database_path="$(read_pending quality_database_path)" || return 1
  required_score_receipt_id="$(read_pending required_score_receipt_id)" ||
    return 1
}

compute_activation_intent_hash() {
  "$node_bin" - "$@" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const values = process.argv.slice(2);
process.stdout.write(
  createHash('sha256')
    .update(`installer-activation-intent-v2\0${JSON.stringify(values)}`)
    .digest('hex'),
);
NODE
}

write_activation_intent() {
  local previous_present="$1"
  local previous_target="$2"
  local release_preexisting="$3"
  local runtime_env_preexisting="$4"
  local intent_tmp started_at intent_hash
  validate_transaction_id "$transaction_id" || return 1
  [ -n "$intent_dir" ] || {
    echo "activation intent path is unavailable" >&2
    return 1
  }
  [ ! -e "$intent_dir" ] && [ ! -L "$intent_dir" ] || {
    echo "deployment activation intent already exists: $intent_dir" >&2
    return 1
  }
  [ ! -e "$staging_dir" ] && [ ! -L "$staging_dir" ] || {
    echo "transaction staging path already exists: $staging_dir" >&2
    return 1
  }
  [ ! -e "$db_snapshot_dir" ] && [ ! -L "$db_snapshot_dir" ] || {
    echo "transaction snapshot path already exists: $db_snapshot_dir" >&2
    return 1
  }
  started_at="$("$node_bin" -e 'process.stdout.write(new Date().toISOString())')" ||
    return 1
  intent_hash="$(
    compute_activation_intent_hash \
      "2" \
      "$transaction_id" \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$upload_tarball" \
      "$tarball" \
      "$tarball_sha256" \
      "$tarball_size_bytes" \
      "$release_dir" \
      "$release_preexisting" \
      "$runtime_env_path" \
      "$runtime_env_preexisting" \
      "$staging_dir" \
      "$database_path" \
      "$db_snapshot_dir" \
      "$db_snapshot_path" \
      "$promotion_required" \
      "$quality_database_path" \
      "$required_score_receipt_id" \
      "$previous_present" \
      "$previous_target" \
      "$started_at"
  )" || return 1
  intent_tmp="$(mktemp -d "$base/.deploy-intent.tmp.XXXXXX")" || return 1
  printf '%s\n' "2" > "$intent_tmp/intent_schema_version" || return 1
  printf '%s\n' "$transaction_id" > "$intent_tmp/transaction_id" || return 1
  printf '%s\n' "$release_name" > "$intent_tmp/release_name" || return 1
  printf '%s\n' "$expected_sha" > "$intent_tmp/github_sha" || return 1
  printf '%s\n' "$expected_digest" > "$intent_tmp/artifact_digest" || return 1
  printf '%s\n' "$upload_tarball" > "$intent_tmp/upload_tarball" || return 1
  printf '%s\n' "$tarball" > "$intent_tmp/tarball" || return 1
  printf '%s\n' "$tarball_sha256" > "$intent_tmp/tarball_sha256" || return 1
  printf '%s\n' "$tarball_size_bytes" > "$intent_tmp/tarball_size_bytes" ||
    return 1
  printf '%s\n' "$release_dir" > "$intent_tmp/release_dir" || return 1
  printf '%s\n' "$release_preexisting" > "$intent_tmp/release_preexisting" ||
    return 1
  printf '%s\n' "$runtime_env_path" > "$intent_tmp/runtime_env_path" || return 1
  printf '%s\n' "$runtime_env_preexisting" > "$intent_tmp/runtime_env_preexisting" ||
    return 1
  printf '%s\n' "$staging_dir" > "$intent_tmp/staging_dir" || return 1
  printf '%s\n' "$database_path" > "$intent_tmp/database_path" || return 1
  printf '%s\n' "$db_snapshot_dir" > "$intent_tmp/db_snapshot_dir" || return 1
  printf '%s\n' "$db_snapshot_path" > "$intent_tmp/db_snapshot_path" || return 1
  printf '%s\n' "$promotion_required" > "$intent_tmp/promotion_required" ||
    return 1
  printf '%s\n' "$quality_database_path" > "$intent_tmp/quality_database_path" ||
    return 1
  printf '%s\n' "$required_score_receipt_id" \
    > "$intent_tmp/required_score_receipt_id" || return 1
  printf '%s\n' "$previous_present" > "$intent_tmp/previous_current_present" ||
    return 1
  printf '%s\n' "$previous_target" > "$intent_tmp/previous_current_target" ||
    return 1
  printf '%s\n' "$started_at" > "$intent_tmp/started_at" || return 1
  printf '%s\n' "$intent_hash" > "$intent_tmp/intent_hash" || return 1
  chmod 700 "$intent_tmp" || return 1
  chmod 600 "$intent_tmp"/* || return 1
  "$node_bin" - "$intent_tmp" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
for (const entry of fs.readdirSync(root)) {
  const target = path.join(root, entry);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`activation intent entry is not a regular file: ${target}`);
  }
  const fd = fs.openSync(target, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
const directoryFd = fs.openSync(root, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
NODE
  mv "$intent_tmp" "$intent_dir" || return 1
  fsync_directory "$base" || return 1
  activation_intent_created=1
}

validate_activation_intent_at() {
  local state_root="$1"
  "$node_bin" - "$state_root" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
const fields = [
  'intent_schema_version',
  'transaction_id',
  'release_name',
  'github_sha',
  'artifact_digest',
  'upload_tarball',
  'tarball',
  'tarball_sha256',
  'tarball_size_bytes',
  'release_dir',
  'release_preexisting',
  'runtime_env_path',
  'runtime_env_preexisting',
  'staging_dir',
  'database_path',
  'db_snapshot_dir',
  'db_snapshot_path',
  'promotion_required',
  'quality_database_path',
  'required_score_receipt_id',
  'previous_current_present',
  'previous_current_target',
  'started_at',
];
const expectedEntries = [...fields, 'intent_hash'].sort();
const actualEntries = fs.readdirSync(root).sort();
if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
  throw new Error('activation intent contains unexpected entries');
}
function readField(field) {
  const target = path.join(root, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`activation intent field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(target, 'utf8');
  if (contents.includes('\0')) throw new Error(`activation intent field ${field} contains NUL`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`activation intent field ${field} is not one line`);
  return lines[0];
}
const values = fields.map(readField);
const recorded = readField('intent_hash');
const computed = createHash('sha256')
  .update(`installer-activation-intent-v2\0${JSON.stringify(values)}`)
  .digest('hex');
if (recorded !== computed) throw new Error('activation intent hash mismatch');
NODE
}

remove_matching_activation_intent_at() {
  local state_root="$1"
  local state_transaction_id state_release_name state_release_sha
  local state_artifact_digest candidate field
  local intent_value state_value intent_staging intent_snapshot_dir
  local intent_release_preexisting state_release_created
  local intent_runtime_env_preexisting state_runtime_env_created

  [ "$deploy_lock_held" -eq 1 ] || {
    echo "terminal activation-intent cleanup requires the deployment lock" >&2
    return 1
  }
  validate_pending_state_hash_at "$state_root" || return 1
  state_transaction_id="$(read_state_field "$state_root" transaction_id)" ||
    return 1
  state_release_name="$(read_state_field "$state_root" release_name)" || return 1
  state_release_sha="$(read_state_field "$state_root" github_sha)" || return 1
  state_artifact_digest="$(read_state_field "$state_root" artifact_digest)" ||
    return 1
  validate_transaction_id "$state_transaction_id" || return 1
  validate_release_identity_values \
    "$state_release_name" \
    "$state_release_sha" \
    "$state_artifact_digest" || return 1
  candidate="$base/.deploy-intent-$state_transaction_id"
  if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
    return 0
  fi
  [ -d "$candidate" ] && [ ! -L "$candidate" ] || {
    echo "terminal activation intent is not a regular directory: $candidate" >&2
    return 1
  }
  validate_activation_intent_at "$candidate" || return 1
  for field in \
    transaction_id \
    release_name \
    github_sha \
    artifact_digest \
    tarball \
    tarball_sha256 \
    tarball_size_bytes \
    release_dir \
    runtime_env_path \
    database_path \
    db_snapshot_path \
    promotion_required \
    quality_database_path \
    required_score_receipt_id \
    previous_current_present \
    previous_current_target; do
    intent_value="$(read_state_field "$candidate" "$field")" || return 1
    state_value="$(read_state_field "$state_root" "$field")" || return 1
    [ "$intent_value" = "$state_value" ] || {
      echo "terminal activation intent field $field contradicts its completion state" >&2
      return 1
    }
  done
  intent_staging="$(read_state_field "$candidate" staging_dir)" || return 1
  [ "$intent_staging" = "$releases/.${state_release_name}.staging-${state_transaction_id}" ] || {
    echo "terminal activation intent staging path is outside its transaction" >&2
    return 1
  }
  intent_snapshot_dir="$(read_state_field "$candidate" db_snapshot_dir)" ||
    return 1
  [ "$intent_snapshot_dir" = "$backup_root/${state_release_name}-${state_transaction_id}" ] || {
    echo "terminal activation intent snapshot path is outside its transaction" >&2
    return 1
  }
  intent_release_preexisting="$(
    read_state_field "$candidate" release_preexisting
  )" || return 1
  state_release_created="$(read_state_field "$state_root" release_created)" ||
    return 1
  case "$intent_release_preexisting:$state_release_created" in
    0:1|1:0) ;;
    *)
      echo "terminal activation intent release ownership contradicts its completion state" >&2
      return 1
      ;;
  esac
  intent_runtime_env_preexisting="$(
    read_state_field "$candidate" runtime_env_preexisting
  )" || return 1
  state_runtime_env_created="$(
    read_state_field "$state_root" runtime_env_created
  )" || return 1
  case "$intent_runtime_env_preexisting:$state_runtime_env_created" in
    0:1|1:0) ;;
    *)
      echo "terminal activation intent runtime-env ownership contradicts its completion state" >&2
      return 1
      ;;
  esac
  rm -rf "$candidate" || return 1
  fsync_directory "$base" || return 1
  if [ "$intent_dir" = "$candidate" ]; then
    activation_intent_created=0
  fi
}

recover_activation_intent_at() {
  local state_root="$1"
  local state_transaction_id state_release_name state_release_sha state_artifact_digest
  local state_upload_tarball state_tarball state_tarball_sha256 state_tarball_size_bytes
  local state_release_dir release_preexisting state_runtime_env
  local runtime_env_preexisting state_staging state_database state_snapshot_dir
  local state_snapshot_path state_promotion_required state_quality_database
  local state_receipt previous_present previous_target current_target expected_root
  local cleanup_dir previous_revision current_present=0 current_status
  local intent_schema pending_transaction_id pending_release_name pending_release_sha
  local pending_artifact_digest pending_tarball pending_tarball_sha256
  local pending_tarball_size_bytes
  local terminal_candidate terminal_outcome terminal_transaction_id
  local terminal_release_name terminal_release_sha terminal_artifact_digest
  local expected_terminal_candidate terminal_state_root= terminal_match_count=0

  validate_activation_intent_at "$state_root" || return 1
  intent_schema="$(read_state_field "$state_root" intent_schema_version)" ||
    return 1
  [ "$intent_schema" = "2" ] || {
    echo "activation intent has unsupported schema" >&2
    return 1
  }
  state_transaction_id="$(read_state_field "$state_root" transaction_id)" || return 1
  state_release_name="$(read_state_field "$state_root" release_name)" || return 1
  state_release_sha="$(read_state_field "$state_root" github_sha)" || return 1
  state_artifact_digest="$(read_state_field "$state_root" artifact_digest)" ||
    return 1
  validate_transaction_id "$state_transaction_id" || return 1
  validate_release_identity_values \
    "$state_release_name" \
    "$state_release_sha" \
    "$state_artifact_digest" || return 1
  expected_root="$base/.deploy-intent-$state_transaction_id"
  [ "$state_root" = "$expected_root" ] || {
    echo "activation intent path does not match its transaction ID" >&2
    return 1
  }

  state_upload_tarball="$(read_state_field "$state_root" upload_tarball)" ||
    return 1
  state_tarball="$(read_state_field "$state_root" tarball)" || return 1
  state_tarball_sha256="$(read_state_field "$state_root" tarball_sha256)" ||
    return 1
  state_tarball_size_bytes="$(
    read_state_field "$state_root" tarball_size_bytes
  )" || return 1
  state_release_dir="$(read_state_field "$state_root" release_dir)" || return 1
  release_preexisting="$(read_state_field "$state_root" release_preexisting)" ||
    return 1
  state_runtime_env="$(read_state_field "$state_root" runtime_env_path)" ||
    return 1
  runtime_env_preexisting="$(
    read_state_field "$state_root" runtime_env_preexisting
  )" || return 1
  state_staging="$(read_state_field "$state_root" staging_dir)" || return 1
  state_database="$(read_state_field "$state_root" database_path)" || return 1
  state_snapshot_dir="$(read_state_field "$state_root" db_snapshot_dir)" ||
    return 1
  state_snapshot_path="$(read_state_field "$state_root" db_snapshot_path)" ||
    return 1
  state_promotion_required="$(
    read_state_field "$state_root" promotion_required
  )" || return 1
  state_quality_database="$(
    read_state_field "$state_root" quality_database_path
  )" || return 1
  state_receipt="$(read_state_field "$state_root" required_score_receipt_id)" ||
    return 1
  previous_present="$(
    read_state_field "$state_root" previous_current_present
  )" || return 1
  previous_target="$(
    read_state_field "$state_root" previous_current_target
  )" || return 1

  case "$release_preexisting:$runtime_env_preexisting:$state_promotion_required:$previous_present" in
    [01]:[01]:[01]:[01]) ;;
    *)
      echo "activation intent contains invalid boolean state" >&2
      return 1
      ;;
  esac
  [ "$state_release_dir" = "$releases/$state_release_name" ] || {
    echo "activation intent release path is outside its release identity" >&2
    return 1
  }
  [ "$state_runtime_env" = "$runtime_env_dir/$state_release_name.env" ] || {
    echo "activation intent runtime env path is outside its release identity" >&2
    return 1
  }
  [ "$state_staging" = "$releases/.${state_release_name}.staging-${state_transaction_id}" ] || {
    echo "activation intent staging path is outside its transaction identity" >&2
    return 1
  }
  [ "$state_snapshot_dir" = "$backup_root/${state_release_name}-${state_transaction_id}" ] &&
    [ "$state_snapshot_path" = "$state_snapshot_dir/pre-migration.sqlite" ] || {
    echo "activation intent snapshot path is outside its transaction identity" >&2
    return 1
  }
  [ "$state_database" = "$database_path" ] || {
    echo "activation intent database path does not match production configuration" >&2
    return 1
  }
  [[ "$state_upload_tarball" == /* ]] &&
    [ "$state_upload_tarball" != "$state_tarball" ] || {
    echo "activation intent upload path is invalid" >&2
    return 1
  }
  validate_transaction_tarball_path_value \
    "$state_tarball" \
    "$state_transaction_id" \
    "activation intent" || return 1
  [[ "$state_tarball_sha256" =~ ^[0-9a-f]{64}$ ]] &&
    [[ "$state_tarball_size_bytes" =~ ^[1-9][0-9]*$ ]] || {
    echo "activation intent tarball digest identity is invalid" >&2
    return 1
  }
  if [ "$state_promotion_required" = "1" ]; then
    [[ "$state_quality_database" == /* ]] &&
      [[ "$state_receipt" =~ ^[0-9a-f]{64}$ ]] || {
      echo "activation intent promotion identity is invalid" >&2
      return 1
    }
  else
    [ -z "$state_quality_database" ] && [ -z "$state_receipt" ] || {
      echo "code-only activation intent unexpectedly binds promotion inputs" >&2
      return 1
    }
  fi
  if [ "$previous_present" = "1" ]; then
    case "$previous_target" in
      "$releases"/*) ;;
      *)
        echo "activation intent previous release is outside releases" >&2
        return 1
        ;;
    esac
  else
    [ -z "$previous_target" ] || {
      echo "activation intent has a previous target without a previous release" >&2
      return 1
    }
  fi

  if [ -e "$pending_dir" ] || [ -L "$pending_dir" ]; then
    [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
      echo "pending deployment path is not a regular directory: $pending_dir" >&2
      return 1
    }
    validate_pending_state_hash_at "$pending_dir" || return 1
    pending_transaction_id="$(read_state_field "$pending_dir" transaction_id)" ||
      return 1
    pending_release_name="$(read_state_field "$pending_dir" release_name)" ||
      return 1
    pending_release_sha="$(read_state_field "$pending_dir" github_sha)" || return 1
    pending_artifact_digest="$(
      read_state_field "$pending_dir" artifact_digest
    )" || return 1
    pending_tarball="$(read_state_field "$pending_dir" tarball)" || return 1
    pending_tarball_sha256="$(
      read_state_field "$pending_dir" tarball_sha256
    )" || return 1
    pending_tarball_size_bytes="$(
      read_state_field "$pending_dir" tarball_size_bytes
    )" || return 1
    [ "$pending_transaction_id" = "$state_transaction_id" ] &&
      [ "$pending_release_name" = "$state_release_name" ] &&
      [ "$pending_release_sha" = "$state_release_sha" ] &&
      [ "$pending_artifact_digest" = "$state_artifact_digest" ] &&
      [ "$pending_tarball" = "$state_tarball" ] &&
      [ "$pending_tarball_sha256" = "$state_tarball_sha256" ] &&
      [ "$pending_tarball_size_bytes" = "$state_tarball_size_bytes" ] || {
      echo "activation intent contradicts the active pending deployment" >&2
      return 1
    }
    validate_owned_tarball_file \
      "$state_tarball" \
      "$state_tarball_sha256" \
      "$state_tarball_size_bytes" \
      "$state_transaction_id" \
      "activation intent" || return 1
    return 0
  fi

  for terminal_candidate in \
    "$completion_root"/* \
    "$base"/.pending-deploy.finalized-*; do
    if [ ! -e "$terminal_candidate" ] && [ ! -L "$terminal_candidate" ]; then
      continue
    fi
    [ -d "$terminal_candidate" ] && [ ! -L "$terminal_candidate" ] || {
      echo "terminal deployment registry entry is not a regular directory: $terminal_candidate" >&2
      return 1
    }
    terminal_outcome="$(validate_finalization_record_at "$terminal_candidate")" ||
      return 1
    terminal_transaction_id="$(
      read_state_field "$terminal_candidate" transaction_id
    )" || return 1
    terminal_release_name="$(
      read_state_field "$terminal_candidate" release_name
    )" || return 1
    terminal_release_sha="$(
      read_state_field "$terminal_candidate" github_sha
    )" || return 1
    terminal_artifact_digest="$(
      read_state_field "$terminal_candidate" artifact_digest
    )" || return 1
    validate_transaction_id "$terminal_transaction_id" || return 1
    validate_release_identity_values \
      "$terminal_release_name" \
      "$terminal_release_sha" \
      "$terminal_artifact_digest" || return 1
    case "$terminal_candidate" in
      "$completion_root"/*)
        expected_terminal_candidate="$completion_root/${terminal_outcome}-${terminal_release_name}-${terminal_transaction_id}"
        ;;
      "$base"/.pending-deploy.finalized-*)
        expected_terminal_candidate="$base/.pending-deploy.finalized-${terminal_outcome}-${terminal_release_name}-${terminal_transaction_id}"
        ;;
      *)
        echo "terminal deployment registry path is outside its registry" >&2
        return 1
        ;;
    esac
    [ "$terminal_candidate" = "$expected_terminal_candidate" ] || {
      echo "terminal deployment registry entry name does not match its identity" >&2
      return 1
    }
    if [ "$terminal_transaction_id" = "$state_transaction_id" ]; then
      terminal_match_count=$((terminal_match_count + 1))
      [ "$terminal_match_count" -le 1 ] || {
        echo "activation intent transaction has multiple terminal deployment records" >&2
        return 1
      }
      terminal_state_root="$terminal_candidate"
    fi
  done
  if [ "$terminal_match_count" -eq 1 ]; then
    remove_matching_activation_intent_at "$terminal_state_root" || return 1
    return 0
  fi

  if current_target="$(read_current_target)"; then
    current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) current_target= ;;
      *) return 1 ;;
    esac
  fi
  if [ "$current_target" = "$state_release_dir" ]; then
    [ "$current_present" -eq 1 ] &&
      [ "$previous_present" = "1" ] &&
      [ "$previous_target" = "$state_release_dir" ] &&
      [ "$release_preexisting" = "1" ] &&
      [ -d "$state_release_dir" ] &&
      [ ! -L "$state_release_dir" ] || {
      echo "pre-pending activation intent has an ambiguous same-name release identity" >&2
      return 1
    }
  fi
  if [ "$previous_present" = "1" ]; then
    [ "$current_present" -eq 1 ] && [ "$current_target" = "$previous_target" ] || {
      echo "pre-pending activation intent previous release changed" >&2
      return 1
    }
  elif [ "$current_present" -eq 1 ]; then
    echo "pre-pending first activation unexpectedly has a current release" >&2
    return 1
  fi

  for cleanup_dir in "$state_staging" "$state_snapshot_dir"; do
    if [ -e "$cleanup_dir" ] || [ -L "$cleanup_dir" ]; then
      [ -d "$cleanup_dir" ] && [ ! -L "$cleanup_dir" ] || {
        echo "activation intent cleanup path is not a regular directory: $cleanup_dir" >&2
        return 1
      }
      rm -rf "$cleanup_dir" || return 1
    fi
  done
  if [ "$release_preexisting" = "0" ] &&
    { [ -e "$state_release_dir" ] || [ -L "$state_release_dir" ]; }; then
    [ -d "$state_release_dir" ] && [ ! -L "$state_release_dir" ] || {
      echo "activation intent release cleanup path is not a regular directory" >&2
      return 1
    }
    rm -rf "$state_release_dir" || return 1
  fi
  if [ "$runtime_env_preexisting" = "0" ] &&
    { [ -e "$state_runtime_env" ] || [ -L "$state_runtime_env" ]; }; then
    [ -f "$state_runtime_env" ] && [ ! -L "$state_runtime_env" ] || {
      echo "activation intent runtime env cleanup path is not a regular file" >&2
      return 1
    }
    rm -f "$state_runtime_env" || return 1
  fi
  if [ -e "$state_tarball" ] || [ -L "$state_tarball" ]; then
    validate_owned_tarball_file \
      "$state_tarball" \
      "$state_tarball_sha256" \
      "$state_tarball_size_bytes" \
      "$state_transaction_id" \
      "activation intent" || return 1
    rm -f "$state_tarball" || return 1
  fi
  fsync_directory "$releases" || return 1
  fsync_directory "$runtime_env_dir" || return 1
  fsync_directory "$backup_root" || return 1
  fsync_directory "$artifact_root" || return 1

  if [ "$state_promotion_required" = "1" ] &&
    [ "$previous_present" = "1" ]; then
    if [ "$reconcile_boot_mode" -eq 1 ]; then
      deferred_state_dir="$state_root"
      return 2
    fi
    if ! restart_service_outside_deploy_lock; then
      echo "failed to restart the previous service during intent recovery" >&2
      return 1
    fi
    previous_revision="$(manifest_runtime_revision "$previous_target")" || return 1
    if ! wait_until_ready 1 "$previous_target" "$previous_revision" 0; then
      echo "previous release did not regain readiness during intent recovery" >&2
      return 1
    fi
  fi
  rm -rf "$state_root" || return 1
  fsync_directory "$base" || return 1
}

recover_activation_intents() {
  local candidate count=0 recovery_status
  deferred_state_dir=
  for candidate in "$base"/.deploy-intent-*; do
    if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
      continue
    fi
    [ -d "$candidate" ] && [ ! -L "$candidate" ] || {
      echo "activation intent is not a regular directory: $candidate" >&2
      return 1
    }
    count=$((count + 1))
    [ "$count" -le 1 ] || {
      echo "multiple activation intents require operator review" >&2
      return 1
    }
    if recover_activation_intent_at "$candidate"; then
      :
    else
      recovery_status=$?
      [ "$recovery_status" -eq 2 ] && {
        activation_intent_created=1
        return 2
      }
      return 1
    fi
  done
  activation_intent_created=0
}

write_pending_state() {
  local previous_present="$1"
  local previous_target="$2"
  local pending_tmp
  [ ! -e "$pending_dir" ] || {
    echo "another deployment is pending commit or rollback: $pending_dir" >&2
    return 1
  }
  validate_transaction_id "$transaction_id" || return 1
  pending_deadline_epoch="$(
    "$node_bin" -e '
      const timeout = Number(process.argv[1]);
      if (!Number.isSafeInteger(timeout) || timeout <= 0) process.exit(1);
      process.stdout.write(String(Math.floor(Date.now() / 1000) + timeout));
    ' "$pending_timeout_seconds"
  )" || return 1
  pending_state_hash="$(
    compute_pending_state_hash "$previous_present" "$previous_target"
  )" || return 1
  pending_tmp="$(mktemp -d "$base/.pending-deploy.XXXXXX")" || return 1
  printf '%s\n' "$pending_state_schema_version" > "$pending_tmp/pending_schema_version" ||
    return 1
  printf '%s\n' "$promotion_required" > "$pending_tmp/promotion_required" ||
    return 1
  printf '%s\n' "$transaction_id" > "$pending_tmp/transaction_id" || return 1
  printf '%s\n' "$pending_deadline_epoch" > "$pending_tmp/deadline_epoch" ||
    return 1
  printf '%s\n' "$release_name" > "$pending_tmp/release_name" || return 1
  printf '%s\n' "$expected_sha" > "$pending_tmp/github_sha" || return 1
  printf '%s\n' "$expected_digest" > "$pending_tmp/artifact_digest" || return 1
  printf '%s\n' "$release_dir" > "$pending_tmp/release_dir" || return 1
  printf '%s\n' "$release_created" > "$pending_tmp/release_created" || return 1
  printf '%s\n' "$previous_present" > "$pending_tmp/previous_current_present" ||
    return 1
  printf '%s\n' "$previous_target" > "$pending_tmp/previous_current_target" ||
    return 1
  printf '%s\n' "$tarball" > "$pending_tmp/tarball" || return 1
  printf '%s\n' "$tarball_sha256" > "$pending_tmp/tarball_sha256" || return 1
  printf '%s\n' "$tarball_size_bytes" > "$pending_tmp/tarball_size_bytes" ||
    return 1
  printf '%s\n' "$runtime_env_path" > "$pending_tmp/runtime_env_path" ||
    return 1
  printf '%s\n' "$runtime_env_created" > "$pending_tmp/runtime_env_created" ||
    return 1
  printf '%s\n' "$database_path" > "$pending_tmp/database_path" || return 1
  printf '%s\n' "$db_snapshot_path" > "$pending_tmp/db_snapshot_path" || return 1
  printf '%s\n' "$db_snapshot_sha256" > "$pending_tmp/db_snapshot_sha256" ||
    return 1
  printf '%s\n' "$quality_database_path" > "$pending_tmp/quality_database_path" ||
    return 1
  printf '%s\n' "$required_score_receipt_id" \
    > "$pending_tmp/required_score_receipt_id" || return 1
  printf '%s\n' "$pending_state_hash" > "$pending_tmp/pending_state_hash" ||
    return 1
  snapshot_previous_startup_authorization \
    "$pending_tmp" \
    "$previous_present" \
    "$previous_target" || return 1
  chown "$release_owner:$runtime_group" "$pending_tmp" || return 1
  chmod 710 "$pending_tmp" || return 1
  chmod 600 "$pending_tmp"/* || return 1
  "$node_bin" - "$pending_tmp" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
for (const entry of fs.readdirSync(root)) {
  const target = path.join(root, entry);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`pending state entry is not a regular file: ${target}`);
  }
  const fd = fs.openSync(target, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
const directoryFd = fs.openSync(root, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
NODE
  append_phase_transition_at "$pending_tmp" prepared >/dev/null || return 1
  mv "$pending_tmp" "$pending_dir" || return 1
  activation_pending_created=1
  fsync_directory "$base" || return 1
}

write_pending_field() {
  local field="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp "$pending_dir/.${field}.XXXXXX")" || return 1
  printf '%s\n' "$value" > "$tmp" || return 1
  chmod 600 "$tmp" || return 1
  fsync_file "$tmp" || return 1
  mv "$tmp" "$pending_dir/$field" || return 1
  "$node_bin" - "$pending_dir" <<'NODE' || return 1
const fs = require('node:fs');
const fd = fs.openSync(process.argv[2], 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
NODE
}

snapshot_previous_startup_authorization() {
  local state_root="$1"
  local previous_present="$2"
  local previous_target="$3"
  local expected_owner_uid expected_runtime_gid
  [ "$promotion_required" -eq 1 ] || return 0
  if [ ! -e "$startup_authorization_path" ] &&
    [ ! -L "$startup_authorization_path" ]; then
    return 0
  fi
  [ "$previous_present" = "1" ] || {
    echo "startup authorization exists without a previous current release" >&2
    return 1
  }
  expected_owner_uid="$(id -u "$release_owner")" || return 1
  expected_runtime_gid="$(resolve_group_id "$runtime_group")" || return 1
  "$node_bin" - \
    "$startup_authorization_path" \
    "$state_root/previous-startup-authorization.json" \
    "$previous_target" \
    "$database_path" \
    "$expected_owner_uid" \
    "$expected_runtime_gid" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const [
  sourcePath,
  snapshotPath,
  previousTarget,
  databasePath,
  expectedOwnerUidText,
  expectedRuntimeGidText,
] = process.argv.slice(2);
const expectedOwnerUid = Number(expectedOwnerUidText);
const expectedRuntimeGid = Number(expectedRuntimeGidText);

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  throw new Error('startup authorization contains unsupported JSON');
}

function hashFile(target) {
  const pathInfo = fs.lstatSync(target, { bigint: true });
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== 1n) {
    throw new Error('startup authorization database is not one regular file');
  }
  const fd = fs.openSync(
    target,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (
      opened.dev !== pathInfo.dev ||
      opened.ino !== pathInfo.ino ||
      opened.nlink !== 1n ||
      opened.size !== pathInfo.size
    ) {
      throw new Error('startup authorization database changed while opening');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
      offset += bytes;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const finalPath = fs.lstatSync(target, { bigint: true });
    if (
      BigInt(offset) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error('startup authorization database changed while hashing');
    }
    return {
      device: String(opened.dev),
      inode: String(opened.ino),
      physicalSha256: hash.digest('hex'),
    };
  } finally {
    fs.closeSync(fd);
  }
}

const info = fs.lstatSync(sourcePath, { bigint: true });
const mode = Number(info.mode & 0o777n);
if (
  !info.isFile() ||
  info.isSymbolicLink() ||
  info.nlink !== 1n ||
  Number(info.uid) !== expectedOwnerUid ||
  Number(info.gid) !== expectedRuntimeGid ||
  mode !== 0o640
) {
  throw new Error('previous startup authorization is not installer-owned');
}
const contents = fs.readFileSync(sourcePath);
const record = JSON.parse(contents.toString('utf8'));
const { contentHash, ...payload } = record;
const computed = createHash('sha256')
  .update(`installer-startup-authorization-v1\0${canonicalJson(payload)}`)
  .digest('hex');
const database = hashFile(databasePath);
if (
  record.schemaVersion !== 1 ||
  record.lifecycle !== 'committed-completion' ||
  record.release?.realPath !== fs.realpathSync(previousTarget) ||
  record.database?.realPath !== fs.realpathSync(databasePath) ||
  record.database?.device !== database.device ||
  record.database?.inode !== database.inode ||
  record.database?.physicalSha256 !== database.physicalSha256 ||
  !/^[0-9a-f]{64}$/.test(String(contentHash ?? '')) ||
  contentHash !== computed
) {
  throw new Error('previous startup authorization is invalid');
}
fs.writeFileSync(snapshotPath, contents, { mode: 0o600, flag: 'wx' });
const writtenSnapshot = fs.statSync(snapshotPath);
if (
  writtenSnapshot.uid !== expectedOwnerUid ||
  writtenSnapshot.gid !== expectedRuntimeGid
) {
  fs.chownSync(snapshotPath, expectedOwnerUid, expectedRuntimeGid);
}
fs.chmodSync(snapshotPath, 0o600);
const snapshotFd = fs.openSync(snapshotPath, 'r');
try {
  fs.fsyncSync(snapshotFd);
} finally {
  fs.closeSync(snapshotFd);
}
NODE
}

write_startup_authorization_at() {
  local state_root="$1"
  local lifecycle="$2"
  local lifecycle_proof="${3:-}"
  local state_promotion_required expected_owner_uid expected_runtime_gid
  state_promotion_required="$(
    read_state_field "$state_root" promotion_required
  )" || return 1
  [ "$state_promotion_required" = "1" ] || return 0
  expected_owner_uid="$(id -u "$release_owner")" || return 1
  expected_runtime_gid="$(resolve_group_id "$runtime_group")" || return 1
  "$node_bin" - \
    "$startup_authorization_dir" \
    "$startup_authorization_path" \
    "$state_root" \
    "$lifecycle" \
    "$lifecycle_proof" \
    "$database_path" \
    "$expected_owner_uid" \
    "$expected_runtime_gid" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  authorizationDirectory,
  authorizationPath,
  stateRoot,
  lifecycle,
  lifecycleProof,
  databasePath,
  expectedOwnerUidText,
  expectedRuntimeGidText,
] = process.argv.slice(2);
const expectedOwnerUid = Number(expectedOwnerUidText);
const expectedRuntimeGid = Number(expectedRuntimeGidText);

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  throw new Error('startup authorization contains unsupported JSON');
}

function readField(field) {
  const target = path.join(stateRoot, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`startup authorization state field ${field} is not regular`);
  }
  const contents = fs.readFileSync(target, 'utf8');
  if (contents.includes('\0')) {
    throw new Error(`startup authorization state field ${field} contains NUL`);
  }
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) {
    throw new Error(`startup authorization state field ${field} is not one line`);
  }
  return lines[0];
}

function hashFile(target) {
  const pathInfo = fs.lstatSync(target, { bigint: true });
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== 1n) {
    throw new Error('installed database is not one regular non-symlink file');
  }
  const fd = fs.openSync(
    target,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (
      opened.dev !== pathInfo.dev ||
      opened.ino !== pathInfo.ino ||
      opened.nlink !== 1n ||
      opened.size !== pathInfo.size
    ) {
      throw new Error('installed database changed while opening');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
      offset += bytes;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const finalPath = fs.lstatSync(target, { bigint: true });
    if (
      BigInt(offset) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error('installed database changed while hashing');
    }
    return {
      realPath: fs.realpathSync(target),
      device: String(opened.dev),
      inode: String(opened.ino),
      physicalSha256: hash.digest('hex'),
    };
  } finally {
    fs.closeSync(fd);
  }
}

const bindingPath = path.join(stateRoot, 'promotion-binding.json');
const bindingInfo = fs.lstatSync(bindingPath);
if (!bindingInfo.isFile() || bindingInfo.isSymbolicLink()) {
  throw new Error('startup authorization promotion binding is not regular');
}
const binding = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
const { contentHash: bindingContentHash, ...bindingPayload } = binding;
const computedBindingHash = createHash('sha256')
  .update(`installer-promotion-binding-v1\0${JSON.stringify(bindingPayload)}`)
  .digest('hex');
const database = hashFile(databasePath);
if (
  binding.schemaVersion !== 1 ||
  binding.pendingStateHash !== readField('pending_state_hash') ||
  binding.transactionId !== readField('transaction_id') ||
  binding.releaseName !== readField('release_name') ||
  binding.releaseSha !== readField('github_sha') ||
  binding.artifactDigest !== readField('artifact_digest') ||
  binding.requiredScoreReceiptId !== readField('required_score_receipt_id') ||
  binding.promotedDatabase?.realPath !== database.realPath ||
  binding.promotedDatabase?.device !== database.device ||
  binding.promotedDatabase?.inode !== database.inode ||
  binding.promotedDatabase?.physicalSha256 !== database.physicalSha256 ||
  !/^[0-9a-f]{64}$/.test(String(binding.promotedDatabase?.logicalContentDigest ?? '')) ||
  !/^[0-9a-f]{64}$/.test(String(binding.promotedDatabase?.schemaDigest ?? '')) ||
  !/^[0-9a-f]{64}$/.test(String(binding.reportSha256 ?? '')) ||
  !/^[0-9a-f]{64}$/.test(String(binding.promotionId ?? '')) ||
  !/^[0-9a-f]{64}$/.test(String(binding.promotionContentHash ?? '')) ||
  !/^[0-9a-f]{64}$/.test(
    String(binding.promotionAuthorizationContentHash ?? ''),
  ) ||
  !/^[0-9a-f]{64}$/.test(String(bindingContentHash ?? '')) ||
  bindingContentHash !== computedBindingHash
) {
  throw new Error('startup authorization promotion binding is invalid');
}

const transactionId = readField('transaction_id');
const releaseName = readField('release_name');
const releasePath = fs.realpathSync(readField('release_dir'));
let state;
if (lifecycle === 'pending-activation') {
  if (!/^[0-9a-f]{64}$/.test(lifecycleProof)) {
    throw new Error('pending startup authorization phase proof is invalid');
  }
  state = {
    kind: 'pending-activation',
    path: stateRoot,
    phase: 'activated',
    phaseTransitionHash: lifecycleProof,
  };
} else if (lifecycle === 'committed-completion') {
  const finalizationPath = path.join(stateRoot, 'finalization.json');
  const finalizationInfo = fs.lstatSync(finalizationPath);
  if (!finalizationInfo.isFile() || finalizationInfo.isSymbolicLink()) {
    throw new Error('committed startup authorization finalization is not regular');
  }
  const finalization = JSON.parse(fs.readFileSync(finalizationPath, 'utf8'));
  const finalizationPayload = {
    schemaVersion: finalization.schemaVersion,
    outcome: finalization.outcome,
    pendingStateHash: finalization.pendingStateHash,
    transactionId: finalization.transactionId,
    releaseName: finalization.releaseName,
    releaseSha: finalization.releaseSha,
    artifactDigest: finalization.artifactDigest,
  };
  const finalizationHash = createHash('sha256')
    .update(`installer-finalization-v1\0${JSON.stringify(finalizationPayload)}`)
    .digest('hex');
  if (
    lifecycleProof ||
    finalization.schemaVersion !== 1 ||
    finalization.outcome !== 'committed' ||
    finalization.pendingStateHash !== readField('pending_state_hash') ||
    finalization.transactionId !== transactionId ||
    finalization.releaseName !== releaseName ||
    finalization.releaseSha !== readField('github_sha') ||
    finalization.artifactDigest !== readField('artifact_digest') ||
    finalization.contentHash !== finalizationHash
  ) {
    throw new Error('committed startup authorization finalization is invalid');
  }
  state = {
    kind: 'committed-completion',
    path: stateRoot,
    outcome: 'committed',
    finalizationContentHash: finalization.contentHash,
  };
} else {
  throw new Error(`unsupported startup authorization lifecycle: ${lifecycle}`);
}

const payload = {
  schemaVersion: 1,
  lifecycle,
  release: {
    name: releaseName,
    sha: readField('github_sha'),
    artifactDigest: readField('artifact_digest'),
    realPath: releasePath,
  },
  database: {
    realPath: database.realPath,
    device: database.device,
    inode: database.inode,
    logicalContentDigest: binding.promotedDatabase.logicalContentDigest,
    schemaDigest: binding.promotedDatabase.schemaDigest,
    physicalSha256: database.physicalSha256,
  },
  scoreReceipt: {
    receiptId: readField('required_score_receipt_id'),
  },
  promotionReceipt: {
    promotionId: binding.promotionId,
    contentHash: binding.promotionContentHash,
  },
  promotionBinding: {
    contentHash: binding.contentHash,
    promotionAuthorizationContentHash:
      binding.promotionAuthorizationContentHash,
    reportSha256: binding.reportSha256,
  },
  transaction: {
    transactionId,
    pendingStateHash: readField('pending_state_hash'),
  },
  state,
  recordedAt: new Date().toISOString(),
};
const record = {
  ...payload,
  contentHash: createHash('sha256')
    .update(`installer-startup-authorization-v1\0${canonicalJson(payload)}`)
    .digest('hex'),
};
const directoryInfo = fs.lstatSync(authorizationDirectory);
if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
  throw new Error('startup authorization directory is not regular');
}
const temporaryPath =
  `${authorizationPath}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
  mode: 0o640,
  flag: 'wx',
});
const temporaryInfo = fs.statSync(temporaryPath);
if (
  temporaryInfo.uid !== expectedOwnerUid ||
  temporaryInfo.gid !== expectedRuntimeGid
) {
  fs.chownSync(temporaryPath, expectedOwnerUid, expectedRuntimeGid);
}
fs.chmodSync(temporaryPath, 0o640);
const fd = fs.openSync(temporaryPath, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(temporaryPath, authorizationPath);
const directoryFd = fs.openSync(authorizationDirectory, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
NODE
}

write_pending_startup_authorization() {
  local phase_tip phase_name phase_hash
  phase_tip="$(authorization_phase_transition_at "$pending_dir")" || return 1
  phase_name="${phase_tip%% *}"
  phase_hash="${phase_tip#* }"
  case "$phase_name" in
    activated|verified) ;;
    *)
    echo "pending startup authorization requires the activated phase" >&2
    return 1
      ;;
  esac
  write_startup_authorization_at \
    "$pending_dir" \
    pending-activation \
    "$phase_hash"
}

write_committed_startup_authorization_at() {
  local state_root="$1"
  write_startup_authorization_at \
    "$state_root" \
    committed-completion
}

restore_previous_startup_authorization_at() {
  local state_root="$1"
  local state_promotion_required expected_owner_uid expected_runtime_gid
  state_promotion_required="$(
    read_state_field "$state_root" promotion_required
  )" || return 1
  [ "$state_promotion_required" = "1" ] || return 0
  expected_owner_uid="$(id -u "$release_owner")" || return 1
  expected_runtime_gid="$(resolve_group_id "$runtime_group")" || return 1
  "$node_bin" - \
    "$state_root" \
    "$startup_authorization_dir" \
    "$startup_authorization_path" \
    "$database_path" \
    "$expected_owner_uid" \
    "$expected_runtime_gid" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  stateRoot,
  authorizationDirectory,
  authorizationPath,
  databasePath,
  expectedOwnerUidText,
  expectedRuntimeGidText,
] = process.argv.slice(2);
const expectedOwnerUid = Number(expectedOwnerUidText);
const expectedRuntimeGid = Number(expectedRuntimeGidText);

function readField(field) {
  const contents = fs.readFileSync(path.join(stateRoot, field), 'utf8');
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (contents.includes('\0') || lines.length !== 1) {
    throw new Error(`rollback startup authorization field ${field} is invalid`);
  }
  return lines[0];
}

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  throw new Error('startup authorization contains unsupported JSON');
}

function hashFile(target) {
  const info = fs.lstatSync(target, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) {
    throw new Error('rollback database is not one regular file');
  }
  const fd = fs.openSync(
    target,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
      offset += bytes;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const finalPath = fs.lstatSync(target, { bigint: true });
    if (
      opened.dev !== info.dev ||
      opened.ino !== info.ino ||
      opened.nlink !== 1n ||
      BigInt(offset) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error('rollback database changed while hashing');
    }
    return {
      realPath: fs.realpathSync(target),
      device: String(opened.dev),
      inode: String(opened.ino),
      physicalSha256: hash.digest('hex'),
    };
  } finally {
    fs.closeSync(fd);
  }
}

function removeActive() {
  if (!fs.existsSync(authorizationPath)) return;
  const info = fs.lstatSync(authorizationPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('rollback startup authorization path is unsafe');
  }
  fs.unlinkSync(authorizationPath);
  const directoryFd = fs.openSync(authorizationDirectory, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
}

const previousPresent = readField('previous_current_present');
const previousTarget = readField('previous_current_target');
const snapshotPath = path.join(
  stateRoot,
  'previous-startup-authorization.json',
);
if (previousPresent === '0') {
  if (previousTarget || fs.existsSync(snapshotPath)) {
    throw new Error('first-release rollback startup authorization is invalid');
  }
  removeActive();
  process.exit(0);
}
if (previousPresent !== '1') {
  throw new Error('rollback startup authorization previous-current flag is invalid');
}
if (!fs.existsSync(snapshotPath)) {
  removeActive();
  process.exit(0);
}

const snapshotInfo = fs.lstatSync(snapshotPath, { bigint: true });
if (
  !snapshotInfo.isFile() ||
  snapshotInfo.isSymbolicLink() ||
  snapshotInfo.nlink !== 1n ||
  Number(snapshotInfo.uid) !== expectedOwnerUid
) {
  throw new Error('rollback startup authorization snapshot is not protected');
}
const contents = fs.readFileSync(snapshotPath);
const record = JSON.parse(contents.toString('utf8'));
const { contentHash, ...payload } = record;
const computed = createHash('sha256')
  .update(`installer-startup-authorization-v1\0${canonicalJson(payload)}`)
  .digest('hex');
const database = hashFile(databasePath);
if (
  record.schemaVersion !== 1 ||
  record.lifecycle !== 'committed-completion' ||
  record.release?.realPath !== fs.realpathSync(previousTarget) ||
  record.database?.realPath !== database.realPath ||
  record.database?.physicalSha256 !== database.physicalSha256 ||
  !/^[0-9a-f]{64}$/.test(String(contentHash ?? '')) ||
  contentHash !== computed
) {
  throw new Error('rollback startup authorization snapshot is invalid');
}
const restoredPayload = {
  ...payload,
  database: {
    ...record.database,
    realPath: database.realPath,
    device: database.device,
    inode: database.inode,
    physicalSha256: database.physicalSha256,
  },
  recordedAt: new Date().toISOString(),
};
const restoredRecord = {
  ...restoredPayload,
  contentHash: createHash('sha256')
    .update(
      `installer-startup-authorization-v1\0${canonicalJson(restoredPayload)}`,
    )
    .digest('hex'),
};
const temporaryPath =
  `${authorizationPath}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(
  temporaryPath,
  `${JSON.stringify(restoredRecord, null, 2)}\n`,
  { mode: 0o640, flag: 'wx' },
);
const temporaryInfo = fs.statSync(temporaryPath);
if (
  temporaryInfo.uid !== expectedOwnerUid ||
  temporaryInfo.gid !== expectedRuntimeGid
) {
  fs.chownSync(temporaryPath, expectedOwnerUid, expectedRuntimeGid);
}
fs.chmodSync(temporaryPath, 0o640);
const fd = fs.openSync(temporaryPath, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(temporaryPath, authorizationPath);
const directoryFd = fs.openSync(authorizationDirectory, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
NODE
}

phase_transition_at() {
  local state_root="$1"
  local mode="$2"
  local requested_phase="${3:-}"
  "$node_bin" - "$state_root" "$mode" "$requested_phase" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [root, mode, requestedPhase] = process.argv.slice(2);
if (!['current', 'append', 'authorization'].includes(mode)) {
  throw new Error(`invalid phase transition mode: ${mode}`);
}
const allowedPhases = new Set(['prepared', 'promoted', 'activated', 'verified']);
if (mode === 'append' && !allowedPhases.has(requestedPhase)) {
  throw new Error(`invalid deployment phase: ${requestedPhase}`);
}
function readField(field) {
  const target = path.join(root, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const value = fs.readFileSync(target, 'utf8').replace(/\n$/, '');
  if (value.includes('\0') || value.includes('\n') || value.includes('\r')) {
    throw new Error(`deployment field ${field} is not one safe line`);
  }
  return value;
}
const transactionId = readField('transaction_id');
const pendingStateHash = readField('pending_state_hash');
const entries = fs.readdirSync(root)
  .filter((entry) => /^phase-transition-[0-9]{4}\.json$/.test(entry))
  .sort();
let previousHash = '';
let previousPhase = '';
let currentRecordPreviousHash = '';
for (let index = 0; index < entries.length; index += 1) {
  const expectedName = `phase-transition-${String(index + 1).padStart(4, '0')}.json`;
  if (entries[index] !== expectedName) {
    throw new Error('deployment phase transitions are not contiguous');
  }
  const target = path.join(root, entries[index]);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('deployment phase transition is not a regular file');
  }
  const record = JSON.parse(fs.readFileSync(target, 'utf8'));
  const expectedKeys = [
    'contentHash',
    'pendingStateHash',
    'phase',
    'previousHash',
    'recordedAt',
    'schemaVersion',
    'sequence',
    'transactionId',
  ];
  if (
    !record ||
    Array.isArray(record) ||
    typeof record !== 'object' ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error('deployment phase transition has unexpected fields');
  }
  const payload = {
    schemaVersion: record.schemaVersion,
    sequence: record.sequence,
    phase: record.phase,
    transactionId: record.transactionId,
    pendingStateHash: record.pendingStateHash,
    previousHash: record.previousHash,
    recordedAt: record.recordedAt,
  };
  const computed = createHash('sha256')
    .update(`installer-phase-transition-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
  const allowedNext = previousPhase === ''
    ? new Set(['prepared'])
    : previousPhase === 'prepared'
      ? new Set(['promoted', 'activated'])
      : previousPhase === 'promoted'
        ? new Set(['activated'])
        : previousPhase === 'activated'
          ? new Set(['verified'])
          : new Set();
  if (
    record.schemaVersion !== 1 ||
    record.sequence !== index + 1 ||
    !allowedPhases.has(record.phase) ||
    !allowedNext.has(record.phase) ||
    record.transactionId !== transactionId ||
    record.pendingStateHash !== pendingStateHash ||
    record.previousHash !== previousHash ||
    typeof record.recordedAt !== 'string' ||
    !Number.isFinite(Date.parse(record.recordedAt)) ||
    record.contentHash !== computed
  ) {
    throw new Error('deployment phase transition chain is invalid');
  }
  previousHash = record.contentHash;
  previousPhase = record.phase;
  currentRecordPreviousHash = record.previousHash;
}
if (mode === 'authorization') {
  if (previousPhase === 'activated') {
    process.stdout.write(`${previousPhase} ${previousHash}`);
    process.exit(0);
  }
  if (
    previousPhase === 'verified' &&
    /^[0-9a-f]{64}$/.test(currentRecordPreviousHash)
  ) {
    process.stdout.write(`${previousPhase} ${currentRecordPreviousHash}`);
    process.exit(0);
  }
  throw new Error(`deployment authorization cannot bind phase ${previousPhase || '<none>'}`);
}
if (mode === 'append') {
  if (previousPhase === requestedPhase) {
    process.stdout.write(`${previousPhase} ${previousHash}`);
    process.exit(0);
  }
  const allowedNext = previousPhase === ''
    ? new Set(['prepared'])
    : previousPhase === 'prepared'
      ? new Set(['promoted', 'activated'])
      : previousPhase === 'promoted'
        ? new Set(['activated'])
        : previousPhase === 'activated'
          ? new Set(['verified'])
          : new Set();
  if (!allowedNext.has(requestedPhase)) {
    throw new Error(`invalid deployment phase transition ${previousPhase || '<none>'} -> ${requestedPhase}`);
  }
  const payload = {
    schemaVersion: 1,
    sequence: entries.length + 1,
    phase: requestedPhase,
    transactionId,
    pendingStateHash,
    previousHash,
    recordedAt: new Date().toISOString(),
  };
  const record = {
    ...payload,
    contentHash: createHash('sha256')
      .update(`installer-phase-transition-v1\0${JSON.stringify(payload)}`)
      .digest('hex'),
  };
  const target = path.join(
    root,
    `phase-transition-${String(payload.sequence).padStart(4, '0')}.json`,
  );
  const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
  const fd = fs.openSync(temporary, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temporary, target);
  const directoryFd = fs.openSync(root, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
  previousPhase = record.phase;
  previousHash = record.contentHash;
}
if (!previousPhase || !previousHash) {
  throw new Error('deployment phase transition chain is empty');
}
process.stdout.write(`${previousPhase} ${previousHash}`);
NODE
}

append_phase_transition_at() {
  phase_transition_at "$1" append "$2"
}

current_phase_transition_at() {
  phase_transition_at "$1" current
}

authorization_phase_transition_at() {
  phase_transition_at "$1" authorization
}

current_pending_phase() {
  current_phase_transition_at "$pending_dir" | awk '{print $1}'
}

write_verification_authorization() {
  local phase_tip phase_name phase_hash expected_key_uid
  validate_verification_id "$verification_id" || return 1
  validate_pending_state_hash || return 1
  phase_tip="$(authorization_phase_transition_at "$pending_dir")" || return 1
  phase_name="${phase_tip%% *}"
  phase_hash="${phase_tip#* }"
  case "$phase_name" in
    activated|verified) ;;
    *)
      echo "deployment must be fully activated before authorization" >&2
      return 1
      ;;
  esac
  expected_key_uid="$(id -u "$release_owner")" || return 1
  "$node_bin" - \
    "$pending_dir" \
    "$verification_id" \
    "$phase_hash" \
    "$verification_attestation" \
    "$verifier_key_path" \
    "$expected_key_uid" \
    "$phase_name" <<'NODE' || return 1
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  root,
  verificationId,
  phaseTransitionHash,
  verifierAttestation,
  verifierKeyPath,
  expectedKeyUid,
  currentPhase,
] = process.argv.slice(2);

function readField(field) {
  const target = path.join(root, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(target, 'utf8');
  if (contents.includes('\0')) throw new Error(`deployment field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`deployment field ${field} is not exactly one line`);
  return lines[0];
}

function promotionBindingHash() {
  if (readField('promotion_required') === '0') return '';
  const target = path.join(root, 'promotion-binding.json');
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('promotion binding is not a regular file');
  }
  const binding = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (
    !binding ||
    Array.isArray(binding) ||
    typeof binding !== 'object' ||
    typeof binding.contentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(binding.contentHash)
  ) {
    throw new Error('promotion binding has an invalid content hash');
  }
  return binding.contentHash;
}

function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}

function attestationPayload() {
  return {
    schemaVersion: 1,
    verificationId,
    transactionId: readField('transaction_id'),
    pendingStateHash: readField('pending_state_hash'),
    releaseName: readField('release_name'),
    releaseSha: readField('github_sha'),
    artifactDigest: readField('artifact_digest'),
    deadlineEpoch: Number(readField('deadline_epoch')),
    phaseTransitionHash,
  };
}

function expectedVerifierAttestation(key, payload) {
  return createHmac('sha256', key)
    .update(`installer-verifier-attestation-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
}

const verifierKey = readVerifierKey();
const expectedAttestation = expectedVerifierAttestation(
  verifierKey,
  attestationPayload(),
);
if (
  !/^[0-9a-f]{64}$/.test(verifierAttestation) ||
  !timingSafeEqual(
    Buffer.from(verifierAttestation, 'hex'),
    Buffer.from(expectedAttestation, 'hex'),
  )
) {
  throw new Error('deployment verifier attestation does not match the exact transaction');
}
const verifierKeyId = createHash('sha256').update(verifierKey).digest('hex');

function hashPayload(payload) {
  return createHash('sha256')
    .update(`installer-verification-authorization-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
}

function validateRecord(record) {
  const expectedKeys = [
    'artifactDigest',
    'authorizedAt',
    'contentHash',
    'deadlineEpoch',
    'pendingStateHash',
    'phaseTransitionHash',
    'promotionBindingHash',
    'releaseName',
    'releaseSha',
    'requiredScoreReceiptId',
    'schemaVersion',
    'transactionId',
    'verificationId',
    'verifierAttestation',
    'verifierKeyId',
  ];
  if (
    !record ||
    Array.isArray(record) ||
    typeof record !== 'object' ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error('deployment verification authorization has unexpected fields');
  }
  const payload = {
    schemaVersion: record.schemaVersion,
    transactionId: record.transactionId,
    pendingStateHash: record.pendingStateHash,
    releaseName: record.releaseName,
    releaseSha: record.releaseSha,
    artifactDigest: record.artifactDigest,
    deadlineEpoch: record.deadlineEpoch,
    requiredScoreReceiptId: record.requiredScoreReceiptId,
    promotionBindingHash: record.promotionBindingHash,
    phaseTransitionHash: record.phaseTransitionHash,
    verifierAttestation: record.verifierAttestation,
    verifierKeyId: record.verifierKeyId,
    verificationId: record.verificationId,
    authorizedAt: record.authorizedAt,
  };
  const recordAttestationPayload = {
    schemaVersion: 1,
    verificationId: record.verificationId,
    transactionId: record.transactionId,
    pendingStateHash: record.pendingStateHash,
    releaseName: record.releaseName,
    releaseSha: record.releaseSha,
    artifactDigest: record.artifactDigest,
    deadlineEpoch: record.deadlineEpoch,
    phaseTransitionHash: record.phaseTransitionHash,
  };
  const expectedRecordAttestation = expectedVerifierAttestation(
    verifierKey,
    recordAttestationPayload,
  );
  if (
    record.schemaVersion !== 1 ||
    record.transactionId !== readField('transaction_id') ||
    record.pendingStateHash !== readField('pending_state_hash') ||
    record.releaseName !== readField('release_name') ||
    record.releaseSha !== readField('github_sha') ||
    record.artifactDigest !== readField('artifact_digest') ||
    record.deadlineEpoch !== Number(readField('deadline_epoch')) ||
    record.requiredScoreReceiptId !== readField('required_score_receipt_id') ||
    record.promotionBindingHash !== promotionBindingHash() ||
    record.phaseTransitionHash !== phaseTransitionHash ||
    typeof record.verifierAttestation !== 'string' ||
    !/^[0-9a-f]{64}$/.test(record.verifierAttestation) ||
    !timingSafeEqual(
      Buffer.from(record.verifierAttestation, 'hex'),
      Buffer.from(expectedRecordAttestation, 'hex'),
    ) ||
    record.verifierKeyId !== verifierKeyId ||
    typeof record.verificationId !== 'string' ||
    !/^[1-9][0-9]*:[1-9][0-9]*$/.test(record.verificationId) ||
    typeof record.authorizedAt !== 'string' ||
    !Number.isFinite(Date.parse(record.authorizedAt)) ||
    record.contentHash !== hashPayload(payload)
  ) {
    throw new Error('deployment verification authorization is invalid');
  }
  return record;
}

const target = path.join(root, 'verification-authorization.json');
if (fs.existsSync(target)) {
  const existing = validateRecord(JSON.parse(fs.readFileSync(target, 'utf8')));
  if (existing.verificationId !== verificationId) {
    throw new Error('deployment is already authorized by a different verification run');
  }
  if (existing.verifierAttestation !== verifierAttestation) {
    throw new Error('deployment verifier attestation does not match the durable authorization');
  }
  process.stdout.write(existing.contentHash);
  process.exit(0);
}
if (currentPhase === 'verified') {
  throw new Error('verified deployment transition is missing its authorization record');
}

const deadlineEpoch = Number(readField('deadline_epoch'));
if (
  !Number.isSafeInteger(deadlineEpoch) ||
  deadlineEpoch < Math.floor(Date.now() / 1000)
) {
  throw new Error('deployment verification deadline expired before authorization became durable');
}
const payload = {
  schemaVersion: 1,
  transactionId: readField('transaction_id'),
  pendingStateHash: readField('pending_state_hash'),
  releaseName: readField('release_name'),
  releaseSha: readField('github_sha'),
  artifactDigest: readField('artifact_digest'),
  deadlineEpoch: Number(readField('deadline_epoch')),
  requiredScoreReceiptId: readField('required_score_receipt_id'),
  promotionBindingHash: promotionBindingHash(),
  phaseTransitionHash,
  verifierAttestation,
  verifierKeyId,
  verificationId,
  authorizedAt: new Date().toISOString(),
};
const record = { ...payload, contentHash: hashPayload(payload) };
const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, {
  mode: 0o600,
  flag: 'wx',
});
const fd = fs.openSync(temporary, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(temporary, target);
const directoryFd = fs.openSync(root, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
process.stdout.write(record.contentHash);
NODE
}

validate_verification_authorization_at() {
  local state_root="$1"
  local expected_verification_id="${2:-}"
  local phase_tip phase_name phase_hash expected_key_uid
  validate_pending_state_hash_at "$state_root" || return 1
  phase_tip="$(authorization_phase_transition_at "$state_root")" || return 1
  phase_name="${phase_tip%% *}"
  phase_hash="${phase_tip#* }"
  case "$phase_name" in
    activated|verified) ;;
    *)
      echo "deployment authorization references an invalid phase: $phase_name" >&2
      return 1
      ;;
  esac
  expected_key_uid="$(id -u "$release_owner")" || return 1
  "$node_bin" - \
    "$state_root" \
    "$expected_verification_id" \
    "$phase_hash" \
    "$verifier_key_path" \
    "$expected_key_uid" <<'NODE' || return 1
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  root,
  expectedVerificationId,
  phaseTransitionHash,
  verifierKeyPath,
  expectedKeyUid,
] = process.argv.slice(2);

function readField(field) {
  const target = path.join(root, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(target, 'utf8');
  if (contents.includes('\0')) throw new Error(`deployment field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`deployment field ${field} is not exactly one line`);
  return lines[0];
}

function promotionBindingHash() {
  if (readField('promotion_required') === '0') return '';
  const target = path.join(root, 'promotion-binding.json');
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('promotion binding is not a regular file');
  }
  const binding = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (
    !binding ||
    Array.isArray(binding) ||
    typeof binding !== 'object' ||
    typeof binding.contentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(binding.contentHash)
  ) {
    throw new Error('promotion binding has an invalid content hash');
  }
  return binding.contentHash;
}

function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}

const target = path.join(root, 'verification-authorization.json');
let info;
try {
  info = fs.lstatSync(target);
} catch {
  throw new Error('deployment verification authorization is not a regular file');
}
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error('deployment verification authorization is not a regular file');
}
const record = JSON.parse(fs.readFileSync(target, 'utf8'));
const expectedKeys = [
  'artifactDigest',
  'authorizedAt',
  'contentHash',
  'deadlineEpoch',
  'pendingStateHash',
  'phaseTransitionHash',
  'promotionBindingHash',
  'releaseName',
  'releaseSha',
  'requiredScoreReceiptId',
  'schemaVersion',
  'transactionId',
  'verificationId',
  'verifierAttestation',
  'verifierKeyId',
];
if (
  !record ||
  Array.isArray(record) ||
  typeof record !== 'object' ||
  JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
) {
  throw new Error('deployment verification authorization has unexpected fields');
}
const payload = {
  schemaVersion: record.schemaVersion,
  transactionId: record.transactionId,
  pendingStateHash: record.pendingStateHash,
  releaseName: record.releaseName,
  releaseSha: record.releaseSha,
  artifactDigest: record.artifactDigest,
  deadlineEpoch: record.deadlineEpoch,
  requiredScoreReceiptId: record.requiredScoreReceiptId,
  promotionBindingHash: record.promotionBindingHash,
  phaseTransitionHash: record.phaseTransitionHash,
  verifierAttestation: record.verifierAttestation,
  verifierKeyId: record.verifierKeyId,
  verificationId: record.verificationId,
  authorizedAt: record.authorizedAt,
};
const computed = createHash('sha256')
  .update(`installer-verification-authorization-v1\0${JSON.stringify(payload)}`)
  .digest('hex');
const verifierKey = readVerifierKey();
const expectedAttestationPayload = {
  schemaVersion: 1,
  verificationId: record.verificationId,
  transactionId: record.transactionId,
  pendingStateHash: record.pendingStateHash,
  releaseName: record.releaseName,
  releaseSha: record.releaseSha,
  artifactDigest: record.artifactDigest,
  deadlineEpoch: record.deadlineEpoch,
  phaseTransitionHash: record.phaseTransitionHash,
};
const expectedAttestation = createHmac('sha256', verifierKey)
  .update(
    `installer-verifier-attestation-v1\0${JSON.stringify(expectedAttestationPayload)}`,
  )
  .digest('hex');
const verifierKeyId = createHash('sha256').update(verifierKey).digest('hex');
if (
  record.schemaVersion !== 1 ||
  record.transactionId !== readField('transaction_id') ||
  record.pendingStateHash !== readField('pending_state_hash') ||
  record.releaseName !== readField('release_name') ||
  record.releaseSha !== readField('github_sha') ||
  record.artifactDigest !== readField('artifact_digest') ||
  record.deadlineEpoch !== Number(readField('deadline_epoch')) ||
  record.requiredScoreReceiptId !== readField('required_score_receipt_id') ||
  record.promotionBindingHash !== promotionBindingHash() ||
  record.phaseTransitionHash !== phaseTransitionHash ||
  typeof record.verifierAttestation !== 'string' ||
  !/^[0-9a-f]{64}$/.test(record.verifierAttestation) ||
  !timingSafeEqual(
    Buffer.from(record.verifierAttestation, 'hex'),
    Buffer.from(expectedAttestation, 'hex'),
  ) ||
  record.verifierKeyId !== verifierKeyId ||
  typeof record.verificationId !== 'string' ||
  !/^[1-9][0-9]*:[1-9][0-9]*$/.test(record.verificationId) ||
  (expectedVerificationId && record.verificationId !== expectedVerificationId) ||
  typeof record.authorizedAt !== 'string' ||
  !Number.isFinite(Date.parse(record.authorizedAt)) ||
  record.contentHash !== computed
) {
  throw new Error('deployment verification authorization is invalid');
}
process.stdout.write(record.verificationId);
NODE
}

ensure_verification_acceptance_at() {
  local state_root="$1"
  local expected_verification_id="$2"
  local verified_phase_hash expected_key_uid acceptance_uid acceptance_gid
  verified_phase_hash="$(
    current_phase_transition_at "$state_root" | awk '$1 == "verified" { print $2 }'
  )" || return 1
  [[ "$verified_phase_hash" =~ ^[0-9a-f]{64}$ ]] || {
    echo "authenticated verifier acceptance requires the exact verified phase" >&2
    return 1
  }
  expected_key_uid="$(id -u "$release_owner")" || return 1
  acceptance_uid="$expected_key_uid"
  acceptance_gid="$(resolve_group_id "$release_group")" || return 1
  "$node_bin" - \
    "$state_root" \
    "$expected_verification_id" \
    "$verified_phase_hash" \
    "$verifier_key_path" \
    "$expected_key_uid" \
    "$acceptance_uid" \
    "$acceptance_gid" <<'NODE' || return 1
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  root,
  expectedVerificationId,
  verifiedPhaseHash,
  verifierKeyPath,
  expectedKeyUid,
  acceptanceUid,
  acceptanceGid,
] = process.argv.slice(2);

function readField(field) {
  const target = path.join(root, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(target, 'utf8');
  if (contents.includes('\0')) throw new Error(`deployment field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`deployment field ${field} is not exactly one line`);
  return lines[0];
}

function readVerifierKey() {
  const info = fs.lstatSync(verifierKeyPath);
  const mode = info.mode & 0o777;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    String(info.uid) !== expectedKeyUid ||
    ![0o400, 0o600].includes(mode)
  ) {
    throw new Error('deployment verifier key must be a protected regular file');
  }
  const key = fs.readFileSync(verifierKeyPath, 'utf8').trim();
  if (Buffer.byteLength(key) < 32 || key.includes('\0') || key.includes('\n')) {
    throw new Error('deployment verifier key must contain at least 32 safe bytes');
  }
  return key;
}

const authorizationPath = path.join(root, 'verification-authorization.json');
const authorizationInfo = fs.lstatSync(authorizationPath);
if (
  !authorizationInfo.isFile() ||
  authorizationInfo.isSymbolicLink() ||
  authorizationInfo.nlink !== 1
) {
  throw new Error('deployment verification authorization is not a regular file');
}
const authorization = JSON.parse(fs.readFileSync(authorizationPath, 'utf8'));
if (
  typeof authorization.contentHash !== 'string' ||
  !/^[0-9a-f]{64}$/.test(authorization.contentHash) ||
  authorization.verificationId !== expectedVerificationId ||
  typeof authorization.phaseTransitionHash !== 'string' ||
  !/^[0-9a-f]{64}$/.test(authorization.phaseTransitionHash)
) {
  throw new Error('deployment verification authorization cannot be accepted');
}
const verifierKey = readVerifierKey();
const verifierKeyId = createHash('sha256').update(verifierKey).digest('hex');
const target = path.join(root, 'verification-acceptance.json');

function payloadFrom(record) {
  return {
    schemaVersion: record.schemaVersion,
    transactionId: record.transactionId,
    pendingStateHash: record.pendingStateHash,
    verificationId: record.verificationId,
    authorizationHash: record.authorizationHash,
    authorizedPhaseHash: record.authorizedPhaseHash,
    verifiedPhaseHash: record.verifiedPhaseHash,
    verifierKeyId: record.verifierKeyId,
    acceptedAt: record.acceptedAt,
  };
}

function validateRecord(record) {
  const expectedKeys = [
    'acceptanceTag',
    'acceptedAt',
    'authorizationHash',
    'authorizedPhaseHash',
    'contentHash',
    'pendingStateHash',
    'schemaVersion',
    'transactionId',
    'verificationId',
    'verifiedPhaseHash',
    'verifierKeyId',
  ];
  if (
    !record ||
    Array.isArray(record) ||
    typeof record !== 'object' ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error('deployment verification acceptance has unexpected fields');
  }
  const payload = payloadFrom(record);
  const contentHash = createHash('sha256')
    .update(`installer-verification-acceptance-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
  const expectedTag = createHmac('sha256', verifierKey)
    .update(`installer-verification-acceptance-auth-v1\0${JSON.stringify({
      ...payload,
      contentHash: record.contentHash,
    })}`)
    .digest('hex');
  if (
    record.schemaVersion !== 1 ||
    record.transactionId !== readField('transaction_id') ||
    record.pendingStateHash !== readField('pending_state_hash') ||
    record.verificationId !== expectedVerificationId ||
    record.authorizationHash !== authorization.contentHash ||
    record.authorizedPhaseHash !== authorization.phaseTransitionHash ||
    record.verifiedPhaseHash !== verifiedPhaseHash ||
    record.verifierKeyId !== verifierKeyId ||
    typeof record.acceptedAt !== 'string' ||
    !Number.isFinite(Date.parse(record.acceptedAt)) ||
    record.contentHash !== contentHash ||
    typeof record.acceptanceTag !== 'string' ||
    !/^[0-9a-f]{64}$/.test(record.acceptanceTag) ||
    !timingSafeEqual(
      Buffer.from(record.acceptanceTag, 'hex'),
      Buffer.from(expectedTag, 'hex'),
    )
  ) {
    throw new Error(
      'authenticated verifier acceptance does not match the durable verified phase',
    );
  }
  return record;
}

let existingInfo = null;
try {
  existingInfo = fs.lstatSync(target, { bigint: true });
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
}
if (existingInfo) {
  const info = existingInfo;
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.nlink !== 1n ||
    String(info.uid) !== acceptanceUid ||
    String(info.gid) !== acceptanceGid ||
    Number(info.mode & 0o777n) !== 0o600
  ) {
    throw new Error('deployment verification acceptance is not a protected regular file');
  }
  validateRecord(JSON.parse(fs.readFileSync(target, 'utf8')));
  process.stdout.write(expectedVerificationId);
  process.exit(0);
}

const payload = {
  schemaVersion: 1,
  transactionId: readField('transaction_id'),
  pendingStateHash: readField('pending_state_hash'),
  verificationId: expectedVerificationId,
  authorizationHash: authorization.contentHash,
  authorizedPhaseHash: authorization.phaseTransitionHash,
  verifiedPhaseHash,
  verifierKeyId,
  acceptedAt: new Date().toISOString(),
};
const contentHash = createHash('sha256')
  .update(`installer-verification-acceptance-v1\0${JSON.stringify(payload)}`)
  .digest('hex');
const acceptanceTag = createHmac('sha256', verifierKey)
  .update(`installer-verification-acceptance-auth-v1\0${JSON.stringify({
    ...payload,
    contentHash,
  })}`)
  .digest('hex');
const record = { ...payload, contentHash, acceptanceTag };
const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, {
  mode: 0o600,
  flag: 'wx',
});
let info = fs.statSync(temporary, { bigint: true });
if (String(info.uid) !== acceptanceUid || String(info.gid) !== acceptanceGid) {
  fs.chownSync(temporary, Number(acceptanceUid), Number(acceptanceGid));
}
fs.chmodSync(temporary, 0o600);
const fd = fs.openSync(temporary, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(temporary, target);
const directoryFd = fs.openSync(root, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
validateRecord(JSON.parse(fs.readFileSync(target, 'utf8')));
process.stdout.write(expectedVerificationId);
NODE
}

recover_verified_authorization_at() {
  local state_root="$1"
  local expected_verification_id="${2:-}"
  local output_variable="${3:-}"
  local resolved_verification_id current_phase acceptance_path
  resolved_verification_id="$(
    validate_verification_authorization_at "$state_root" "$expected_verification_id"
  )" || return 1
  current_phase="$(current_phase_transition_at "$state_root" | awk '{print $1}')" ||
    return 1
  acceptance_path="$state_root/verification-acceptance.json"
  if [ -e "$acceptance_path" ] || [ -L "$acceptance_path" ]; then
    [ "$current_phase" = "verified" ] || {
      echo "authenticated verifier acceptance lost its durable verified phase" >&2
      return 1
    }
  else
    case "$current_phase" in
      activated)
        append_phase_transition_at "$state_root" verified >/dev/null || return 1
        ;;
      verified) ;;
      *)
        echo "deployment authorization cannot recover phase $current_phase" >&2
        return 1
        ;;
    esac
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_AFTER_VERIFIED_PHASE \
      after-verified-phase || return 1
  fi
  current_phase="$(current_phase_transition_at "$state_root" | awk '{print $1}')" ||
    return 1
  [ "$current_phase" = "verified" ] || {
    echo "deployment verified phase transition did not become durable" >&2
    return 1
  }
  ensure_verification_acceptance_at \
    "$state_root" \
    "$resolved_verification_id" >/dev/null || return 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_AFTER_AUTHORIZATION_ACCEPTANCE \
    after-authorization-acceptance || return 1
  validate_verification_authorization_at \
    "$state_root" \
    "$resolved_verification_id" >/dev/null || return 1
  ensure_verification_acceptance_at \
    "$state_root" \
    "$resolved_verification_id" >/dev/null || return 1
  if [ -n "$output_variable" ]; then
    printf -v "$output_variable" '%s' "$resolved_verification_id" || return 1
  else
    printf '%s\n' "$resolved_verification_id" || return 1
  fi
}

fsync_directory() {
  "$node_bin" - "$1" <<'NODE' || return 1
const fs = require('node:fs');
const fd = fs.openSync(process.argv[2], 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
NODE
}

fsync_file() {
  "$node_bin" - "$1" <<'NODE' || return 1
const fs = require('node:fs');
const target = process.argv[2];
const info = fs.lstatSync(target);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error(`fsync target is not a regular file: ${target}`);
}
const fd = fs.openSync(target, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
NODE
}

fsync_tree() {
  "$node_bin" - "$1" <<'NODE' || return 1
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
function sync(target) {
  const info = fs.lstatSync(target);
  if (info.isSymbolicLink()) return;
  if (info.isDirectory()) {
    for (const entry of fs.readdirSync(target)) {
      sync(path.join(target, entry));
    }
  } else if (!info.isFile()) {
    throw new Error(`release durability target has unsupported type: ${target}`);
  }
  const fd = fs.openSync(target, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
sync(root);
NODE
}

watchdog_ready_path() {
  printf '%s\n' "$watchdog_log_dir/watchdog-${transaction_id}.ready.json" ||
    return 1
}

write_watchdog_record() {
  local kind="$1"
  local outcome="$2"
  local watchdog_pid="$3"
  "$node_bin" - \
    "$watchdog_log_dir" \
    "$kind" \
    "$outcome" \
    "$watchdog_pid" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  root,
  kind,
  outcome,
  watchdogPidText,
  transactionId,
  pendingStateHash,
  deadlineEpochText,
  releaseName,
  releaseSha,
  artifactDigest,
] = process.argv.slice(2);
if (!['ready', 'receipt'].includes(kind)) throw new Error(`invalid watchdog record kind: ${kind}`);
if (
  kind === 'ready'
    ? outcome !== 'ready'
    : !['completed', 'rolled-back', 'superseded', 'failed'].includes(outcome)
) {
  throw new Error(`invalid watchdog record outcome: ${outcome}`);
}
const watchdogPid = Number(watchdogPidText);
const deadlineEpoch = Number(deadlineEpochText);
if (!Number.isSafeInteger(watchdogPid) || watchdogPid <= 0) {
  throw new Error('watchdog PID is invalid');
}
if (!Number.isSafeInteger(deadlineEpoch) || deadlineEpoch <= 0) {
  throw new Error('watchdog deadline is invalid');
}
if (
  !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(transactionId) ||
  !/^[0-9a-f]{64}$/.test(pendingStateHash) ||
  !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(releaseName) ||
  releaseName.includes('..') ||
  !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(releaseSha) ||
  !/^sha256:[0-9a-f]{64}$/.test(artifactDigest)
) {
  throw new Error('watchdog record identity is invalid');
}
const payload = {
  schemaVersion: 1,
  kind,
  outcome,
  watchdogPid,
  transactionId,
  pendingStateHash,
  deadlineEpoch,
  releaseName,
  releaseSha,
  artifactDigest,
  recordedAt: new Date().toISOString(),
};
const record = {
  ...payload,
  contentHash: createHash('sha256')
    .update(`installer-watchdog-record-v1\0${JSON.stringify(payload)}`)
    .digest('hex'),
};
const target = kind === 'ready'
  ? path.join(root, `watchdog-${transactionId}.ready.json`)
  : path.join(root, `watchdog-${transactionId}.receipt.json`);
const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
let temporaryCreated = false;
let temporaryFd = null;
let published = false;
let reusedExisting = false;
let rootChanged = false;

function syncRoot() {
  const directoryFd = fs.openSync(root, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
}

function validateExisting() {
  const info = fs.lstatSync(target);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.nlink !== 1 ||
    (info.mode & 0o777) !== 0o600
  ) {
    throw new Error('watchdog record is not a protected regular file');
  }
  const existing = JSON.parse(fs.readFileSync(target, 'utf8'));
  const expectedKeys = [
    'artifactDigest',
    'contentHash',
    'deadlineEpoch',
    'kind',
    'outcome',
    'pendingStateHash',
    'recordedAt',
    'releaseName',
    'releaseSha',
    'schemaVersion',
    'transactionId',
    'watchdogPid',
  ];
  if (
    !existing ||
    Array.isArray(existing) ||
    typeof existing !== 'object' ||
    JSON.stringify(Object.keys(existing).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error('watchdog record has unexpected fields');
  }
  const existingPayload = {
    schemaVersion: existing.schemaVersion,
    kind: existing.kind,
    outcome: existing.outcome,
    watchdogPid: existing.watchdogPid,
    transactionId: existing.transactionId,
    pendingStateHash: existing.pendingStateHash,
    deadlineEpoch: existing.deadlineEpoch,
    releaseName: existing.releaseName,
    releaseSha: existing.releaseSha,
    artifactDigest: existing.artifactDigest,
    recordedAt: existing.recordedAt,
  };
  const computed = createHash('sha256')
    .update(`installer-watchdog-record-v1\0${JSON.stringify(existingPayload)}`)
    .digest('hex');
  if (
    existing.schemaVersion !== 1 ||
    existing.kind !== kind ||
    existing.outcome !== outcome ||
    !Number.isSafeInteger(existing.watchdogPid) ||
    existing.watchdogPid <= 0 ||
    (kind === 'ready' && existing.watchdogPid !== watchdogPid) ||
    existing.transactionId !== transactionId ||
    existing.pendingStateHash !== pendingStateHash ||
    existing.deadlineEpoch !== deadlineEpoch ||
    existing.releaseName !== releaseName ||
    existing.releaseSha !== releaseSha ||
    existing.artifactDigest !== artifactDigest ||
    typeof existing.recordedAt !== 'string' ||
    !Number.isFinite(Date.parse(existing.recordedAt)) ||
    existing.contentHash !== computed
  ) {
    throw new Error('watchdog record contradicts the exact deployment transaction');
  }
}

try {
  temporaryFd = fs.openSync(temporary, 'wx', 0o600);
  temporaryCreated = true;
  try {
    fs.fchmodSync(temporaryFd, 0o600);
    fs.writeFileSync(temporaryFd, `${JSON.stringify(record, null, 2)}\n`);
    fs.fsyncSync(temporaryFd);
  } finally {
    fs.closeSync(temporaryFd);
    temporaryFd = null;
  }
  try {
    fs.linkSync(temporary, target);
    published = true;
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    validateExisting();
    fs.rmSync(temporary);
    temporaryCreated = false;
    rootChanged = true;
    syncRoot();
    rootChanged = false;
    reusedExisting = true;
  }
  if (!reusedExisting) {
    fs.rmSync(temporary);
    temporaryCreated = false;
    rootChanged = true;
    validateExisting();
    syncRoot();
    rootChanged = false;
  }
} catch (error) {
  const cleanupErrors = [];
  if (temporaryFd !== null) {
    try {
      fs.closeSync(temporaryFd);
      temporaryFd = null;
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
  }
  if (temporaryCreated) {
    try {
      fs.rmSync(temporary, { force: true });
      temporaryCreated = false;
      rootChanged = true;
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
  }
  if (published) {
    try {
      fs.rmSync(target, { force: true });
      published = false;
      rootChanged = true;
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
  }
  if (rootChanged) {
    try {
      syncRoot();
      rootChanged = false;
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError(
      [error, ...cleanupErrors],
      'watchdog record publication and fail-closed cleanup both failed',
    );
  }
  throw error;
}
process.stdout.write(target);
NODE
}

validate_watchdog_ready() {
  local record_path="$1"
  local watchdog_pid="$2"
  "$node_bin" - \
    "$record_path" \
    "$watchdog_pid" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const [
  recordPath,
  watchdogPidText,
  transactionId,
  pendingStateHash,
  deadlineEpochText,
  releaseName,
  releaseSha,
  artifactDigest,
] = process.argv.slice(2);
const info = fs.lstatSync(recordPath);
if (
  !info.isFile() ||
  info.isSymbolicLink() ||
  info.nlink !== 1 ||
  (info.mode & 0o777) !== 0o600
) {
  throw new Error('watchdog ready marker is not a protected regular file');
}
const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const expectedKeys = [
  'artifactDigest',
  'contentHash',
  'deadlineEpoch',
  'kind',
  'outcome',
  'pendingStateHash',
  'recordedAt',
  'releaseName',
  'releaseSha',
  'schemaVersion',
  'transactionId',
  'watchdogPid',
];
if (
  !record ||
  Array.isArray(record) ||
  typeof record !== 'object' ||
  JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
) {
  throw new Error('watchdog ready marker has unexpected fields');
}
const payload = {
  schemaVersion: record.schemaVersion,
  kind: record.kind,
  outcome: record.outcome,
  watchdogPid: record.watchdogPid,
  transactionId: record.transactionId,
  pendingStateHash: record.pendingStateHash,
  deadlineEpoch: record.deadlineEpoch,
  releaseName: record.releaseName,
  releaseSha: record.releaseSha,
  artifactDigest: record.artifactDigest,
  recordedAt: record.recordedAt,
};
const computed = createHash('sha256')
  .update(`installer-watchdog-record-v1\0${JSON.stringify(payload)}`)
  .digest('hex');
if (
  record.schemaVersion !== 1 ||
  record.kind !== 'ready' ||
  record.outcome !== 'ready' ||
  record.watchdogPid !== Number(watchdogPidText) ||
  record.transactionId !== transactionId ||
  record.pendingStateHash !== pendingStateHash ||
  record.deadlineEpoch !== Number(deadlineEpochText) ||
  record.releaseName !== releaseName ||
  record.releaseSha !== releaseSha ||
  record.artifactDigest !== artifactDigest ||
  typeof record.recordedAt !== 'string' ||
  !Number.isFinite(Date.parse(record.recordedAt)) ||
  record.contentHash !== computed
) {
  throw new Error('watchdog ready marker does not match the exact deployment transaction');
}
NODE
}

watchdog_pending_matches_exact() {
  local match_status state_deadline
  if [ ! -e "$pending_dir" ] && [ ! -L "$pending_dir" ]; then
    return 3
  fi
  [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
    echo "watchdog pending path is not a regular directory: $pending_dir" >&2
    return 2
  }
  if pending_matches_exact_transaction; then
    :
  else
    match_status=$?
    return "$match_status"
  fi
  state_deadline="$(read_pending deadline_epoch)" || return 2
  [[ "$state_deadline" =~ ^[1-9][0-9]*$ ]] || {
    echo "watchdog pending state has an invalid deadline" >&2
    return 2
  }
  [ "$state_deadline" = "$pending_deadline_epoch" ] && return 0
  return 1
}

watchdog_exit() {
  local status=$?
  local receipt_outcome="${watchdog_terminal_outcome:-failed}"
  trap - EXIT
  if [ "$status" -ne 0 ] &&
    [ "$watchdog_terminal_recorded" -eq 0 ] &&
    [ -n "$transaction_id" ] &&
    [ -n "$pending_state_hash" ] &&
    [ -n "$pending_deadline_epoch" ]; then
    if ! write_watchdog_record \
      receipt "$receipt_outcome" "${BASHPID:-$$}" >/dev/null; then
      echo "failed to publish watchdog $receipt_outcome receipt" >&2
      status=1
    fi
  fi
  exit "$status"
}

publish_watchdog_terminal_record() {
  local outcome="$1"
  case "$outcome" in
    completed|rolled-back|superseded|failed) ;;
    *)
      echo "invalid watchdog terminal outcome: $outcome" >&2
      return 1
      ;;
  esac
  watchdog_terminal_outcome="$outcome"
  write_watchdog_record receipt "$outcome" "${BASHPID:-$$}" >/dev/null ||
    return 1
  watchdog_terminal_recorded=1
}

write_finalization_record() {
  local outcome="$1"
  validate_pending_state_hash || return 1
  "$node_bin" - "$pending_dir" "$outcome" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [root, outcome] = process.argv.slice(2);
if (!['committed', 'rolled-back'].includes(outcome)) {
  throw new Error(`invalid deployment finalization outcome: ${outcome}`);
}
function readField(field) {
  const fieldPath = path.join(root, field);
  const info = fs.lstatSync(fieldPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(fieldPath, 'utf8');
  if (contents.includes('\0')) throw new Error(`deployment field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`deployment field ${field} is not exactly one line`);
  return lines[0];
}
const payload = {
  schemaVersion: 1,
  outcome,
  pendingStateHash: readField('pending_state_hash'),
  transactionId: readField('transaction_id'),
  releaseName: readField('release_name'),
  releaseSha: readField('github_sha'),
  artifactDigest: readField('artifact_digest'),
};
const record = {
  ...payload,
  contentHash: createHash('sha256')
    .update(`installer-finalization-v1\0${JSON.stringify(payload)}`)
    .digest('hex'),
};
const recordPath = path.join(root, 'finalization.json');
if (fs.existsSync(recordPath)) {
  const info = fs.lstatSync(recordPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('deployment finalization record is not a regular file');
  }
  const existing = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
  if (JSON.stringify(existing) !== JSON.stringify(record)) {
    throw new Error('deployment finalization intent contradicts the existing record');
  }
  process.exit(0);
}
const temporaryPath = `${recordPath}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
  mode: 0o600,
  flag: 'wx',
});
const fd = fs.openSync(temporaryPath, 'r');
try {
  fs.fsyncSync(fd);
} finally {
  fs.closeSync(fd);
}
fs.renameSync(temporaryPath, recordPath);
const directoryFd = fs.openSync(root, 'r');
try {
  fs.fsyncSync(directoryFd);
} finally {
  fs.closeSync(directoryFd);
}
NODE
}

validate_finalization_record_at() {
  local state_root="$1"
  validate_pending_state_hash_at "$state_root" || return 1
  "$node_bin" - "$state_root" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
function readField(field) {
  const fieldPath = path.join(root, field);
  const info = fs.lstatSync(fieldPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`deployment field ${field} is not a regular file`);
  }
  const contents = fs.readFileSync(fieldPath, 'utf8');
  if (contents.includes('\0')) throw new Error(`deployment field ${field} contains a NUL byte`);
  const lines = contents.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) throw new Error(`deployment field ${field} is not exactly one line`);
  return lines[0];
}
const recordPath = path.join(root, 'finalization.json');
const info = fs.lstatSync(recordPath);
if (!info.isFile() || info.isSymbolicLink()) {
  throw new Error('deployment finalization record is not a regular file');
}
const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
if (!record || Array.isArray(record) || typeof record !== 'object') {
  throw new Error('deployment finalization record must be an object');
}
const expectedKeys = [
  'artifactDigest',
  'contentHash',
  'outcome',
  'pendingStateHash',
  'releaseName',
  'releaseSha',
  'schemaVersion',
  'transactionId',
];
if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)) {
  throw new Error('deployment finalization record has unexpected fields');
}
if (
  record.schemaVersion !== 1 ||
  !['committed', 'rolled-back'].includes(record.outcome) ||
  record.pendingStateHash !== readField('pending_state_hash') ||
  record.transactionId !== readField('transaction_id') ||
  record.releaseName !== readField('release_name') ||
  record.releaseSha !== readField('github_sha') ||
  record.artifactDigest !== readField('artifact_digest') ||
  typeof record.contentHash !== 'string' ||
  !/^[0-9a-f]{64}$/.test(record.contentHash)
) {
  throw new Error('deployment finalization record does not match pending identity');
}
const payload = {
  schemaVersion: record.schemaVersion,
  outcome: record.outcome,
  pendingStateHash: record.pendingStateHash,
  transactionId: record.transactionId,
  releaseName: record.releaseName,
  releaseSha: record.releaseSha,
  artifactDigest: record.artifactDigest,
};
const computed = createHash('sha256')
  .update(`installer-finalization-v1\0${JSON.stringify(payload)}`)
  .digest('hex');
if (record.contentHash !== computed) {
  throw new Error('deployment finalization record content hash mismatch');
}
process.stdout.write(record.outcome);
NODE
}

ensure_pending_finalization_outcome() {
  local expected_outcome="$1"
  local recorded_outcome
  if [ ! -e "$pending_dir/finalization.json" ] && [ ! -L "$pending_dir/finalization.json" ]; then
    return 0
  fi
  recorded_outcome="$(validate_finalization_record_at "$pending_dir")" || return 1
  [ "$recorded_outcome" = "$expected_outcome" ] || {
    echo "pending deployment finalization outcome is $recorded_outcome, not $expected_outcome" >&2
    return 1
  }
}

find_finalized_state() {
  local candidate
  local count=0
  finalized_state_dir=
  for candidate in "$base"/.pending-deploy.finalized-*; do
    if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
      continue
    fi
    [ -d "$candidate" ] && [ ! -L "$candidate" ] || {
      echo "finalized deployment marker is not a regular directory: $candidate" >&2
      return 1
    }
    count=$((count + 1))
    finalized_state_dir="$candidate"
  done
  [ "$count" -le 1 ] || {
    echo "multiple finalized deployment markers require operator review" >&2
    return 1
  }
}

recover_finalized_state() {
  local expected_outcome="${1:-}"
  local expected_release_name="${2:-}"
  local expected_release_sha="${3:-}"
  local expected_artifact_digest="${4:-}"
  local expected_transaction_id="${5:-}"
  local expected_pending_state_hash="${6:-}"
  local require_rollback_readiness="${7:-1}"
  local outcome state_release_name state_release_sha state_artifact_digest
  local state_transaction_id state_pending_state_hash state_release_dir state_release_created
  local previous_present previous_target state_tarball
  local state_tarball_sha256 state_tarball_size_bytes
  local state_runtime_env state_runtime_env_created state_database_path
  local state_snapshot_path state_snapshot_dir current_target expected_finalized_dir
  local completed_state_dir current_status readiness_status state_schema
  local current_present=0

  [ "$deploy_lock_held" -eq 1 ] || {
    echo "finalized deployment recovery requires the deployment lock" >&2
    return 1
  }
  recovered_finalization=0
  recovered_finalization_outcome=
  case "$require_rollback_readiness" in
    0|1) ;;
    *)
      echo "invalid finalized rollback readiness mode" >&2
      return 1
      ;;
  esac
  if [ -n "$expected_pending_state_hash" ]; then
    validate_pending_state_hash_value "$expected_pending_state_hash" || return 1
  fi
  find_finalized_state || return 1
  [ -n "$finalized_state_dir" ] || return 0

  outcome="$(validate_finalization_record_at "$finalized_state_dir")" || return 1
  state_release_name="$(
    read_state_field "$finalized_state_dir" release_name
  )" || return 1
  state_release_sha="$(read_state_field "$finalized_state_dir" github_sha)" ||
    return 1
  state_artifact_digest="$(
    read_state_field "$finalized_state_dir" artifact_digest
  )" || return 1
  state_transaction_id="$(
    read_state_field "$finalized_state_dir" transaction_id
  )" || return 1
  state_pending_state_hash="$(
    read_state_field "$finalized_state_dir" pending_state_hash
  )" || return 1
  validate_release_identity_values \
    "$state_release_name" \
    "$state_release_sha" \
    "$state_artifact_digest" || return 1
  [[ "$state_transaction_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    echo "finalized deployment has an invalid transaction ID" >&2
    return 1
  }
  expected_finalized_dir="$base/.pending-deploy.finalized-${outcome}-${state_release_name}-${state_transaction_id}"
  [ "$finalized_state_dir" = "$expected_finalized_dir" ] || {
    echo "finalized deployment marker name does not match its authenticated identity" >&2
    return 1
  }
  if [ -n "$expected_outcome" ]; then
    [ "$outcome" = "$expected_outcome" ] &&
      [ "$state_release_name" = "$expected_release_name" ] &&
      [ "$state_release_sha" = "$expected_release_sha" ] &&
      [ "$state_artifact_digest" = "$expected_artifact_digest" ] &&
      [ "$state_transaction_id" = "$expected_transaction_id" ] || {
      echo "finalized deployment does not match the requested $expected_outcome transaction" >&2
      return 1
    }
    if [ -n "$expected_pending_state_hash" ] &&
      [ "$state_pending_state_hash" != "$expected_pending_state_hash" ]; then
      echo "finalized deployment does not match the requested pending-state identity" >&2
      return 1
    fi
  fi

  state_schema="$(
    read_state_field "$finalized_state_dir" pending_schema_version
  )" || return 1
  [ "$state_schema" = "$pending_state_schema_version" ] || {
    echo "finalized deployment has an unsupported pending schema" >&2
    return 1
  }
  state_release_dir="$(read_state_field "$finalized_state_dir" release_dir)" ||
    return 1
  state_release_created="$(
    read_state_field "$finalized_state_dir" release_created
  )" || return 1
  previous_present="$(
    read_state_field "$finalized_state_dir" previous_current_present
  )" || return 1
  previous_target="$(
    read_state_field "$finalized_state_dir" previous_current_target
  )" || return 1
  state_tarball="$(read_state_field "$finalized_state_dir" tarball)" || return 1
  state_tarball_sha256="$(
    read_state_field "$finalized_state_dir" tarball_sha256
  )" || return 1
  state_tarball_size_bytes="$(
    read_state_field "$finalized_state_dir" tarball_size_bytes
  )" || return 1
  state_runtime_env="$(
    read_state_field "$finalized_state_dir" runtime_env_path
  )" || return 1
  state_runtime_env_created="$(
    read_state_field "$finalized_state_dir" runtime_env_created
  )" || return 1
  state_database_path="$(
    read_state_field "$finalized_state_dir" database_path
  )" || return 1
  state_snapshot_path="$(
    read_state_field "$finalized_state_dir" db_snapshot_path
  )" || return 1
  state_snapshot_dir="$backup_root/${state_release_name}-${state_transaction_id}"

  [ "$state_release_dir" = "$releases/$state_release_name" ] || {
    echo "finalized deployment release path is outside its release identity" >&2
    return 1
  }
  [ "$state_runtime_env" = "$runtime_env_dir/$state_release_name.env" ] || {
    echo "finalized deployment runtime env path is outside its release identity" >&2
    return 1
  }
  [ "$state_snapshot_path" = "$state_snapshot_dir/pre-migration.sqlite" ] || {
    echo "finalized deployment snapshot path is outside its release identity" >&2
    return 1
  }
  [ "$state_database_path" = "$database_path" ] || {
    echo "finalized deployment database path does not match the configured production database" >&2
    return 1
  }
  validate_transaction_tarball_path_value \
    "$state_tarball" \
    "$state_transaction_id" \
    "finalized deployment" || return 1
  case "$state_release_created:$state_runtime_env_created:$previous_present" in
    [01]:[01]:[01]) ;;
    *)
      echo "finalized deployment has invalid boolean state" >&2
      return 1
      ;;
  esac

  if current_target="$(read_current_target)"; then
    current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) current_target= ;;
      *) return 1 ;;
    esac
  fi
  if [ "$outcome" = "committed" ]; then
    [ "$current_present" -eq 1 ] && [ "$current_target" = "$state_release_dir" ] || {
      echo "committed deployment recovery found a contradictory current release" >&2
      return 1
    }
    [ -d "$state_release_dir" ] && [ ! -L "$state_release_dir" ] || {
      echo "committed deployment recovery is missing its release directory" >&2
      return 1
    }
  elif [ "$previous_present" = "1" ]; then
    case "$previous_target" in
      "$releases"/*) ;;
      *)
        echo "rolled-back deployment previous release is outside the releases directory" >&2
        return 1
        ;;
    esac
    [ "$current_present" -eq 1 ] && [ "$current_target" = "$previous_target" ] || {
      echo "rolled-back deployment recovery found a contradictory current release" >&2
      return 1
    }
    [ -d "$previous_target" ] && [ ! -L "$previous_target" ] || {
      echo "rolled-back deployment recovery is missing the previous release" >&2
      return 1
    }
  else
    [ "$current_present" -eq 0 ] || {
      echo "rolled-back first deployment unexpectedly has a current release" >&2
      return 1
    }
  fi

  if [ "$outcome" = "rolled-back" ] &&
    [ "$require_rollback_readiness" -eq 1 ]; then
    if ensure_previous_release_ready_after_rollback "$finalized_state_dir"; then
      :
    else
      readiness_status=$?
      [ "$readiness_status" -eq 2 ] && return 2
      return 1
    fi
  fi

  recover_completed_state \
    "$outcome" \
    "$state_release_name" \
    "$state_release_sha" \
    "$state_artifact_digest" \
    "$state_transaction_id" \
    "$state_pending_state_hash" \
    "$require_rollback_readiness" || return 1
  [ "$recovered_completion" -eq 0 ] || {
    echo "finalized deployment duplicates an existing completion receipt" >&2
    return 1
  }

  if [ "$outcome" = "rolled-back" ] && [ "$state_release_created" = "1" ]; then
    if [ -e "$state_release_dir" ] || [ -L "$state_release_dir" ]; then
      [ -d "$state_release_dir" ] && [ ! -L "$state_release_dir" ] || {
        echo "rolled-back candidate cleanup path is not a regular directory" >&2
        return 1
      }
      rm -rf "$state_release_dir" || return 1
      fsync_directory "$releases" || return 1
    fi
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_RECOVERY_AFTER_RELEASE_CLEANUP \
      recovery-after-release-cleanup || return 1
  fi
  if [ "$outcome" = "rolled-back" ] && [ "$state_runtime_env_created" = "1" ]; then
    if [ -e "$state_runtime_env" ] || [ -L "$state_runtime_env" ]; then
      [ ! -d "$state_runtime_env" ] || {
        echo "rolled-back runtime env cleanup path is a directory" >&2
        return 1
      }
      rm -f "$state_runtime_env" || return 1
      fsync_directory "$runtime_env_dir" || return 1
    fi
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_RECOVERY_AFTER_RUNTIME_ENV_CLEANUP \
      recovery-after-runtime-env-cleanup || return 1
  fi
  if [ -e "$state_snapshot_dir" ] || [ -L "$state_snapshot_dir" ]; then
    [ -d "$state_snapshot_dir" ] && [ ! -L "$state_snapshot_dir" ] || {
      echo "deployment snapshot cleanup path is not a regular directory" >&2
      return 1
    }
    rm -rf "$state_snapshot_dir" || return 1
    fsync_directory "$backup_root" || return 1
  fi
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_RECOVERY_AFTER_SNAPSHOT_CLEANUP \
    recovery-after-snapshot-cleanup || return 1
  if [ -e "$state_tarball" ] || [ -L "$state_tarball" ]; then
    validate_owned_tarball_file \
      "$state_tarball" \
      "$state_tarball_sha256" \
      "$state_tarball_size_bytes" \
      "$state_transaction_id" \
      "finalized deployment" || return 1
    rm -f "$state_tarball" || return 1
    fsync_directory "$artifact_root" || return 1
  fi
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_RECOVERY_AFTER_TARBALL_CLEANUP \
    recovery-after-tarball-cleanup || return 1

  completed_state_dir="$completion_root/${outcome}-${state_release_name}-${state_transaction_id}"
  [ ! -e "$completed_state_dir" ] && [ ! -L "$completed_state_dir" ] || {
    echo "deployment completion receipt already exists: $completed_state_dir" >&2
    return 1
  }
  mv "$finalized_state_dir" "$completed_state_dir" || return 1
  chown "$release_owner:$runtime_group" "$completed_state_dir" ||
    return 1
  chmod 750 "$completed_state_dir" || return 1
  chown \
    "$release_owner:$runtime_group" \
    "$completed_state_dir/finalization.json" || return 1
  chmod 640 "$completed_state_dir/finalization.json" || return 1
  if [ -f "$completed_state_dir/promotion-binding.json" ] &&
    [ ! -L "$completed_state_dir/promotion-binding.json" ]; then
    chown \
      "$release_owner:$runtime_group" \
      "$completed_state_dir/promotion-binding.json" || return 1
    chmod 640 "$completed_state_dir/promotion-binding.json" || return 1
  fi
  fsync_directory "$completion_root" || return 1
  fsync_directory "$base" || return 1
  if [ "$outcome" = "committed" ]; then
    write_committed_startup_authorization_at "$completed_state_dir" ||
      return 1
  else
    restore_previous_startup_authorization_at "$completed_state_dir" ||
      return 1
  fi
  remove_matching_activation_intent_at "$completed_state_dir" || return 1
  recovered_finalization=1
  recovered_finalization_outcome="$outcome"
}

recover_completed_state() {
  local expected_outcome="${1:-}"
  local expected_release_name="$2"
  local expected_release_sha="$3"
  local expected_artifact_digest="$4"
  local expected_transaction_id="$5"
  local expected_pending_state_hash="${6:-}"
  local require_rollback_readiness="${7:-1}"
  local candidate outcome state_release_name state_release_sha state_artifact_digest
  local state_transaction_id state_pending_state_hash expected_completed_dir
  local match_dir= match_outcome= match_count=0 opposite_match=0
  local current_target state_release_dir previous_present previous_target
  local live_pending_transaction_id current_present=0 current_status readiness_status

  [ "$deploy_lock_held" -eq 1 ] || {
    echo "deployment completion recovery requires the deployment lock" >&2
    return 1
  }
  case "$expected_outcome" in
    ""|committed|rolled-back) ;;
    *)
      echo "invalid expected deployment completion outcome: $expected_outcome" >&2
      return 1
      ;;
  esac
  case "$require_rollback_readiness" in
    0|1) ;;
    *)
      echo "invalid rollback completion readiness mode" >&2
      return 1
      ;;
  esac
  validate_release_identity_values \
    "$expected_release_name" \
    "$expected_release_sha" \
    "$expected_artifact_digest" || return 1
  validate_transaction_id "$expected_transaction_id" || return 1
  if [ -n "$expected_pending_state_hash" ]; then
    validate_pending_state_hash_value "$expected_pending_state_hash" || return 1
  fi
  recovered_completion=0
  recovered_completion_outcome=
  for candidate in "$completion_root"/*; do
    if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
      continue
    fi
    [ -d "$candidate" ] && [ ! -L "$candidate" ] || {
      echo "deployment completion receipt is not a regular directory: $candidate" >&2
      return 1
    }
    outcome="$(validate_finalization_record_at "$candidate")" || return 1
    state_release_name="$(read_state_field "$candidate" release_name)" || return 1
    state_release_sha="$(read_state_field "$candidate" github_sha)" || return 1
    state_artifact_digest="$(read_state_field "$candidate" artifact_digest)" ||
      return 1
    state_transaction_id="$(read_state_field "$candidate" transaction_id)" ||
      return 1
    state_pending_state_hash="$(
      read_state_field "$candidate" pending_state_hash
    )" || return 1
    validate_release_identity_values \
      "$state_release_name" \
      "$state_release_sha" \
      "$state_artifact_digest" || return 1
    [[ "$state_transaction_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
      echo "deployment completion receipt has an invalid transaction ID" >&2
      return 1
    }
    expected_completed_dir="$completion_root/${outcome}-${state_release_name}-${state_transaction_id}"
    [ "$candidate" = "$expected_completed_dir" ] || {
      echo "deployment completion receipt name does not match its authenticated identity" >&2
      return 1
    }
    if [ "$state_transaction_id" != "$expected_transaction_id" ]; then
      continue
    fi
    [ "$state_release_name" = "$expected_release_name" ] &&
      [ "$state_release_sha" = "$expected_release_sha" ] &&
      [ "$state_artifact_digest" = "$expected_artifact_digest" ] || {
      echo "deployment transaction ID is bound to a different release identity" >&2
      return 1
    }
    if [ -n "$expected_pending_state_hash" ] &&
      [ "$state_pending_state_hash" != "$expected_pending_state_hash" ]; then
      echo "deployment completion receipt has a different pending-state identity" >&2
      return 1
    fi
    if [ -n "$expected_outcome" ] && [ "$outcome" != "$expected_outcome" ]; then
      opposite_match=1
      continue
    fi
    match_count=$((match_count + 1))
    match_dir="$candidate"
    match_outcome="$outcome"
  done
  [ "$opposite_match" -eq 0 ] || {
    echo "deployment transaction has a contradictory terminal completion receipt" >&2
    return 1
  }
  [ "$match_count" -le 1 ] || {
    echo "multiple matching deployment completion receipts require operator review" >&2
    return 1
  }
  if [ "$match_count" -eq 0 ]; then
    return 0
  fi
  if [ -e "$pending_dir" ] || [ -L "$pending_dir" ]; then
    [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
      echo "pending deployment path is not a regular directory: $pending_dir" >&2
      return 1
    }
    validate_pending_state_hash_at "$pending_dir" || return 1
    live_pending_transaction_id="$(
      read_state_field "$pending_dir" transaction_id
    )" || return 1
    validate_transaction_id "$live_pending_transaction_id" || return 1
    [ "$live_pending_transaction_id" != "$expected_transaction_id" ] || {
      echo "deployment completion receipt coexists with its live pending transaction" >&2
      return 1
    }
  fi

  state_release_dir="$(read_state_field "$match_dir" release_dir)" || return 1
  [ "$state_release_dir" = "$releases/$expected_release_name" ] || {
    echo "deployment completion receipt release path is outside its release identity" >&2
    return 1
  }
  if current_target="$(read_current_target)"; then
    current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) current_target= ;;
      *) return 1 ;;
    esac
  fi
  if [ "$match_outcome" = "committed" ]; then
    [ "$current_present" -eq 1 ] && [ "$current_target" = "$state_release_dir" ] || {
      echo "completed commit receipt contradicts the current release" >&2
      return 1
    }
    [ -d "$state_release_dir" ] && [ ! -L "$state_release_dir" ] || {
      echo "completed commit receipt is missing its release directory" >&2
      return 1
    }
  else
    previous_present="$(read_state_field "$match_dir" previous_current_present)" ||
      return 1
    previous_target="$(read_state_field "$match_dir" previous_current_target)" ||
      return 1
    case "$previous_present" in
      0)
        [ "$current_present" -eq 0 ] || {
          echo "completed first-release rollback unexpectedly has a current release" >&2
          return 1
        }
        ;;
      1)
        case "$previous_target" in
          "$releases"/*) ;;
          *)
            echo "completed rollback receipt previous release is outside the releases directory" >&2
            return 1
            ;;
        esac
        [ "$current_present" -eq 1 ] && [ "$current_target" = "$previous_target" ] || {
          echo "completed rollback receipt contradicts the current release" >&2
          return 1
        }
        [ -d "$previous_target" ] && [ ! -L "$previous_target" ] || {
          echo "completed rollback receipt is missing the previous release" >&2
          return 1
        }
        ;;
      *)
        echo "deployment completion receipt has invalid previous-current state" >&2
        return 1
        ;;
      esac
    if [ "$require_rollback_readiness" -eq 1 ]; then
      if ensure_previous_release_ready_after_rollback "$match_dir"; then
        :
      else
        readiness_status=$?
        [ "$readiness_status" -eq 2 ] && return 2
        return 1
      fi
    fi
  fi
  if [ "$match_outcome" = "committed" ]; then
    chown "$release_owner:$runtime_group" "$match_dir" ||
      return 1
    chmod 750 "$match_dir" || return 1
    chown "$release_owner:$runtime_group" "$match_dir/finalization.json" ||
      return 1
    chmod 640 "$match_dir/finalization.json" || return 1
    if [ -f "$match_dir/promotion-binding.json" ] &&
      [ ! -L "$match_dir/promotion-binding.json" ]; then
      chown \
        "$release_owner:$runtime_group" \
        "$match_dir/promotion-binding.json" || return 1
      chmod 640 "$match_dir/promotion-binding.json" || return 1
    fi
    write_committed_startup_authorization_at "$match_dir" || return 1
  else
    restore_previous_startup_authorization_at "$match_dir" || return 1
  fi
  remove_matching_activation_intent_at "$match_dir" || return 1
  recovered_completion=1
  recovered_completion_outcome="$match_outcome"
}

recover_watchdog_terminal_state() {
  local outcome state_transaction_id state_release_name state_release_sha
  local state_artifact_digest state_pending_state_hash

  recover_completed_state \
    "" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    0 || return 1
  [ "$recovered_completion" -eq 0 ] || return 0

  find_finalized_state || return 1
  [ -n "$finalized_state_dir" ] || return 0
  outcome="$(validate_finalization_record_at "$finalized_state_dir")" || return 1
  state_transaction_id="$(
    read_state_field "$finalized_state_dir" transaction_id
  )" || return 1
  validate_transaction_id "$state_transaction_id" || return 1
  [ "$state_transaction_id" = "$transaction_id" ] || return 0
  state_release_name="$(
    read_state_field "$finalized_state_dir" release_name
  )" || return 1
  state_release_sha="$(
    read_state_field "$finalized_state_dir" github_sha
  )" || return 1
  state_artifact_digest="$(
    read_state_field "$finalized_state_dir" artifact_digest
  )" || return 1
  state_pending_state_hash="$(
    read_state_field "$finalized_state_dir" pending_state_hash
  )" || return 1
  [ "$state_release_name" = "$release_name" ] &&
    [ "$state_release_sha" = "$expected_sha" ] &&
    [ "$state_artifact_digest" = "$expected_digest" ] &&
    [ "$state_pending_state_hash" = "$pending_state_hash" ] || {
    echo "watchdog finalized state contradicts the exact deployment transaction" >&2
    return 1
  }
  recover_finalized_state \
    "$outcome" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    0 || return 1
  [ "$recovered_finalization" -eq 1 ] || {
    echo "watchdog exact finalized state did not reach a completion receipt" >&2
    return 1
  }
  recover_completed_state \
    "" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    0 || return 1
  [ "$recovered_completion" -eq 1 ] || {
    echo "watchdog exact completion receipt was not recovered" >&2
    return 1
  }
}

ensure_transaction_watchdog_state_unused() {
  "$node_bin" - "$watchdog_log_dir" "$transaction_id" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [root, requestedTransactionId] = process.argv.slice(2);
const uuid =
  '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const currentPattern = new RegExp(`^watchdog-(${uuid})\\.(ready|receipt)\\.json$`);
const legacyScopedPattern =
  new RegExp(`^watchdog-(${uuid})\\.receipt-([1-9][0-9]*)(?:\\.json)?$`);
const legacyBarePattern = /^receipt-([1-9][0-9]*)(?:\.json)?$/;
const expectedKeys = [
  'artifactDigest',
  'contentHash',
  'deadlineEpoch',
  'kind',
  'outcome',
  'pendingStateHash',
  'recordedAt',
  'releaseName',
  'releaseSha',
  'schemaVersion',
  'transactionId',
  'watchdogPid',
];

function validateRecord(entry, expectedKind, filenameTransactionId, filenamePid) {
  const target = path.join(root, entry);
  const info = fs.lstatSync(target);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.nlink !== 1 ||
    (info.mode & 0o777) !== 0o600
  ) {
    throw new Error(`watchdog transaction record is not one protected file: ${entry}`);
  }
  const record = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (
    !record ||
    Array.isArray(record) ||
    typeof record !== 'object' ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)
  ) {
    throw new Error(`watchdog transaction record has unexpected fields: ${entry}`);
  }
  const payload = {
    schemaVersion: record.schemaVersion,
    kind: record.kind,
    outcome: record.outcome,
    watchdogPid: record.watchdogPid,
    transactionId: record.transactionId,
    pendingStateHash: record.pendingStateHash,
    deadlineEpoch: record.deadlineEpoch,
    releaseName: record.releaseName,
    releaseSha: record.releaseSha,
    artifactDigest: record.artifactDigest,
    recordedAt: record.recordedAt,
  };
  const computed = createHash('sha256')
    .update(`installer-watchdog-record-v1\0${JSON.stringify(payload)}`)
    .digest('hex');
  const outcomeValid =
    expectedKind === 'ready'
      ? record.outcome === 'ready'
      : ['completed', 'rolled-back', 'superseded', 'failed'].includes(record.outcome);
  if (
    record.schemaVersion !== 1 ||
    record.kind !== expectedKind ||
    !outcomeValid ||
    !Number.isSafeInteger(record.watchdogPid) ||
    record.watchdogPid <= 0 ||
    (filenamePid !== null && record.watchdogPid !== filenamePid) ||
    !new RegExp(`^${uuid}$`).test(record.transactionId) ||
    (filenameTransactionId !== null &&
      record.transactionId !== filenameTransactionId) ||
    !/^[0-9a-f]{64}$/.test(record.pendingStateHash) ||
    !Number.isSafeInteger(record.deadlineEpoch) ||
    record.deadlineEpoch <= 0 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(record.releaseName) ||
    record.releaseName.includes('..') ||
    record.releaseName.includes('/') ||
    record.releaseName.includes('\\') ||
    !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(record.releaseSha) ||
    !/^sha256:[0-9a-f]{64}$/.test(record.artifactDigest) ||
    typeof record.recordedAt !== 'string' ||
    !Number.isFinite(Date.parse(record.recordedAt)) ||
    record.contentHash !== computed
  ) {
    throw new Error(`watchdog transaction record is invalid: ${entry}`);
  }
  return record;
}

for (const entry of fs.readdirSync(root)) {
  const current = entry.match(currentPattern);
  if (current) {
    if (current[1] !== requestedTransactionId) continue;
    validateRecord(entry, current[2], current[1], null);
    throw new Error(
      `deployment transaction ID already has watchdog state: ${requestedTransactionId}`,
    );
  }
  const scopedLegacy = entry.match(legacyScopedPattern);
  if (scopedLegacy) {
    if (scopedLegacy[1] !== requestedTransactionId) continue;
    validateRecord(
      entry,
      'receipt',
      scopedLegacy[1],
      Number(scopedLegacy[2]),
    );
    throw new Error(
      `deployment transaction ID already has legacy watchdog state: ${requestedTransactionId}`,
    );
  }
  if (entry.startsWith(`watchdog-${requestedTransactionId}.receipt-`)) {
    throw new Error(`legacy watchdog receipt name is invalid: ${entry}`);
  }
  const bareLegacy = entry.match(legacyBarePattern);
  if (!bareLegacy) continue;
  const record = validateRecord(entry, 'receipt', null, Number(bareLegacy[1]));
  if (record.transactionId === requestedTransactionId) {
    throw new Error(
      `deployment transaction ID already has legacy watchdog state: ${requestedTransactionId}`,
    );
  }
}
NODE
}

ensure_transaction_id_unused() {
  local candidate candidate_transaction_id transaction_artifact outcome
  local candidate_release_name candidate_release_sha candidate_artifact_digest
  local expected_candidate seen_transactions=$'\n'
  validate_transaction_id "$transaction_id" || return 1
  transaction_artifact="$(transaction_tarball_path "$transaction_id")" || return 1
  if [ -e "$transaction_artifact" ] || [ -L "$transaction_artifact" ]; then
    echo "deployment transaction ID already owns an artifact: $transaction_id" >&2
    return 1
  fi
  ensure_transaction_watchdog_state_unused || return 1
  for candidate in "$completion_root"/* "$base"/.pending-deploy.finalized-*; do
    if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
      continue
    fi
    [ -d "$candidate" ] && [ ! -L "$candidate" ] || {
      echo "deployment transaction registry entry is not a regular directory: $candidate" >&2
      return 1
    }
    outcome="$(validate_finalization_record_at "$candidate")" || return 1
    candidate_transaction_id="$(read_state_field "$candidate" transaction_id)" ||
      return 1
    candidate_release_name="$(read_state_field "$candidate" release_name)" ||
      return 1
    candidate_release_sha="$(read_state_field "$candidate" github_sha)" ||
      return 1
    candidate_artifact_digest="$(
      read_state_field "$candidate" artifact_digest
    )" || return 1
    validate_transaction_id "$candidate_transaction_id" || return 1
    validate_release_identity_values \
      "$candidate_release_name" \
      "$candidate_release_sha" \
      "$candidate_artifact_digest" || return 1
    case "$candidate" in
      "$completion_root"/*)
        expected_candidate="$completion_root/${outcome}-${candidate_release_name}-${candidate_transaction_id}"
        ;;
      "$base"/.pending-deploy.finalized-*)
        expected_candidate="$base/.pending-deploy.finalized-${outcome}-${candidate_release_name}-${candidate_transaction_id}"
        ;;
      *)
        echo "deployment transaction registry path is outside its registry" >&2
        return 1
        ;;
    esac
    [ "$candidate" = "$expected_candidate" ] || {
      echo "deployment transaction registry entry name does not match its identity" >&2
      return 1
    }
    case "$seen_transactions" in
      *$'\n'"$candidate_transaction_id"$'\n'*)
        echo "deployment transaction registry contains a reused transaction ID" >&2
        return 1
        ;;
    esac
    seen_transactions+="$candidate_transaction_id"$'\n'
    if [ "$candidate_transaction_id" = "$transaction_id" ]; then
      echo "deployment transaction ID is already permanently reserved: $transaction_id" >&2
      return 1
    fi
  done
}

validate_promotion_report() {
  [ "$promotion_required" -eq 1 ] || return 0
  [ -f "$promotion_report_path" ] && [ ! -L "$promotion_report_path" ] || {
    echo "pending deployment is missing a regular promotion report: $promotion_report_path" >&2
    return 1
  }
  "$node_bin" - \
    "$promotion_report_path" \
    "$pending_dir" \
    "$transaction_id" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$pending_state_hash" \
    "$required_score_receipt_id" \
    "$quality_database_path" \
    "$database_path" \
    "$db_snapshot_path" \
    "$db_snapshot_sha256" \
    "$lock_file" <<'NODE' || return 1
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  reportPath,
  pendingPath,
  transactionId,
  releaseName,
  releaseSha,
  artifactDigest,
  pendingStateHash,
  requiredScoreReceiptId,
  qualityDatabasePath,
  productionDatabasePath,
  rollbackBackupPath,
  rollbackBackupSha256,
  lockFilePath,
] = process.argv.slice(2);
const contents = fs.readFileSync(reportPath);
const reportSha256 = createHash('sha256').update(contents).digest('hex');
const report = JSON.parse(contents.toString('utf8'));
const deployment = report.deploymentTransaction;
const sourceAuthorization = deployment?.sourceAuthorization;
const promotionReceipt = report.staged?.canonicalPromotionReceipt;
const promotionAuthorization = report.promotionAuthorization;
const installedDatabaseAuthorization =
  promotionAuthorization?.installedDatabase;
const deploymentLockProof = report.deploymentLock?.proof;
const lockFileInfo = fs.statSync(lockFilePath, { bigint: true });

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  throw new Error('promotion authorization contains unsupported JSON');
}

function readPendingField(field) {
  const target = path.join(pendingPath, field);
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`pending deployment field ${field} is not a regular file`);
  }
  const value = fs.readFileSync(target, 'utf8').replace(/\n$/, '');
  if (!value || value.includes('\0') || value.includes('\n')) {
    throw new Error(`pending deployment field ${field} is invalid`);
  }
  return value;
}

function runtimeRepository() {
  const runtimeEnvPath = readPendingField('runtime_env_path');
  const info = fs.lstatSync(runtimeEnvPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error('release runtime env is not a regular non-symlink file');
  }
  const assignments = new Map();
  for (const line of fs.readFileSync(runtimeEnvPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(
      /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/,
    );
    if (!match) continue;
    let value = match[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '').trim();
    assignments.set(match[1], value);
  }
  const owner = assignments.get('GITHUB_OWNER') || 'openclaw';
  const repo = assignments.get('GITHUB_REPO') || 'openclaw';
  for (const [label, value] of [['owner', owner], ['repository', repo]]) {
    if (
      !value ||
      value.trim() !== value ||
      value.includes('/') ||
      /\s/.test(value)
    ) throw new Error(`release runtime GitHub ${label} is invalid`);
  }
  return `${owner}/${repo}`;
}

function githubProofIdentity(proof, label) {
  const remote = proof?.remoteCatalog;
  const active = proof?.activeCatalog;
  if (
    proof?.schemaVersion !== 1 ||
    proof?.source !== 'independent_github_graphql' ||
    proof?.exactIdentityMatch !== true ||
    typeof proof.repository !== 'string' ||
    !/^[^/\s]+\/[^/\s]+$/.test(proof.repository) ||
    !Number.isFinite(Date.parse(proof.observedAt)) ||
    remote?.exhausted !== true ||
    remote?.stabilized !== true ||
    !/^[0-9a-f]{64}$/.test(String(remote?.digest ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(active?.digest ?? '')) ||
    !Number.isSafeInteger(active?.releaseCount) ||
    active.releaseCount <= 0 ||
    !Array.isArray(active?.tags) ||
    active.tags.length !== active.releaseCount ||
    active.tags.some(
      (tag) => typeof tag !== 'string' || !tag || tag.trim() !== tag,
    )
  ) {
    throw new Error(`${label} has no exact independent GitHub catalog proof`);
  }
  return {
    repository: proof.repository,
    observedAt: proof.observedAt,
    remoteCatalogDigest: remote.digest,
    activeCatalogDigest: active.digest,
    activeReleaseCount: active.releaseCount,
    activeReleaseTags: [...active.tags],
  };
}

function githubAuthorizationIdentity(value) {
  if (
    value?.schemaVersion !== 1 ||
    value?.source !== 'independent_github_graphql' ||
    value?.exactIdentityMatch !== true ||
    typeof value.repository !== 'string' ||
    !/^[^/\s]+\/[^/\s]+$/.test(value.repository) ||
    !Number.isFinite(Date.parse(value.observedAt)) ||
    !/^[0-9a-f]{64}$/.test(String(value.remoteCatalogDigest ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(value.activeCatalogDigest ?? '')) ||
    !Number.isSafeInteger(value.activeReleaseCount) ||
    value.activeReleaseCount <= 0 ||
    !Array.isArray(value.activeReleaseTags) ||
    value.activeReleaseTags.length !== value.activeReleaseCount ||
    value.activeReleaseTags.some(
      (tag) => typeof tag !== 'string' || !tag || tag.trim() !== tag,
    )
  ) {
    throw new Error(
      'promotion authorization has no exact independent GitHub catalog proof',
    );
  }
  return {
    repository: value.repository,
    observedAt: value.observedAt,
    remoteCatalogDigest: value.remoteCatalogDigest,
    activeCatalogDigest: value.activeCatalogDigest,
    activeReleaseCount: value.activeReleaseCount,
    activeReleaseTags: [...value.activeReleaseTags],
  };
}

const sourceGithubCatalog = githubProofIdentity(
  report.githubReleaseCatalog?.source,
  'source promotion report',
);
const beforeSwapGithubCatalog = githubProofIdentity(
  report.githubReleaseCatalog?.beforeSwap,
  'before-swap promotion report',
);
const authorizedGithubCatalog = githubAuthorizationIdentity(
  promotionAuthorization?.githubReleaseCatalog,
);
const {
  contentHash: promotionAuthorizationContentHash,
  ...promotionAuthorizationPayload
} = promotionAuthorization ?? {};
const expectedPromotionAuthorizationContentHash = createHash('sha256')
  .update(
    `quality-db-promotion-authorization-v1\0${
      canonicalJson(promotionAuthorizationPayload)
    }`,
  )
  .digest('hex');
if (
  !installedDatabaseAuthorization ||
  Array.isArray(installedDatabaseAuthorization) ||
  typeof installedDatabaseAuthorization !== 'object' ||
  JSON.stringify(Object.keys(installedDatabaseAuthorization).sort()) !==
    JSON.stringify([
      'logicalContentDigest',
      'physicalSha256',
      'schemaDigest',
    ]) ||
  !/^[0-9a-f]{64}$/.test(
    String(installedDatabaseAuthorization.logicalContentDigest ?? ''),
  ) ||
  !/^[0-9a-f]{64}$/.test(
    String(installedDatabaseAuthorization.schemaDigest ?? ''),
  ) ||
  !/^[0-9a-f]{64}$/.test(
    String(installedDatabaseAuthorization.physicalSha256 ?? ''),
  )
) {
  throw new Error(
    'promotion authorization has no exact installed database identity',
  );
}
if (
  installedDatabaseAuthorization.logicalContentDigest !==
    report.destination?.database?.logicalContentDigest ||
  installedDatabaseAuthorization.schemaDigest !==
    report.destination?.database?.schemaDigest
) {
  throw new Error(
    'promotion authorization installed database logical/schema identity does not match the destination report',
  );
}
const expectedRepository = runtimeRepository();
if (
  report.mode !== 'apply' ||
  report.applied !== true ||
  report.backupPath !== rollbackBackupPath ||
  deployment?.schemaVersion !== 1 ||
  deployment?.transactionId !== transactionId ||
  deployment?.releaseName !== releaseName ||
  deployment?.releaseSha !== releaseSha ||
  deployment?.artifactDigest !== artifactDigest ||
  deployment?.pendingStateHash !== pendingStateHash ||
  deployment?.requiredScoreReceiptId !== requiredScoreReceiptId ||
  deployment?.lockHeldByInstaller !== true ||
  deployment?.pendingDeploymentAuthorization?.verified !== true ||
  sourceAuthorization?.verified !== true ||
  sourceAuthorization?.receiptId !== requiredScoreReceiptId ||
  sourceAuthorization?.receiptStatus !== 'success' ||
  sourceAuthorization?.codeRevision !== releaseSha ||
  report.deploymentLock?.sharedWithInstaller !== true ||
  report.deploymentLock?.inheritedFromInstaller !== true ||
  report.deploymentLock?.transactionId !== transactionId ||
  deploymentLockProof?.schemaVersion !== 1 ||
  deploymentLockProof?.method !== 'linux-proc-fdinfo-flock' ||
  deploymentLockProof?.fd !== 9 ||
  deploymentLockProof?.path !== lockFilePath ||
  deploymentLockProof?.device !== String(lockFileInfo.dev) ||
  deploymentLockProof?.inode !== String(lockFileInfo.ino) ||
  deploymentLockProof?.lockType !== 'exclusive' ||
  deploymentLockProof?.verified !== true ||
  typeof promotionReceipt?.promotionId !== 'string' ||
  typeof promotionReceipt?.contentHash !== 'string' ||
  report.githubReleaseCatalog?.exactAcrossCompletedStages !== true ||
  promotionAuthorization?.schemaVersion !== 1 ||
  promotionAuthorization?.phase !== 'applied' ||
  !/^[0-9a-f]{64}$/.test(String(promotionAuthorizationContentHash ?? '')) ||
  promotionAuthorizationContentHash !==
    expectedPromotionAuthorizationContentHash ||
  promotionAuthorization?.promotionReceipt?.promotionId !==
    promotionReceipt.promotionId ||
  promotionAuthorization?.promotionReceipt?.contentHash !==
    promotionReceipt.contentHash ||
  promotionAuthorization?.sourceDatabase?.logicalContentDigest !==
    report.source?.database?.logicalContentDigest ||
  sourceGithubCatalog.repository !== expectedRepository ||
  beforeSwapGithubCatalog.repository !== expectedRepository ||
  authorizedGithubCatalog.repository !== expectedRepository ||
  canonicalJson({
    ...sourceGithubCatalog,
    observedAt: null,
  }) !== canonicalJson({
    ...beforeSwapGithubCatalog,
    observedAt: null,
  }) ||
  canonicalJson(authorizedGithubCatalog) !==
    canonicalJson(beforeSwapGithubCatalog) ||
  report.rollbackBackup?.verifiedAgainstPrePromotionDestination !== true ||
  report.rollbackBackup?.externallyPrepared !== true
) {
  throw new Error('promotion report does not bind the complete installer transaction');
}
const qualityRealPath = fs.realpathSync(qualityDatabasePath);
const productionRealPath = fs.realpathSync(productionDatabasePath);
const backupRealPath = fs.realpathSync(rollbackBackupPath);
if (
  report.source?.file?.realPath !== qualityRealPath ||
  report.destination?.file?.realPath !== productionRealPath ||
  report.rollbackBackup?.file?.realPath !== backupRealPath
) {
  throw new Error('promotion report database paths do not match installer transaction paths');
}
function fileIdentity(target) {
  const info = fs.statSync(target, { bigint: true });
  return {
    realPath: fs.realpathSync(target),
    device: String(info.dev),
    inode: String(info.ino),
  };
}
function installedFileIdentity(target) {
  const pathInfo = fs.lstatSync(target, { bigint: true });
  if (
    !pathInfo.isFile() ||
    pathInfo.isSymbolicLink() ||
    pathInfo.nlink !== 1n
  ) {
    throw new Error('installed database is not one regular non-symlink file');
  }
  const fd = fs.openSync(
    target,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (
      opened.dev !== pathInfo.dev ||
      opened.ino !== pathInfo.ino ||
      opened.nlink !== 1n ||
      opened.size !== pathInfo.size
    ) {
      throw new Error('installed database changed while opening');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, offset);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
      offset += bytes;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const finalPath = fs.lstatSync(target, { bigint: true });
    if (
      BigInt(offset) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error('installed database changed while hashing');
    }
    return {
      realPath: fs.realpathSync(target),
      device: String(opened.dev),
      inode: String(opened.ino),
      physicalSha256: hash.digest('hex'),
    };
  } finally {
    fs.closeSync(fd);
  }
}
const installed = installedFileIdentity(productionDatabasePath);
const backup = fileIdentity(rollbackBackupPath);
if (
  installed.physicalSha256 !==
  installedDatabaseAuthorization.physicalSha256
) {
  throw new Error(
    'installed database physical digest does not match promotion authorization',
  );
}
const actualBackupSha256 = createHash('sha256')
  .update(fs.readFileSync(rollbackBackupPath))
  .digest('hex');
if (actualBackupSha256 !== rollbackBackupSha256) {
  throw new Error('rollback backup physical digest does not match pending deployment state');
}
for (const [label, actual, reported] of [
  ['installed database', installed, report.destination.file],
  ['rollback backup', backup, report.rollbackBackup.file],
]) {
  if (
    actual.realPath !== reported.realPath ||
    actual.device !== reported.device ||
    actual.inode !== reported.inode
  ) {
    throw new Error(`${label} inode does not match promotion report`);
  }
}
const binding = {
  schemaVersion: 1,
  pendingStateHash,
  transactionId,
  releaseName,
  releaseSha,
  artifactDigest,
  requiredScoreReceiptId,
  reportSha256,
  promotionId: promotionReceipt.promotionId,
  promotionContentHash: promotionReceipt.contentHash,
  promotionAuthorizationContentHash,
  githubReleaseCatalog: authorizedGithubCatalog,
  qualityDatabase: {
    realPath: qualityRealPath,
    logicalContentDigest: report.source?.database?.logicalContentDigest,
  },
  promotedDatabase: {
    ...installed,
    logicalContentDigest:
      installedDatabaseAuthorization.logicalContentDigest,
    schemaDigest: installedDatabaseAuthorization.schemaDigest,
  },
  rollbackBackup: {
    ...backup,
    logicalContentDigest: report.rollbackBackup?.database?.logicalContentDigest,
  },
};
for (const [label, value] of [
  ['quality logical digest', binding.qualityDatabase.logicalContentDigest],
  ['promoted logical digest', binding.promotedDatabase.logicalContentDigest],
  ['promoted schema digest', binding.promotedDatabase.schemaDigest],
  ['promoted physical digest', binding.promotedDatabase.physicalSha256],
  ['rollback logical digest', binding.rollbackBackup.logicalContentDigest],
]) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`promotion report has invalid ${label}`);
  }
}
binding.contentHash = createHash('sha256')
  .update(`installer-promotion-binding-v1\0${JSON.stringify(binding)}`)
  .digest('hex');
const bindingPath = path.join(pendingPath, 'promotion-binding.json');
if (fs.existsSync(bindingPath)) {
  const existing = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
  if (JSON.stringify(existing) !== JSON.stringify(binding)) {
    throw new Error('promotion binding changed after it was recorded');
  }
} else {
  const temporaryPath = `${bindingPath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(binding, null, 2)}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
  const fd = fs.openSync(temporaryPath, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temporaryPath, bindingPath);
  const directoryFd = fs.openSync(pendingPath, 'r');
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
}
NODE
  chown \
    "$release_owner:$runtime_group" \
    "$pending_dir/promotion-binding.json" || return 1
  chmod 640 "$pending_dir/promotion-binding.json" || return 1
  fsync_file "$pending_dir/promotion-binding.json" || return 1
  fsync_directory "$pending_dir" || return 1
}

prepare_promotion_dotenv() {
  local temporary_path
  promotion_dotenv_path="$pending_dir/.promotion.env.empty"
  if [ -e "$promotion_dotenv_path" ] || [ -L "$promotion_dotenv_path" ]; then
    [ -f "$promotion_dotenv_path" ] &&
      [ ! -L "$promotion_dotenv_path" ] &&
      [ ! -s "$promotion_dotenv_path" ] || {
      echo "promotion dotenv guard must be one empty regular file" >&2
      return 1
    }
    return 0
  fi
  temporary_path="$(mktemp "$pending_dir/.promotion.env.empty.XXXXXX")" || return 1
  : > "$temporary_path" || {
    rm -f "$temporary_path"
    return 1
  }
  chmod 600 "$temporary_path" || {
    rm -f "$temporary_path"
    return 1
  }
  fsync_file "$temporary_path" || {
    rm -f "$temporary_path"
    return 1
  }
  mv "$temporary_path" "$promotion_dotenv_path" || {
    rm -f "$temporary_path"
    return 1
  }
  fsync_directory "$pending_dir" || return 1
}

run_quality_promotion() {
  local report_tmp promotion_bin
  [ "$promotion_required" -eq 1 ] || return 0
  report_tmp="$pending_dir/.promotion-report.tmp"
  rm -f "$report_tmp" || return 1
  prepare_promotion_dotenv || return 1
  promotion_bin="${RADAR_INSTALL_PROMOTION_BIN:-}"
  if [ -n "$promotion_bin" ]; then
    [ "${RADAR_INSTALL_TEST_MODE:-0}" = "1" ] &&
      [[ "${RADAR_INSTALL_TEST_NONCE:-}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "configured promotion executable is restricted to explicit installer test mode" >&2
      return 1
    }
    [ -x "$promotion_bin" ] || {
      echo "configured promotion executable is not executable: $promotion_bin" >&2
      return 1
    }
    RADAR_CODE_REVISION="$expected_sha" \
    RADAR_INSTALL_BASE="$base" \
    DOTENV_CONFIG_PATH="$promotion_dotenv_path" \
      "$promotion_bin" \
        --source "$quality_database_path" \
        --destination "$database_path" \
        --rollback-backup "$db_snapshot_path" \
        --deployment-transaction-id "$transaction_id" \
        --release-name "$release_name" \
        --release-sha "$expected_sha" \
        --artifact-digest "$expected_digest" \
        --pending-state-hash "$pending_state_hash" \
        --required-score-receipt-id "$required_score_receipt_id" \
        --deployment-lock-fd 9 \
        --apply > "$report_tmp" || {
      rm -f "$report_tmp"
      return 1
    }
  else
    [ -x "$npm_bin" ] || {
      echo "promotion npm executable is not executable: $npm_bin" >&2
      return 1
    }
    RADAR_CODE_REVISION="$expected_sha" \
    RADAR_INSTALL_BASE="$base" \
    RADAR_PROMOTION_LOCK_STDIN=1 \
    DOTENV_CONFIG_PATH="$promotion_dotenv_path" \
      "$npm_bin" \
        --silent \
        --prefix "$release_dir/$promotion_runtime_relative" \
        run promote:quality-db -- \
        --source "$quality_database_path" \
        --destination "$database_path" \
        --rollback-backup "$db_snapshot_path" \
        --deployment-transaction-id "$transaction_id" \
        --release-name "$release_name" \
        --release-sha "$expected_sha" \
        --artifact-digest "$expected_digest" \
        --pending-state-hash "$pending_state_hash" \
        --required-score-receipt-id "$required_score_receipt_id" \
        --deployment-lock-fd 9 \
        --apply <&9 > "$report_tmp" || {
      rm -f "$report_tmp"
      return 1
    }
  fi
  chmod 600 "$report_tmp" || {
    rm -f "$report_tmp"
    return 1
  }
  fsync_file "$report_tmp" || {
    rm -f "$report_tmp"
    return 1
  }
  mv "$report_tmp" "$promotion_report_path" || {
    rm -f "$report_tmp"
    return 1
  }
  fsync_directory "$pending_dir" || return 1
  validate_promotion_report || return 1
  append_phase_transition_at "$pending_dir" promoted >/dev/null || return 1
  promotion_completed=1
}

ensure_previous_release_ready_after_rollback() {
  local state_root="${1:-$pending_dir}"
  local state_transaction_id state_pending_state_hash previous_present previous_target
  local previous_revision current_target current_status reloaded_transaction_id
  local reloaded_pending_state_hash reloaded_previous_present reloaded_previous_target
  local reloaded_revision
  local current_present=0
  validate_pending_state_hash_at "$state_root" || return 1
  state_transaction_id="$(read_state_field "$state_root" transaction_id)" || return 1
  validate_transaction_id "$state_transaction_id" || return 1
  state_pending_state_hash="$(
    read_state_field "$state_root" pending_state_hash
  )" || return 1
  validate_pending_state_hash_value "$state_pending_state_hash" || return 1
  previous_present="$(read_state_field "$state_root" previous_current_present)" ||
    return 1
  case "$previous_present" in
    0)
      rollback_readiness_transaction_id="$state_transaction_id"
      rollback_readiness_pending_state_hash="$state_pending_state_hash"
      return 0
      ;;
    1) ;;
    *)
      echo "pending rollback has invalid previous-current state" >&2
      return 1
      ;;
  esac
  previous_target="$(read_state_field "$state_root" previous_current_target)" ||
    return 1
  case "$previous_target" in
    "$releases"/*) ;;
    *)
      echo "pending rollback previous release is outside releases" >&2
      return 1
      ;;
  esac
  if current_target="$(read_current_target)"; then
    current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) current_target= ;;
      *) return 1 ;;
    esac
  fi
  [ "$current_present" -eq 1 ] && [ "$current_target" = "$previous_target" ] || {
    echo "pending rollback previous release is not current" >&2
    return 1
  }
  [ -d "$previous_target" ] && [ ! -L "$previous_target" ] || {
    echo "pending rollback previous release is unavailable" >&2
    return 1
  }
  previous_revision="$(manifest_runtime_revision "$previous_target")" || return 1
  if [ "$rollback_readiness_transaction_id" = "$state_transaction_id" ] &&
    [ "$rollback_readiness_pending_state_hash" = "$state_pending_state_hash" ]; then
    return 0
  fi
  [ "$reconcile_boot_mode" -eq 0 ] || return 2
  if ! restart_service_outside_deploy_lock; then
    echo "failed to restart the previous release after rollback" >&2
    return 1
  fi
  reloaded_transaction_id="$(read_state_field "$state_root" transaction_id)" ||
    return 1
  [ "$reloaded_transaction_id" = "$state_transaction_id" ] || {
    echo "rollback state changed while the previous service restarted" >&2
    return 1
  }
  validate_pending_state_hash_at "$state_root" || return 1
  reloaded_pending_state_hash="$(
    read_state_field "$state_root" pending_state_hash
  )" || return 1
  reloaded_previous_present="$(
    read_state_field "$state_root" previous_current_present
  )" || return 1
  reloaded_previous_target="$(
    read_state_field "$state_root" previous_current_target
  )" || return 1
  [ "$reloaded_pending_state_hash" = "$state_pending_state_hash" ] &&
    [ "$reloaded_previous_present" = "$previous_present" ] &&
    [ "$reloaded_previous_target" = "$previous_target" ] || {
    echo "rollback identity changed while the previous service restarted" >&2
    return 1
  }
  current_target_matches "$previous_target" || {
    echo "current release changed while the previous service restarted" >&2
    return 1
  }
  if ! wait_until_ready 1 "$previous_target" "$previous_revision" 0; then
    echo "previous release did not regain semantic readiness after rollback" >&2
    return 1
  fi
  current_target_matches "$previous_target" || {
    echo "current release changed after rollback readiness succeeded" >&2
    return 1
  }
  reloaded_revision="$(manifest_runtime_revision "$previous_target")" || return 1
  [ "$reloaded_revision" = "$previous_revision" ] || {
    echo "previous release manifest changed during rollback readiness" >&2
    return 1
  }
  rollback_readiness_transaction_id="$state_transaction_id"
  rollback_readiness_pending_state_hash="$state_pending_state_hash"
}

restore_previous_release() {
  local previous_present previous_target candidate_dir current_target
  local current_present=0 current_status readiness_status
  validate_pending_state_hash || return 1
  pending_matches_exact_transaction || {
    echo "pending deployment transaction does not match rollback request" >&2
    return 1
  }
  if [ -e "$pending_dir/verification-authorization.json" ] ||
    [ -L "$pending_dir/verification-authorization.json" ]; then
    recover_verified_authorization_at "$pending_dir" >/dev/null || {
      echo "pending deployment has a malformed verification authorization" >&2
      return 1
    }
    echo "verified deployment cannot be rolled back; commit or reconcile it" >&2
    return 1
  fi
  ensure_pending_finalization_outcome rolled-back || return 1
  candidate_dir="$(read_pending release_dir)" || return 1
  previous_present="$(read_pending previous_current_present)" || return 1
  previous_target="$(read_pending previous_current_target)" || return 1
  case "$previous_present" in
    0)
      [ -z "$previous_target" ] || {
        echo "first-release rollback unexpectedly records a previous release" >&2
        return 1
      }
      ;;
    1)
      case "$previous_target" in
        "$releases"/*) ;;
        *)
          echo "pending rollback previous release is outside releases" >&2
          return 1
          ;;
      esac
      ;;
    *)
      echo "pending rollback has invalid previous-current state" >&2
      return 1
      ;;
  esac
  if current_target="$(read_current_target)"; then
    current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) current_target= ;;
      *) return 1 ;;
    esac
  fi
  [ "$candidate_dir" = "$release_dir" ] || {
    echo "pending release path does not match rollback identity: $candidate_dir" >&2
    return 1
  }
  if [ "$previous_present" = "1" ]; then
    if [ "$current_present" -ne 1 ] ||
      { [ "$current_target" != "$candidate_dir" ] &&
        [ "$current_target" != "$previous_target" ]; }; then
      echo "current release changed while deployment was pending: $current_target" >&2
      return 1
    fi
    if [ "$reconcile_boot_mode" -eq 0 ] &&
      ! "$systemctl_bin" stop "$service_name"; then
      echo "failed to stop the candidate service before database rollback" >&2
      return 1
    fi
    if ! restore_database_snapshot; then
      echo "failed to restore the pre-migration database snapshot" >&2
      return 1
    fi
    if [ "$current_target" = "$candidate_dir" ]; then
      switch_current "$previous_target" || return 1
    fi
  else
    if [ "$current_target" != "$candidate_dir" ] && [ "$current_present" -eq 1 ]; then
      echo "current release changed while deployment was pending: $current_target" >&2
      return 1
    fi
    if [ "$reconcile_boot_mode" -eq 0 ] &&
      ! "$systemctl_bin" stop "$service_name"; then
      echo "failed to stop the service while rolling back the first release" >&2
      return 1
    fi
    if ! restore_database_snapshot; then
      echo "failed to restore the pre-migration database snapshot" >&2
      return 1
    fi
    if [ "$current_target" = "$candidate_dir" ]; then
      rm -f "$current" || return 1
    fi
  fi
  restore_previous_startup_authorization_at "$pending_dir" || return 1

  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_ROLLBACK_BEFORE_FINALIZE \
    rollback-before-finalize || return 1
  write_finalization_record rolled-back || return 1
  if ensure_previous_release_ready_after_rollback "$pending_dir"; then
    :
  else
    readiness_status=$?
    [ "$readiness_status" -eq 2 ] && return 2
    return 1
  fi
  recover_completed_state \
    rolled-back \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" || return 1
  if [ "$recovered_completion" -eq 1 ]; then
    activation_pending_created=0
    activation_switched=0
    db_snapshot_created=0
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE \
      rollback-after-finalize || return 1
    echo "previous release restored" >&2 || return 1
    return 0
  fi
  recover_finalized_state \
    rolled-back \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" || return 1
  if [ "$recovered_finalization" -eq 1 ]; then
    activation_pending_created=0
    activation_switched=0
    db_snapshot_created=0
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE \
      rollback-after-finalize || return 1
    echo "previous release restored" >&2 || return 1
    return 0
  fi
  finalize_pending_state rolled-back >/dev/null || return 1
  activation_pending_created=0
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE \
    rollback-after-finalize || return 1
  recover_finalized_state \
    rolled-back \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" || return 1
  [ "$recovered_finalization" -eq 1 ] || {
    echo "rolled-back deployment finalization was not recovered" >&2
    return 1
  }
  if [ -n "$intent_dir" ] &&
    { [ -e "$intent_dir" ] || [ -L "$intent_dir" ]; }; then
    validate_activation_intent_at "$intent_dir" || return 1
    rm -rf "$intent_dir" || return 1
    fsync_directory "$base" || return 1
  fi
  activation_switched=0
  db_snapshot_created=0
  echo "previous release restored" >&2 || return 1
}

cleanup_activation_files() {
  local cleanup_current_target="${1:-}"
  if [ -n "$next_link" ]; then rm -f "$next_link" || return 1; fi
  if [ -n "$staging_dir" ]; then rm -rf "$staging_dir" || return 1; fi
  if [ "$activation_pending_created" -eq 0 ] && [ "$db_snapshot_created" -eq 1 ]; then
    rm -rf "$db_snapshot_dir" || return 1
    db_snapshot_created=0
  fi
  if [ "$activation_pending_created" -eq 0 ] &&
    [ "$runtime_env_created" -eq 1 ] &&
    [ "$cleanup_current_target" != "$release_dir" ]; then
    rm -f "$runtime_env_path" || return 1
    runtime_env_created=0
  fi
}

activation_exit() {
  local status=$?
  local current_target current_status previous_revision
  local current_present=0 current_identity_known=0 intent_was_pre_pending=0
  trap - EXIT HUP INT TERM
  if [ -n "$intent_dir" ] &&
    { [ -e "$intent_dir" ] || [ -L "$intent_dir" ]; }; then
    if [ ! -e "$pending_dir" ] && [ ! -L "$pending_dir" ]; then
      intent_was_pre_pending=1
    fi
    if ! recover_activation_intents; then
      echo "automatic activation-intent recovery failed" >&2
      status=1
    fi
  fi
  if [ "$intent_was_pre_pending" -eq 1 ]; then
    staging_dir=
    release_created=0
    runtime_env_created=0
    db_snapshot_created=0
    service_stopped_for_promotion=0
  fi
  if current_target="$(read_current_target)"; then
    current_present=1
    current_identity_known=1
  else
    current_status=$?
    case "$current_status" in
      1)
        current_target=
        current_identity_known=1
        ;;
      *)
        echo "activation cleanup cannot determine the current release" >&2
        status=1
        ;;
    esac
  fi
  if [ "$current_identity_known" -eq 1 ]; then
    if ! cleanup_activation_files "$current_target"; then
      echo "activation temporary-file cleanup failed" >&2
      status=1
    fi
  fi
  if [ "$current_identity_known" -eq 1 ] &&
    [ "$current_present" -eq 1 ] &&
    [ "$current_target" = "$release_dir" ]; then
    activation_switched=1
  fi
  if [ "$activation_pending_created" -eq 1 ] && [ "$activation_handoff_complete" -eq 0 ]; then
    if [ "$activation_switched" -eq 1 ] ||
      [ "$promotion_completed" -eq 1 ] ||
      [ "$service_stopped_for_promotion" -eq 1 ]; then
      show_diagnostics
    fi
    if ! restore_previous_release; then
      echo "automatic rollback did not restore a ready previous release" >&2
      status=1
    fi
  elif [ "$activation_handoff_complete" -eq 0 ] &&
    [ "$service_stopped_for_promotion" -eq 1 ]; then
    if ! restart_service_outside_deploy_lock; then
      echo "failed to restart the previous service after pre-pending activation failure" >&2
      status=1
    elif [ "$current_identity_known" -ne 1 ] || [ "$current_present" -ne 1 ]; then
      echo "previous release identity is unavailable after pre-pending activation failure" >&2
      status=1
    elif ! previous_revision="$(manifest_runtime_revision "$current_target")"; then
      echo "previous release manifest is invalid after pre-pending activation failure" >&2
      status=1
    elif ! wait_until_ready 1 "$current_target" "$previous_revision" 0; then
      echo "previous release did not regain readiness after pre-pending activation failure" >&2
      status=1
    fi
    service_stopped_for_promotion=0
    if [ "$current_identity_known" -eq 1 ] &&
      [ "$release_created" -eq 1 ] &&
      [ "$current_target" != "$release_dir" ]; then
      rm -rf "$release_dir" || status=1
      release_created=0
    fi
  elif [ "$activation_handoff_complete" -eq 0 ] &&
    [ "$current_identity_known" -eq 1 ] &&
    [ "$release_created" -eq 1 ] &&
    [ "$current_target" != "$release_dir" ]; then
    rm -rf "$release_dir" || status=1
  fi
  exit "$status"
}

activation_signal() {
  local signal="$1"
  echo "activation interrupted by $signal; rolling back" >&2
  exit 128
}

start_watchdog() {
  if [ "${RADAR_INSTALL_DISABLE_WATCHDOG:-0}" = "1" ]; then return 0; fi
  local script_path script_dir script_dir_input script_name
  local log_path watchdog_pid ready_path attempt
  script_dir_input="$(dirname "$0")" || return 1
  script_dir="$(cd "$script_dir_input" && pwd -P)" || return 1
  script_name="$(basename "$0")" || return 1
  script_path="$script_dir/$script_name"
  [ -f "$script_path" ] && [ ! -L "$script_path" ] || {
    echo "watchdog installer path is not a regular file: $script_path" >&2
    return 1
  }
  log_path="$(mktemp "$watchdog_log_dir/watchdog-${release_name}.XXXXXX.log")" ||
    return 1
  chown "$release_owner:$runtime_group" "$log_path" || {
    rm -f "$log_path" || true
    return 1
  }
  chmod 640 "$log_path" || {
    rm -f "$log_path" || true
    return 1
  }
  ready_path="$(watchdog_ready_path)" || {
    rm -f "$log_path" || true
    return 1
  }
  rm -f "$ready_path" || return 1
  fsync_directory "$watchdog_log_dir" || return 1
  nohup /bin/bash --noprofile --norc -p "$script_path" watchdog \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" \
    </dev/null >"$log_path" 2>&1 9>&- &
  watchdog_pid=$!
  for ((attempt = 1; attempt <= watchdog_ready_attempts; attempt += 1)); do
    if [ -f "$ready_path" ] &&
      validate_watchdog_ready "$ready_path" "$watchdog_pid" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$watchdog_pid" 2>/dev/null; then
      wait "$watchdog_pid" 2>/dev/null || true
      echo "deployment rollback watchdog failed before readiness; see $log_path" >&2
      return 1
    fi
    sleep "$watchdog_ready_sleep_seconds" || {
      kill -TERM "$watchdog_pid" 2>/dev/null || true
      wait "$watchdog_pid" 2>/dev/null || true
      return 1
    }
  done
  kill -TERM "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  echo "deployment rollback watchdog did not acknowledge readiness; see $log_path" >&2
  return 1
}

finalize_pending_state() {
  local outcome="$1"
  local finalized_dir finalized_transaction_id
  [ "$deploy_lock_held" -eq 1 ] || {
    echo "deployment finalization requires the deployment lock" >&2
    return 1
  }
  case "$outcome" in
    committed|rolled-back) ;;
    *)
      echo "invalid deployment finalization outcome: $outcome" >&2
      return 1
      ;;
  esac
  ensure_pending_finalization_outcome "$outcome" || return 1
  write_finalization_record "$outcome" || return 1
  case "$outcome" in
    committed)
      trigger_test_sigkill \
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZATION_RECORD \
        commit-after-finalization-record || return 1
      ;;
    rolled-back)
      trigger_test_sigkill \
        RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZATION_RECORD \
        rollback-after-finalization-record || return 1
      ;;
  esac
  finalized_transaction_id="$(read_pending transaction_id)" || return 1
  finalized_dir="$base/.pending-deploy.finalized-${outcome}-${release_name}-${finalized_transaction_id}"
  [ ! -e "$finalized_dir" ] && [ ! -L "$finalized_dir" ] || {
    echo "finalized pending deployment path already exists: $finalized_dir" >&2
    return 1
  }
  mv "$pending_dir" "$finalized_dir" || return 1
  fsync_directory "$base" || return 1
  printf '%s\n' "$finalized_dir" || return 1
}

activate_release() {
  upload_tarball="${2:?tarball path required}"
  release_name="${3:?release name required}"
  expected_sha="${4:?GitHub SHA required}"
  expected_digest="${5:?artifact digest required}"
  transaction_id="${6:-}"
  quality_database_path="${7:-}"
  required_score_receipt_id="${8:-}"
  if [ -n "$quality_database_path" ] || [ -n "$required_score_receipt_id" ]; then
    [ -n "$quality_database_path" ] && [ -n "$required_score_receipt_id" ] || {
      echo "quality database and score receipt ID must be supplied together" >&2
      exit 1
    }
    promotion_required=1
  else
    [ "${RADAR_INSTALL_ALLOW_CODE_ONLY_ACTIVATION:-0}" = "1" ] || {
      echo "production activation requires a quality database and exact score receipt ID" >&2
      exit 1
    }
    [ "${RADAR_INSTALL_TEST_MODE:-0}" = "1" ] &&
      [[ "${RADAR_INSTALL_TEST_NONCE:-}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "code-only activation is restricted to explicit installer test mode" >&2
      exit 1
    }
  fi
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  validate_common_runtime || exit 1
  validate_auto_refresh_disabled || exit 1
  resolve_database_path || exit 1
  if [ "$promotion_required" -eq 1 ]; then
    resolve_quality_database_path "$quality_database_path" || exit 1
    validate_promotion_preflight || exit 1
  fi
  acquire_deploy_lock || exit 1
  recover_finalized_state || exit 1
  recover_activation_intents || exit 1
  ensure_transaction_id_unused || exit 1
  [[ "$upload_tarball" == /* ]] || {
    echo "release upload path must be absolute: $upload_tarball" >&2
    exit 1
  }
  [ -f "$upload_tarball" ] && [ ! -L "$upload_tarball" ] || {
    echo "tarball not found as a regular non-symlink file: $upload_tarball" >&2
    exit 1
  }
  tarball="$(transaction_tarball_path "$transaction_id")" || exit 1
  validate_transaction_tarball_path_value \
    "$tarball" \
    "$transaction_id" \
    "activation" || exit 1
  local upload_identity
  upload_identity="$(inspect_upload_tarball "$upload_tarball")" || exit 1
  tarball_sha256="${upload_identity%% *}"
  tarball_size_bytes="${upload_identity#* }"
  [[ "$tarball_sha256" =~ ^[0-9a-f]{64}$ ]] &&
    [[ "$tarball_size_bytes" =~ ^[1-9][0-9]*$ ]] || {
    echo "release upload digest identity is invalid" >&2
    exit 1
  }
  [ ! -e "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
    echo "another deployment is pending commit or rollback: $pending_dir" >&2
    exit 1
  }

  trap activation_exit EXIT
  trap 'activation_signal HUP' HUP
  trap 'activation_signal INT' INT
  trap 'activation_signal TERM' TERM

  local previous_current_target previous_current_present
  local release_preexisting runtime_env_preexisting
  previous_current_target=
  previous_current_present=0
  local current_status
  if previous_current_target="$(read_current_target)"; then
    case "$previous_current_target" in
      "$releases"/*) ;;
      *)
        echo "current symlink points outside the releases directory: $previous_current_target" >&2
        exit 1
        ;;
    esac
    [ -d "$previous_current_target" ] || {
      echo "current symlink target is not a release directory: $previous_current_target" >&2
      exit 1
    }
    previous_current_present=1
  else
    current_status=$?
    case "$current_status" in
      1) previous_current_target= ;;
      *) exit 1 ;;
    esac
  fi
  release_preexisting=0
  runtime_env_preexisting=0
  if [ -e "$release_dir" ] || [ -L "$release_dir" ]; then
    release_preexisting=1
  fi
  if [ -e "$runtime_env_path" ] || [ -L "$runtime_env_path" ]; then
    runtime_env_preexisting=1
  fi
  staging_dir="$releases/.${release_name}.staging-${transaction_id}"
  write_activation_intent \
    "$previous_current_present" \
    "$previous_current_target" \
    "$release_preexisting" \
    "$runtime_env_preexisting" || exit 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_BEFORE_ARTIFACT_ADOPTION \
    before-artifact-adoption || exit 1
  adopt_upload_tarball || exit 1
  validate_owned_tarball_file \
    "$tarball" \
    "$tarball_sha256" \
    "$tarball_size_bytes" \
    "$transaction_id" \
    "activation" || exit 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_AFTER_ARTIFACT_ADOPTION \
    after-artifact-adoption || exit 1
  validate_release_archive "$tarball" || exit 1
  install -d -m 700 -o "$release_owner" -g "$release_group" "$staging_dir" ||
    exit 1
  tar --no-same-owner --no-same-permissions -xzf "$tarball" -C "$staging_dir" ||
    exit 1
  validate_release_tree_containment "$staging_dir" 0 || exit 1
  write_runtime_env || exit 1
  ln -s "$runtime_env_path" "$staging_dir/.env" || exit 1
  seal_release_tree "$staging_dir" || exit 1
  fsync_tree "$staging_dir" || exit 1

  validate_runtime_env_link "$staging_dir" || exit 1
  local staging_digest
  staging_digest="$(release_digest "$staging_dir")" || exit 1
  validate_manifest_file "$staging_dir" "$staging_digest" || exit 1
  validate_runtime "$staging_dir" || exit 1

  if [ -e "$release_dir" ] || [ -L "$release_dir" ]; then
    [ -d "$release_dir" ] && [ ! -L "$release_dir" ] || {
      echo "existing release path is not a directory: $release_dir" >&2
      exit 1
    }
    validate_release_tree_containment "$release_dir" 1 "$runtime_env_path" ||
      exit 1
    local existing_digest
    existing_digest="$(release_digest "$release_dir")" || exit 1
    if [ "$existing_digest" != "$expected_digest" ]; then
      echo "release already exists with different contents: $release_dir" >&2
      exit 1
    fi
    validate_runtime_env_link "$release_dir" || exit 1
    validate_manifest_file "$release_dir" || exit 1
    validate_runtime "$release_dir" || exit 1
    rm -rf "$staging_dir" || exit 1
    staging_dir=
  else
    "$node_bin" - "$staging_dir" "$release_dir" <<'NODE' || exit 1
const fs = require('node:fs');
fs.renameSync(process.argv[2], process.argv[3]);
NODE
    fsync_directory "$releases" || exit 1
    staging_dir=
    release_created=1
  fi

  seal_release_tree "$release_dir" || exit 1

  if [ "$promotion_required" -eq 1 ]; then
    if ! "$systemctl_bin" stop "$service_name"; then
      echo "failed to stop the previous service before database snapshot" >&2
      exit 1
    fi
    service_stopped_for_promotion=1
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_AFTER_PROMOTION_STOP \
      after-promotion-stop || exit 1
  fi
  snapshot_database || exit 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_AFTER_SNAPSHOT \
    after-database-snapshot || exit 1
  validate_owned_tarball_file \
    "$tarball" \
    "$tarball_sha256" \
    "$tarball_size_bytes" \
    "$transaction_id" \
    "activation" || exit 1
  write_pending_state "$previous_current_present" "$previous_current_target" || exit 1
  start_watchdog || exit 1
  validate_activation_intent_at "$intent_dir" || exit 1
  rm -rf "$intent_dir" || exit 1
  fsync_directory "$base" || exit 1
  activation_intent_created=0
  trigger_test_sigkill RADAR_TEST_SIGKILL_AFTER_PENDING after-pending || exit 1
  if [ "$promotion_required" -eq 1 ]; then
    run_quality_promotion || exit 1
    trigger_test_sigkill \
      RADAR_TEST_SIGKILL_AFTER_PROMOTION \
      after-promotion || exit 1
  fi
  switch_current "$release_dir" || exit 1
  activation_switched=1
  append_phase_transition_at "$pending_dir" activated >/dev/null || exit 1
  write_pending_startup_authorization || exit 1
  trigger_test_sigkill RADAR_TEST_SIGKILL_AFTER_SWITCH after-switch || exit 1

  if ! restart_service_outside_deploy_lock; then
    echo "service restart failed for release $release_name" >&2
    exit 1
  fi
  validate_pending_state_hash || exit 1
  pending_matches_exact_transaction || {
    echo "candidate restart changed the pending deployment transaction" >&2
    exit 1
  }
  current_target_matches "$release_dir" || {
    echo "candidate restart changed the activated current release" >&2
    exit 1
  }
  local pending_phase
  pending_phase="$(current_pending_phase)" || exit 1
  [ "$pending_phase" = "activated" ] || {
    echo "candidate restart changed the activated deployment phase" >&2
    exit 1
  }
  if ! wait_until_ready 1; then
    echo "release $release_name did not reach exact semantic readiness" >&2
    exit 1
  fi

  activation_handoff_complete=1
  local activation_phase_tip activation_phase_hash
  activation_phase_tip="$(current_phase_transition_at "$pending_dir")" || exit 1
  activation_phase_hash="${activation_phase_tip#* }"
  "$node_bin" - \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" \
    "$activation_phase_hash" <<'NODE' || exit 1
const [
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash,
  deadlineEpoch,
  phaseTransitionHash,
] = process.argv.slice(2);
process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  status: 'pending_verification',
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash,
  deadlineEpoch: Number(deadlineEpoch),
  phaseTransitionHash,
})}\n`);
NODE
}

authorize_release() {
  release_name="${2:?release name required}"
  expected_sha="${3:?GitHub SHA required}"
  expected_digest="${4:?artifact digest required}"
  transaction_id="${5:?transaction ID required}"
  verification_id="${6:?verification ID required}"
  verification_attestation="${7:?verifier attestation required}"
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  validate_verification_id "$verification_id" || exit 1
  [[ "$verification_attestation" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid deployment verifier attestation" >&2
    exit 1
  }
  validate_common_runtime || exit 1
  validate_auto_refresh_disabled || exit 1
  resolve_database_path || exit 1
  acquire_deploy_lock || exit 1
  recover_activation_intents || exit 1
  [ ! -e "$intent_dir" ] && [ ! -L "$intent_dir" ] || {
    echo "deployment watchdog arming is incomplete; authorization is forbidden" >&2
    exit 1
  }
  pending_matches_requested_transaction || {
    echo "no matching exact deployment transaction is pending authorization" >&2
    exit 1
  }
  ensure_pending_finalization_outcome committed || exit 1
  load_pending_transaction || exit 1
  validate_promotion_report || exit 1
  current_target_matches "$release_dir" || {
    echo "current release does not match pending authorization: $release_dir" >&2
    exit 1
  }
  local deadline_current
  deadline_current="$("$node_bin" -e '
    const deadline = Number(process.argv[1]);
    process.stdout.write(String(
      Number.isSafeInteger(deadline) && deadline >= Math.floor(Date.now() / 1000),
    ));
  ' "$pending_deadline_epoch")" || exit 1
  [ "$deadline_current" = "true" ] || {
    echo "pending deployment deadline expired; authorization is forbidden" >&2
    exit 1
  }
  wait_until_ready 1 || {
    echo "release $release_name lost exact readiness before authorization" >&2
    exit 1
  }
  local authorization_hash authorized_verification_id verification_phase_tip
  authorization_hash="$(write_verification_authorization)" || exit 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_AFTER_AUTHORIZATION_RECORD \
    after-authorization-record || exit 1
  recover_verified_authorization_at \
    "$pending_dir" \
    "$verification_id" \
    authorized_verification_id || exit 1
  [ "$authorized_verification_id" = "$verification_id" ] || {
    echo "deployment verification identity changed during journal recovery" >&2
    exit 1
  }
  verification_phase_tip="$(current_phase_transition_at "$pending_dir")" || exit 1
  "$node_bin" - \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" \
    "$verification_id" \
    "$authorization_hash" \
    "${verification_phase_tip#* }" <<'NODE' || exit 1
const [
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash,
  deadlineEpoch,
  verificationId,
  authorizationHash,
  phaseTransitionHash,
] = process.argv.slice(2);
process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  status: 'verified',
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash,
  deadlineEpoch: Number(deadlineEpoch),
  phase: 'verified',
  phaseTransitionHash,
  verificationId,
  authorizationHash,
})}\n`);
NODE
}

load_status_identity_at() {
  local state_root="$1"
  local state_kind="${2:-deployment}"
  release_name="$(read_state_field "$state_root" release_name)" || return 1
  expected_sha="$(read_state_field "$state_root" github_sha)" || return 1
  expected_digest="$(read_state_field "$state_root" artifact_digest)" || return 1
  transaction_id="$(read_state_field "$state_root" transaction_id)" || return 1
  validate_release_identity_values \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" || return 1
  validate_transaction_id "$transaction_id" || return 1
  if [ "$state_kind" = "intent" ]; then
    pending_state_hash=
    pending_deadline_epoch=
    return 0
  fi
  [ "$state_kind" = "deployment" ] || {
    echo "invalid deployment status state kind: $state_kind" >&2
    return 1
  }
  pending_state_hash="$(read_state_field "$state_root" pending_state_hash)" ||
    return 1
  pending_deadline_epoch="$(read_state_field "$state_root" deadline_epoch)" ||
    return 1
  validate_pending_state_hash_value "$pending_state_hash" || return 1
  [[ "$pending_deadline_epoch" =~ ^[1-9][0-9]*$ ]] || {
    echo "deployment status state has an invalid deadline" >&2
    return 1
  }
}

emit_deployment_status() {
  local status="$1"
  local outcome="${2:-}"
  local phase="${3:-}"
  local authorized="${4:-false}"
  local status_verification_id="${5:-}"
  local status_phase_hash="${6:-}"
  "$node_bin" - \
    "$status" \
    "$outcome" \
    "$phase" \
    "$authorized" \
    "$status_verification_id" \
    "$status_phase_hash" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    "$pending_deadline_epoch" <<'NODE' || return 1
const [
  status,
  outcome,
  phase,
  authorizedText,
  verificationId,
  phaseTransitionHash,
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash,
  deadlineEpochText,
] = process.argv.slice(2);
const deadlineEpoch = deadlineEpochText ? Number(deadlineEpochText) : null;
process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  status,
  outcome: outcome || null,
  phase: phase || null,
  authorized: authorizedText === 'true',
  verificationId: verificationId || null,
  phaseTransitionHash: phaseTransitionHash || null,
  releaseName,
  releaseSha,
  artifactDigest,
  transactionId,
  pendingStateHash: pendingStateHash || null,
  deadlineEpoch: Number.isSafeInteger(deadlineEpoch) ? deadlineEpoch : null,
})}\n`);
NODE
}

status_release() {
  release_name="${2:?release name required}"
  expected_sha="${3:?GitHub SHA required}"
  expected_digest="${4:?artifact digest required}"
  transaction_id="${5:?transaction ID required}"
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  validate_common_runtime || exit 1
  resolve_database_path || exit 1
  acquire_deploy_lock || exit 1

  local recorded_outcome phase phase_tip phase_hash status_verification_id=
  local pending_match_status finalized_transaction_id finalized_release_name
  local finalized_release_sha finalized_artifact_digest expected_finalized_dir
  local intent_transaction_id intent_release_name intent_release_sha intent_artifact_digest

  recover_completed_state \
    "" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "" \
    0 || exit 1
  if [ "$recovered_completion" -eq 1 ]; then
    case "$recovered_completion_outcome" in
      committed)
        emit_deployment_status committed committed || exit 1
        ;;
      rolled-back)
        emit_deployment_status rolled_back rolled-back || exit 1
        ;;
      *)
        echo "deployment completion recovery returned an invalid outcome" >&2
        exit 1
        ;;
    esac
    return 0
  fi
  find_finalized_state || exit 1
  if [ -n "$finalized_state_dir" ]; then
    recorded_outcome="$(validate_finalization_record_at "$finalized_state_dir")" ||
      exit 1
    finalized_transaction_id="$(
      read_state_field "$finalized_state_dir" transaction_id
    )" || exit 1
    finalized_release_name="$(
      read_state_field "$finalized_state_dir" release_name
    )" || exit 1
    finalized_release_sha="$(
      read_state_field "$finalized_state_dir" github_sha
    )" || exit 1
    finalized_artifact_digest="$(
      read_state_field "$finalized_state_dir" artifact_digest
    )" || exit 1
    validate_transaction_id "$finalized_transaction_id" || exit 1
    validate_release_identity_values \
      "$finalized_release_name" \
      "$finalized_release_sha" \
      "$finalized_artifact_digest" || exit 1
    expected_finalized_dir="$base/.pending-deploy.finalized-${recorded_outcome}-${finalized_release_name}-${finalized_transaction_id}"
    [ "$finalized_state_dir" = "$expected_finalized_dir" ] || {
      echo "finalized deployment marker name does not match its identity" >&2
      exit 1
    }
    if [ "$finalized_transaction_id" = "$transaction_id" ]; then
      [ "$finalized_release_name" = "$release_name" ] &&
        [ "$finalized_release_sha" = "$expected_sha" ] &&
        [ "$finalized_artifact_digest" = "$expected_digest" ] || {
        echo "deployment transaction ID is bound to a different finalized identity" >&2
        exit 1
      }
      if [ "$recorded_outcome" = "committed" ]; then
        emit_deployment_status commit_decided committed || exit 1
      else
        emit_deployment_status rollback_decided rolled-back || exit 1
      fi
      return 0
    fi
  fi

  if [ -n "$intent_dir" ] &&
    { [ -e "$intent_dir" ] || [ -L "$intent_dir" ]; }; then
    validate_activation_intent_at "$intent_dir" || exit 1
    intent_transaction_id="$(read_state_field "$intent_dir" transaction_id)" || exit 1
    intent_release_name="$(read_state_field "$intent_dir" release_name)" || exit 1
    intent_release_sha="$(read_state_field "$intent_dir" github_sha)" || exit 1
    intent_artifact_digest="$(read_state_field "$intent_dir" artifact_digest)" ||
      exit 1
    [ "$intent_transaction_id" = "$transaction_id" ] &&
      [ "$intent_release_name" = "$release_name" ] &&
      [ "$intent_release_sha" = "$expected_sha" ] &&
      [ "$intent_artifact_digest" = "$expected_digest" ] || {
      echo "deployment activation intent does not match the requested transaction" >&2
      exit 1
    }
    pending_state_hash=
    pending_deadline_epoch=
    emit_deployment_status preparing "" preparing || exit 1
    return 0
  fi

  if [ -e "$pending_dir" ] || [ -L "$pending_dir" ]; then
    [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
      echo "pending deployment path is not a regular directory: $pending_dir" >&2
      exit 1
    }
    if pending_matches_requested_transaction; then
      load_pending_transaction || exit 1
      validate_pending_state_hash || exit 1
      phase_tip="$(current_phase_transition_at "$pending_dir")" || exit 1
      phase="${phase_tip%% *}"
      phase_hash="${phase_tip#* }"
      if [ -e "$pending_dir/finalization.json" ] ||
        [ -L "$pending_dir/finalization.json" ]; then
        recorded_outcome="$(validate_finalization_record_at "$pending_dir")" || exit 1
        if [ "$recorded_outcome" = "committed" ]; then
          emit_deployment_status \
            commit_decided committed "$phase" false "" "$phase_hash" || exit 1
        else
          emit_deployment_status \
            rollback_decided rolled-back "$phase" false "" "$phase_hash" || exit 1
        fi
        return 0
      fi
      if [ -e "$pending_dir/verification-authorization.json" ] ||
        [ -L "$pending_dir/verification-authorization.json" ]; then
        status_verification_id="$(recover_verified_authorization_at "$pending_dir")" ||
          exit 1
        phase_tip="$(current_phase_transition_at "$pending_dir")" || exit 1
        phase="${phase_tip%% *}"
        phase_hash="${phase_tip#* }"
        emit_deployment_status \
          verified \
          "" \
          "$phase" \
          true \
          "$status_verification_id" \
          "$phase_hash" || exit 1
        return 0
      fi
      emit_deployment_status \
        pending_verification \
        "" \
        "$phase" \
        false \
        "" \
        "$phase_hash" || exit 1
      return 0
    else
      pending_match_status=$?
      [ "$pending_match_status" -eq 1 ] || exit 1
    fi
  fi

  pending_state_hash=
  pending_deadline_epoch=
  emit_deployment_status not_found || exit 1
}

commit_release() {
  release_name="${2:?release name required}"
  expected_sha="${3:?GitHub SHA required}"
  expected_digest="${4:?artifact digest required}"
  transaction_id="${5:?transaction ID required}"
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  validate_common_runtime || exit 1
  validate_auto_refresh_disabled || exit 1
  resolve_database_path || exit 1
  acquire_deploy_lock || exit 1
  recover_activation_intents || exit 1
  [ ! -e "$intent_dir" ] && [ ! -L "$intent_dir" ] || {
    echo "deployment watchdog arming is incomplete; commit is forbidden" >&2
    exit 1
  }
  recover_completed_state \
    committed \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" || exit 1
  if [ "$recovered_completion" -eq 1 ]; then
    echo "release $release_name committed" || return 1
    return 0
  fi
  recover_finalized_state \
    committed \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" || exit 1
  if [ "$recovered_finalization" -eq 1 ]; then
    echo "release $release_name committed" || return 1
    return 0
  fi
  pending_matches_requested_transaction || {
    echo "no matching exact deployment transaction is pending commit" >&2
    exit 1
  }
  validate_pending_state_hash || exit 1
  if [ -e "$pending_dir/finalization.json" ] ||
    [ -L "$pending_dir/finalization.json" ]; then
    local recorded_outcome
    recorded_outcome="$(validate_finalization_record_at "$pending_dir")" || exit 1
    [ "$recorded_outcome" = "committed" ] || {
      echo "pending deployment has a contradictory rollback decision" >&2
      exit 1
    }
    finalize_pending_state committed >/dev/null || exit 1
    recover_finalized_state \
      committed \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    [ "$recovered_finalization" -eq 1 ] || {
      echo "pending commit decision did not reach a completion receipt" >&2
      exit 1
    }
    echo "release $release_name committed" || return 1
    return 0
  fi
  ensure_pending_finalization_outcome committed || exit 1
  load_pending_transaction || exit 1
  validate_promotion_report || exit 1
  recover_verified_authorization_at "$pending_dir" >/dev/null || exit 1
  current_target_matches "$release_dir" || {
    echo "current release does not match pending commit: $release_dir" >&2
    exit 1
  }
  validate_manifest_file "$release_dir" || exit 1
  validate_runtime_env_link "$release_dir" || exit 1
  wait_until_ready 1 || {
    echo "release $release_name lost exact readiness before commit" >&2
    exit 1
  }
  finalize_pending_state committed >/dev/null || exit 1
  trigger_test_sigkill \
    RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE \
    commit-after-finalize || exit 1
  recover_finalized_state \
    committed \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" || exit 1
  [ "$recovered_finalization" -eq 1 ] || {
    echo "committed deployment finalization was not recovered" >&2
    exit 1
  }
  db_snapshot_created=0
  echo "release $release_name committed" || return 1
}

rollback_release() {
  release_name="${2:?release name required}"
  expected_sha="${3:?GitHub SHA required}"
  expected_digest="${4:?artifact digest required}"
  transaction_id="${5:?transaction ID required}"
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  validate_common_runtime || exit 1
  resolve_database_path || exit 1
  acquire_deploy_lock || exit 1
  recover_activation_intents || exit 1
  recover_completed_state \
    rolled-back \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" || exit 1
  if [ "$recovered_completion" -eq 1 ]; then
    echo "previous release restored" >&2 || return 1
    return 0
  fi
  recover_finalized_state \
    rolled-back \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" || exit 1
  if [ "$recovered_finalization" -eq 1 ]; then
    echo "previous release restored" >&2 || return 1
    return 0
  fi
  if [ ! -e "$pending_dir" ] && [ ! -L "$pending_dir" ]; then
    echo "no deployment is pending rollback" || return 1
    return 0
  fi
  [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
    echo "pending deployment path is not a regular directory: $pending_dir" >&2
    exit 1
  }
  pending_matches_requested_transaction || {
    echo "no matching exact deployment transaction is pending rollback" >&2
    exit 1
  }
  if [ -e "$pending_dir/finalization.json" ] ||
    [ -L "$pending_dir/finalization.json" ]; then
    local recorded_outcome
    recorded_outcome="$(validate_finalization_record_at "$pending_dir")" || exit 1
    [ "$recorded_outcome" = "rolled-back" ] || {
      echo "pending deployment has a contradictory commit decision" >&2
      exit 1
    }
    load_pending_transaction || exit 1
    ensure_previous_release_ready_after_rollback "$pending_dir" || exit 1
    recover_completed_state \
      rolled-back \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    if [ "$recovered_completion" -eq 1 ]; then
      echo "previous release restored" >&2 || return 1
      return 0
    fi
    recover_finalized_state \
      rolled-back \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    if [ "$recovered_finalization" -eq 1 ]; then
      echo "previous release restored" >&2 || return 1
      return 0
    fi
    finalize_pending_state rolled-back >/dev/null || exit 1
    recover_finalized_state \
      rolled-back \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    [ "$recovered_finalization" -eq 1 ] || {
      echo "pending rollback decision did not reach a completion receipt" >&2
      exit 1
    }
    echo "previous release restored" >&2 || return 1
    return 0
  fi
  load_pending_transaction || exit 1
  restore_previous_release || exit 1
}

reconcile_release() {
  local boot_mode=0
  local recorded_outcome deadline_current pending_phase recovery_status
  if [ "${2:-}" = "--boot" ]; then
    boot_mode=1
    reconcile_boot_mode=1
  elif [ -n "${2:-}" ]; then
    echo "unknown reconcile option: ${2:-}" >&2
    exit 2
  fi

  validate_common_runtime || exit 1
  validate_auto_refresh_disabled || exit 1
  resolve_database_path || exit 1
  acquire_deploy_lock || exit 1
  if recover_activation_intents; then
    :
  else
    recovery_status=$?
    if [ "$recovery_status" -eq 2 ]; then
      load_status_identity_at "$deferred_state_dir" intent || exit 1
      emit_deployment_status \
        rollback_decided rolled-back preparing || exit 1
      return 0
    fi
    exit 1
  fi
  if recover_finalized_state; then
    :
  else
    recovery_status=$?
    if [ "$recovery_status" -eq 2 ]; then
      load_status_identity_at "$finalized_state_dir" || exit 1
      emit_deployment_status rollback_decided rolled-back || exit 1
      return 0
    fi
    exit 1
  fi
  if [ "$recovered_finalization" -eq 1 ]; then
    "$node_bin" -e \
      'process.stdout.write(`${JSON.stringify({schemaVersion:1,status:"recovered_finalization"})}\n`)' ||
      exit 1
    return 0
  fi
  if [ ! -e "$pending_dir" ] && [ ! -L "$pending_dir" ]; then
    "$node_bin" -e \
      'process.stdout.write(`${JSON.stringify({schemaVersion:1,status:"no_pending_transaction"})}\n`)' ||
      exit 1
    return 0
  fi
  [ -d "$pending_dir" ] && [ ! -L "$pending_dir" ] || {
    echo "pending deployment path is not a regular directory: $pending_dir" >&2
    exit 1
  }

  release_name="$(read_pending release_name)" || exit 1
  expected_sha="$(read_pending github_sha)" || exit 1
  expected_digest="$(read_pending artifact_digest)" || exit 1
  transaction_id="$(read_pending transaction_id)" || exit 1
  promotion_required="$(read_pending promotion_required)" || exit 1
  quality_database_path="$(read_pending quality_database_path)" || exit 1
  required_score_receipt_id="$(read_pending required_score_receipt_id)" || exit 1
  tarball="$(read_pending tarball)" || exit 1
  validate_release_identity || exit 1
  validate_transaction_id "$transaction_id" || exit 1
  load_pending_transaction || exit 1
  validate_pending_state_hash || exit 1
  pending_matches_exact_transaction || {
    echo "pending deployment does not match its exact transaction identity" >&2
    exit 1
  }

  if [ -e "$pending_dir/finalization.json" ] || [ -L "$pending_dir/finalization.json" ]; then
    recorded_outcome="$(validate_finalization_record_at "$pending_dir")" || exit 1
    if [ "$recorded_outcome" = "rolled-back" ]; then
      if ensure_previous_release_ready_after_rollback "$pending_dir"; then
        :
      else
        recovery_status=$?
        if [ "$recovery_status" -eq 2 ]; then
          emit_deployment_status rollback_decided rolled-back || exit 1
          return 0
        fi
        exit 1
      fi
      recover_completed_state \
        rolled-back \
        "$release_name" \
        "$expected_sha" \
        "$expected_digest" \
        "$transaction_id" \
        "$pending_state_hash" || exit 1
      if [ "$recovered_completion" -eq 1 ]; then
        emit_deployment_status rolled_back rolled-back || exit 1
        return 0
      fi
      recover_finalized_state \
        rolled-back \
        "$release_name" \
        "$expected_sha" \
        "$expected_digest" \
        "$transaction_id" \
        "$pending_state_hash" || exit 1
      if [ "$recovered_finalization" -eq 1 ]; then
        emit_deployment_status rolled_back rolled-back || exit 1
        return 0
      fi
    fi
    finalize_pending_state "$recorded_outcome" >/dev/null || exit 1
    recover_finalized_state \
      "$recorded_outcome" \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    [ "$recovered_finalization" -eq 1 ] || {
      echo "deployment decision recovery did not reach a terminal receipt" >&2
      exit 1
    }
    if [ "$recorded_outcome" = "committed" ]; then
      emit_deployment_status committed committed || exit 1
    else
      emit_deployment_status rolled_back rolled-back || exit 1
    fi
    return 0
  fi

  if [ -e "$pending_dir/verification-authorization.json" ] ||
    [ -L "$pending_dir/verification-authorization.json" ]; then
    local authorized_verification_id
    recover_verified_authorization_at \
      "$pending_dir" \
      "" \
      authorized_verification_id || exit 1
    validate_promotion_report || exit 1
    current_target_matches "$release_dir" || {
      echo "verified deployment current release does not match its transaction" >&2
      exit 1
    }
    validate_manifest_file "$release_dir" || exit 1
    validate_runtime_env_link "$release_dir" || exit 1
    write_pending_startup_authorization || exit 1
    if [ "$boot_mode" -eq 1 ]; then
      pending_phase="$(current_pending_phase)" || exit 1
      emit_deployment_status \
        verified \
        "" \
        "$pending_phase" \
        true \
        "$authorized_verification_id" || exit 1
      return 0
    fi
    wait_until_ready 1 || {
      echo "verified deployment is not ready; leaving its commit decision pending" >&2
      exit 1
    }
    finalize_pending_state committed >/dev/null || exit 1
    recover_finalized_state \
      committed \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    [ "$recovered_finalization" -eq 1 ] || {
      echo "verified deployment reconciliation did not reach a committed receipt" >&2
      exit 1
    }
    emit_deployment_status committed committed || exit 1
    return 0
  fi

  if [ -n "$intent_dir" ] &&
    { [ -e "$intent_dir" ] || [ -L "$intent_dir" ]; }; then
    echo "deployment watchdog arming was interrupted; reconciling rollback" >&2
    if restore_previous_release; then
      emit_deployment_status rolled_back rolled-back || exit 1
    else
      recovery_status=$?
      if [ "$recovery_status" -eq 2 ]; then
        emit_deployment_status rollback_decided rolled-back || exit 1
        return 0
      fi
      exit 1
    fi
    return 0
  fi

  deadline_current="$("$node_bin" -e '
    const deadline = Number(process.argv[1]);
    process.stdout.write(String(
      Number.isSafeInteger(deadline) && deadline >= Math.floor(Date.now() / 1000),
    ));
  ' "$pending_deadline_epoch")" || exit 1
  if [ "$deadline_current" = "true" ] && [ "$boot_mode" -eq 0 ]; then
    local status_verification_id=
    if [ -e "$pending_dir/verification-authorization.json" ] ||
      [ -L "$pending_dir/verification-authorization.json" ]; then
      status_verification_id="$(recover_verified_authorization_at "$pending_dir")" ||
        exit 1
      pending_phase="$(current_pending_phase)" || exit 1
      emit_deployment_status \
        verified "" "$pending_phase" true "$status_verification_id" || exit 1
    else
      pending_phase="$(current_pending_phase)" || exit 1
      emit_deployment_status pending_verification "" "$pending_phase" || exit 1
    fi
    return 0
  fi

  if [ "$deadline_current" = "true" ] && [ "$boot_mode" -eq 1 ]; then
    pending_phase="$(current_pending_phase)" || exit 1
    if [ "$pending_phase" = "activated" ] &&
      current_target_matches "$release_dir" &&
      validate_manifest_file "$release_dir" &&
      validate_runtime_env_link "$release_dir" &&
      validate_promotion_report; then
      write_pending_startup_authorization || exit 1
      emit_deployment_status \
        pending_verification \
        "" \
        "$pending_phase" \
        false || exit 1
      return 0
    fi
    echo \
      "boot reconciliation found an invalid or incomplete unverified deployment; " \
      "rolling back $transaction_id" \
      >&2
  elif [ "$boot_mode" -eq 1 ]; then
    echo "boot reconciliation found expired deployment $transaction_id; rolling back" >&2
  else
    echo "deployment deadline expired; reconciling rollback for $transaction_id" >&2
  fi
  if restore_previous_release; then
    emit_deployment_status rolled_back rolled-back || exit 1
  else
    recovery_status=$?
    if [ "$recovery_status" -eq 2 ]; then
      emit_deployment_status rollback_decided rolled-back || exit 1
      return 0
    fi
    exit 1
  fi
}

watchdog_release() {
  release_name="${2:?release name required}"
  expected_sha="${3:?GitHub SHA required}"
  expected_digest="${4:?artifact digest required}"
  transaction_id="${5:?transaction ID required}"
  pending_state_hash="${6:?pending state hash required}"
  pending_deadline_epoch="${7:?pending deadline epoch required}"
  [[ "$transaction_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    echo "invalid watchdog transaction ID" >&2
    exit 1
  }
  [[ "$pending_state_hash" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid watchdog pending state hash" >&2
    exit 1
  }
  [[ "$pending_deadline_epoch" =~ ^[1-9][0-9]*$ ]] || {
    echo "invalid watchdog pending deadline" >&2
    exit 1
  }
  trap watchdog_exit EXIT
  validate_release_identity || exit 1
  validate_common_runtime || exit 1
  resolve_database_path || exit 1
  local remaining_seconds pending_status
  if watchdog_pending_matches_exact; then
    :
  else
    pending_status=$?
    case "$pending_status" in
      1|3)
        publish_watchdog_terminal_record superseded || exit 1
        return 0
        ;;
      2) exit 1 ;;
      *)
        echo "watchdog pending-state classification failed" >&2
        exit 1
        ;;
    esac
  fi
  write_watchdog_record ready ready "${BASHPID:-$$}" >/dev/null || exit 1
  remaining_seconds="$(
    "$node_bin" -e '
      const deadline = Number(process.argv[1]);
      if (!Number.isSafeInteger(deadline) || deadline <= 0) process.exit(1);
      process.stdout.write(String(Math.max(0, deadline - Math.floor(Date.now() / 1000))));
    ' "$pending_deadline_epoch"
  )" || exit 1
  if [ "$remaining_seconds" -gt 0 ]; then
    sleep "$remaining_seconds" || exit 1
  fi
  acquire_deploy_lock || exit 1
  if watchdog_pending_matches_exact; then
    :
  else
    pending_status=$?
    case "$pending_status" in
      1)
        publish_watchdog_terminal_record superseded || exit 1
        return 0
        ;;
      2) exit 1 ;;
      3)
        recover_watchdog_terminal_state || exit 1
        [ "$recovered_completion" -eq 1 ] || {
          echo "watchdog pending state disappeared without an exact completion receipt" >&2
          exit 1
        }
        case "$recovered_completion_outcome" in
          committed) publish_watchdog_terminal_record completed || exit 1 ;;
          rolled-back) publish_watchdog_terminal_record rolled-back || exit 1 ;;
          *)
            echo "watchdog recovered an invalid completion outcome" >&2
            exit 1
            ;;
        esac
        return 0
        ;;
      *)
        echo "watchdog pending-state classification failed" >&2
        exit 1
        ;;
    esac
  fi
  load_pending_transaction || exit 1
  validate_pending_state_hash || exit 1
  if [ -n "$intent_dir" ] &&
    { [ -e "$intent_dir" ] || [ -L "$intent_dir" ]; }; then
    validate_activation_intent_at "$intent_dir" || exit 1
    rm -rf "$intent_dir" || exit 1
    fsync_directory "$base" || exit 1
  fi
  if [ -e "$pending_dir/verification-authorization.json" ] ||
    [ -L "$pending_dir/verification-authorization.json" ]; then
    recover_verified_authorization_at "$pending_dir" >/dev/null || exit 1
    validate_promotion_report || exit 1
    current_target_matches "$release_dir" || {
      echo "verified deployment current release does not match its transaction" >&2
      exit 1
    }
    validate_manifest_file "$release_dir" || exit 1
    validate_runtime_env_link "$release_dir" || exit 1
    wait_until_ready 1 || {
      echo "verified deployment is not ready; watchdog is leaving commit pending" >&2
      exit 1
    }
    finalize_pending_state committed >/dev/null || exit 1
    recover_finalized_state \
      committed \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" || exit 1
    [ "$recovered_finalization" -eq 1 ] || {
      echo "verified deployment watchdog did not reach a committed receipt" >&2
      exit 1
    }
    recover_completed_state \
      "" \
      "$release_name" \
      "$expected_sha" \
      "$expected_digest" \
      "$transaction_id" \
      "$pending_state_hash" \
      0 || exit 1
    [ "$recovered_completion" -eq 1 ] || {
      echo "verified watchdog completion receipt was not recovered" >&2
      exit 1
    }
    [ "$recovered_completion_outcome" = "committed" ] || {
      echo "verified watchdog recovered a non-commit completion receipt" >&2
      exit 1
    }
    publish_watchdog_terminal_record completed || exit 1
    return 0
  fi
  echo "pending deployment deadline expired; rolling back $release_name" >&2
  restore_previous_release || exit 1
  recover_completed_state \
    "" \
    "$release_name" \
    "$expected_sha" \
    "$expected_digest" \
    "$transaction_id" \
    "$pending_state_hash" \
    0 || exit 1
  [ "$recovered_completion" -eq 1 ] || {
    echo "rollback watchdog completion receipt was not recovered" >&2
    exit 1
  }
  [ "$recovered_completion_outcome" = "rolled-back" ] || {
    echo "rollback watchdog recovered a non-rollback completion receipt" >&2
    exit 1
  }
  publish_watchdog_terminal_record rolled-back || exit 1
}

case "$action" in
  protocol) protocol_release "$@" ;;
  activate) activate_release "$@" ;;
  authorize) authorize_release "$@" ;;
  status) status_release "$@" ;;
  commit) commit_release "$@" ;;
  rollback) rollback_release "$@" ;;
  reconcile) reconcile_release "$@" ;;
  watchdog) watchdog_release "$@" ;;
  *)
    usage
    exit 2
    ;;
esac
