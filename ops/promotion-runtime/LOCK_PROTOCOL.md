# Promotion Lock Protocol

Installer-owned database promotion uses the installer's inherited deployment
lock descriptor as a capability. An environment variable is not authorization.

## Installer Handoff

The installer must:

1. Open the canonical lock at
   `<install-base>/shared/deploy-promotion.lock` on file descriptor 9.
2. Acquire the exclusive `flock` on descriptor 9.
3. Keep descriptor 9 open and locked for the complete promotion call.
4. Remove `RADAR_DEPLOY_LOCK_HELD=1`.
5. Remove `RADAR_DEPLOY_LOCK_PATH` from promotion authorization input.
6. Add `--deployment-lock-fd 9` to both promotion invocation paths.

The installer invokes the declared package lifecycle through npm so database
lifecycle authorization is backed by a real npm ancestor. Because npm does not
preserve arbitrary descriptors for lifecycle children, the installer also maps
its locked FD 9 to npm's stdin. The declared wrapper immediately duplicates
that same open file description back to FD 9 before starting the promoter:

```sh
RADAR_PROMOTION_LOCK_STDIN=1 \
"$npm_bin" \
  --silent \
  --prefix "$release_dir/$promotion_runtime_relative" \
  run promote:quality-db -- \
  ... \
  --deployment-lock-fd 9 \
  --apply <&9
```

The configured test promotion executable receives the same
`--deployment-lock-fd 9` argument. Any wrapper in that path must explicitly
preserve descriptor 9.

`validate_promotion_report` must also validate `report.deploymentLock.proof`.
Pass `$lock_file` into its embedded Node validator and require:

- `schemaVersion === 1`
- `method === "linux-proc-fdinfo-flock"`
- `fd === 9`
- `path === lock_file`
- `lockType === "exclusive"`
- `verified === true`
- `device` and `inode` equal `fs.statSync(lock_file, { bigint: true })`

The existing `lockHeldByInstaller` report field may remain for protocol
compatibility, but it is derived output and must not be treated as proof.

## Promotion Proof

Promotion rejects installer-owned mode unless Linux `/proc/self/fdinfo/9`
contains an exclusive whole-file `FLOCK` entry. It also requires `fstat(9)` to
match the device and inode of the canonical lock path. The descriptor, path
identity, and lock entry are rechecked immediately before swap, before success,
and before an automatic rollback restore.

`RADAR_DEPLOY_LOCK_PATH` remains a standalone-promotion setting. It is not
trusted for installer-owned authorization. Installer-owned promotion derives
the canonical lock path from the verified destination shared directory.
