# TinyGo Toolchain Patch

This directory stores the TinyGo build wrapper and the minimal stdlib patch
needed for the TinyGo `gogo` build to preserve the original extractor regex
semantics.

Design:

- Keep the patch in-repo.
- Never mutate the machine-global `GOROOT` during normal builds.
- Materialize a cached patched `GOROOT` under `tinygo/.toolchain/`.
- Point TinyGo at that cached `GOROOT` only for the current build.

Files:

- `build-tinygo.sh`: TinyGo build wrapper for the `v2` module.
- `toolchain/manifest.env`: pinned toolchain versions for reproducible builds.
- `toolchain/regexp-syntax-repeat.patch`: patch for `src/regexp/syntax/compile.go`
  and `src/regexp/syntax/simplify.go`.

Entry point:

- `tinygo/build-tinygo.sh`

Typical usage:

```sh
bash tinygo/build-tinygo.sh
```

The script will:

1. Validate the host `Go` and `TinyGo` versions.
2. Copy the current TinyGo host `GOROOT` into `tinygo/.toolchain/...`.
3. Apply the regexp patch if the copied tree is not already patched.
4. Build `./cmd/tinygo` with that patched `GOROOT`.

If you intentionally upgrade the host toolchain before updating this patch,
set `ALLOW_TOOLCHAIN_MISMATCH=1` to bypass the version guard.

Build profiles:

- `release` (default)
  - Uses `-no-debug -opt=z`.
  - Runs `strip` when available.
  - Runs UPX automatically when available.
- `minimal`
  - Inspired by the `rem/docs` TinyGo minimal-binary workflow.
  - Uses `-no-debug -opt=z`.
  - Adds `-gc=leaking` for non-Windows targets.
  - Runs `strip` for non-Windows targets when available.
  - Intended for short-lived scan binaries where size matters most.
- `compat`
  - Uses `-no-debug -opt=z`.
  - Does not force `-gc=leaking` or `strip`.
  - Intended when you want the same patched toolchain but fewer runtime tradeoffs.

Examples:

```sh
# default release build
bash tinygo/build-tinygo.sh

# keep the safer GC behavior
bash tinygo/build-tinygo.sh --profile compat

# append extra build tags
bash tinygo/build-tinygo.sh --tags "noasm"

# compress with UPX after build
bash tinygo/build-tinygo.sh --upx
```
