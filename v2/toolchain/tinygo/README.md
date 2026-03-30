# TinyGo Toolchain Patch

This directory stores the minimal stdlib patch needed for the TinyGo `gogo`
build to preserve the original extractor regex semantics.

Design:

- Keep the patch in-repo.
- Never mutate the machine-global `GOROOT` during normal builds.
- Materialize a cached patched `GOROOT` under `v2/.toolchain/`.
- Point TinyGo at that cached `GOROOT` only for the current build.

Files:

- `manifest.env`: pinned toolchain versions for reproducible builds.
- `regexp-syntax-repeat.patch`: patch for `src/regexp/syntax/compile.go`
  and `src/regexp/syntax/simplify.go`.

Entry point:

- `scripts/build-tinygo.sh`

Typical usage:

```sh
bash scripts/build-tinygo.sh
```

The script will:

1. Validate the host `Go` and `TinyGo` versions.
2. Copy the current TinyGo host `GOROOT` into `v2/.toolchain/...`.
3. Apply the regexp patch if the copied tree is not already patched.
4. Build `./cmd/tinygo` with that patched `GOROOT`.

If you intentionally upgrade the host toolchain before updating this patch,
set `ALLOW_TOOLCHAIN_MISMATCH=1` to bypass the version guard.

Build profiles:

- `minimal` (default)
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
# default minimal build
bash scripts/build-tinygo.sh

# keep the safer GC behavior
bash scripts/build-tinygo.sh --profile compat

# append extra build tags
bash scripts/build-tinygo.sh --tags "noasm"

# compress with UPX after build
bash scripts/build-tinygo.sh --upx
```
