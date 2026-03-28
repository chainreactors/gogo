# Performance Optimization Plan

## Scope

The current formatting path has one dominant hotspot: `(*ResultsData).ToFormat`.

Measured on a synthetic `~10MB` result file with about `15k` rows:

- `LoadResultFile`: about `1.3s`
- `ToJson`: about `0.3s`
- `ToFormat(false)`: about `49s`

This means optimization work should focus on text formatting first, not decryption.

## Hotspots

### 1. `ToFormat`

File: [pkg/result_data.go](./pkg/result_data.go)

Current issues:

- Uses `string += fmt.Sprintf(...)` inside nested loops.
- Builds and discards many temporary strings.
- Recomputes formatted fragments repeatedly.

Expected effect:

- Highest impact.
- Should reduce both `ns/op` and `allocs/op` significantly.

### 2. IP grouping and sorting

File: [pkg/result_data.go](./pkg/result_data.go)

Current issues:

- `sortIP` calls `utils.ParseIP` inside the comparator repeatedly.
- The same IP string is parsed many times during sorting.

Expected effect:

- Moderate impact.
- Mostly helps `ToFormat`, because that path always groups and sorts first.

### 3. Full-file parse model

Files:

- [pkg/result_data.go](./pkg/result_data.go)
- dependency `fileutils.DecryptFile`

Current issues:

- Entire file is read into memory.
- `bytes.Split` duplicates slice bookkeeping across the whole payload.
- Formatting modes that do not need the full in-memory structure still pay the full parse cost.

Expected effect:

- Medium impact for large files.
- Important after `ToFormat` is fixed.

## Optimization Plan

### Phase 1: Low-risk formatting rewrite

Target:

- `(*ResultsData).ToFormat`

Changes:

- Replace `string +=` with `strings.Builder`.
- Replace loop-local `fmt.Sprintf` calls with direct `WriteString` where practical.
- Pre-size `ports` slices.
- Remove the redundant `seen` map if the `PortMapResult` invariant already guarantees uniqueness.

Success criteria:

- `BenchmarkResultsDataToFormat/10MB/plain` improves by at least `5x`.
- `allocs/op` drops materially.

### Phase 2: Cache parsed IPs for sorting

Target:

- `sortIP`
- `groupBySortedIP`

Changes:

- Parse each IP once before sorting.
- Sort a small struct slice such as `{raw string, parsed *utils.IP}`.

Success criteria:

- `BenchmarkResultsDataGroupBySortedIP/10MB` improves clearly.
- Secondary improvement visible in `BenchmarkResultsDataToFormat`.

### Phase 3: Streaming formatter path

Target:

- `FormatOutput`
- `LoadResultFile`

Changes:

- Add a streaming path for `-F` modes that do not require the fully grouped structure.
- Keep existing grouped path only for `full`, `color`, `extract`, and similar modes.
- For `json`, `jl`, `url`, `ip,url`, and similar value outputs, process line-by-line.

Success criteria:

- `LoadResultFile` is no longer on the critical path for simple value outputs.
- End-to-end `-F ... -o url` and `-F ... -o json` scale close to input size.

## Benchmark Suite

File: [pkg/result_data_bench_test.go](./pkg/result_data_bench_test.go)

Benchmarks included:

- `BenchmarkLoadResultFile`
- `BenchmarkResultsDataToFormat`
- `BenchmarkResultsDataToJson`
- `BenchmarkResultsDataGroupBySortedIP`

Dataset sizes:

- `1MB`
- `5MB`
- `10MB`

The benchmark data is synthetic but shaped to exercise:

- repeated IP grouping
- per-IP port sorting
- realistic `frameworks`, `vulns`, `extracteds`, and title strings

## How To Compare Before/After

Quick single-run baseline:

```powershell
go test ./pkg -run '^$' -bench 'Benchmark(LoadResultFile|ResultsData)' -benchmem -benchtime=1x
```

More stable comparison:

```powershell
go test ./pkg -run '^$' -bench 'Benchmark(LoadResultFile|ResultsData)' -benchmem -count=5 -benchtime=1x > before.txt
go test ./pkg -run '^$' -bench 'Benchmark(LoadResultFile|ResultsData)' -benchmem -count=5 -benchtime=1x > after.txt
benchstat before.txt after.txt
```

Primary metrics to watch:

- `ns/op`
- `B/op`
- `allocs/op`

Primary acceptance target:

- `ToFormat` becomes the same order of magnitude as parse time, not tens of seconds slower.
