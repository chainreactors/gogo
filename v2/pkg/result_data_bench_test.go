package pkg

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var (
	benchDataCacheMu sync.Mutex
	benchDataCache   = map[int]benchmarkDataset{}

	benchLoadSink   interface{}
	benchStringSink string
	benchMapSink    map[string]PortMapResult
	benchSliceSink  []string
)

type benchmarkDataset struct {
	blob []byte
	rows int
	rd   *ResultsData
}

type benchmarkSize struct {
	name string
	size int
}

var benchmarkSizes = []benchmarkSize{
	{name: "1MB", size: 1 << 20},
	{name: "5MB", size: 5 << 20},
	{name: "10MB", size: 10 << 20},
}

func getBenchmarkDataset(tb testing.TB, targetBytes int) benchmarkDataset {
	tb.Helper()

	benchDataCacheMu.Lock()
	defer benchDataCacheMu.Unlock()

	if cached, ok := benchDataCache[targetBytes]; ok {
		return cached
	}

	ds := buildBenchmarkDataset(tb, targetBytes)
	benchDataCache[targetBytes] = ds
	return ds
}

func buildBenchmarkDataset(tb testing.TB, targetBytes int) benchmarkDataset {
	tb.Helper()

	const portsPerIP = 16
	var builder strings.Builder
	builder.Grow(targetBytes + 1024)

	builder.WriteString("{\"ip\":\"10.0.0.0/16\",\"ips\":null,\"ports\":\"top1\",\"json_file\":\"\",\"list_file\":\"\",\"threads\":1000,\"mod\":\"default\",\"no_scan\":false,\"alive_spray\":null,\"port_spray\":false,\"exploit\":\"none\",\"json_type\":\"scan\",\"version_level\":1}\n")

	rows := 0
	for builder.Len() < targetBytes {
		hostIndex := rows / portsPerIP
		portIndex := rows % portsPerIP
		ip := fmt.Sprintf("10.%d.%d.%d", hostIndex/65536, (hostIndex/256)%256, hostIndex%256)
		port := 8000 + portIndex
		protocol := "http"
		if portIndex%2 == 1 {
			protocol = "https"
		}
		status := []string{"200", "403", "404"}[rows%3]
		title := fmt.Sprintf("Synthetic service %d for gogo performance benchmark", rows)
		host := fmt.Sprintf("app-%d.example.internal", rows)
		line := fmt.Sprintf(
			"{\"ip\":\"%s\",\"port\":\"%d\",\"protocol\":\"%s\",\"status\":\"%s\",\"frameworks\":{\"nginx\":{\"name\":\"nginx\",\"froms\":{\"6\":true},\"tags\":[\"fingers\",\"component\"],\"attributes\":{\"part\":\"a\",\"vendor\":\"\",\"product\":\"\",\"version\":\"1.25.5\"}},\"springboot\":{\"name\":\"springboot\",\"froms\":{\"6\":true},\"tags\":[\"fingers\",\"component\"],\"attributes\":{\"part\":\"a\",\"vendor\":\"\",\"product\":\"\",\"version\":\"3.2.2\"}}},\"title\":\"%s\",\"host\":\"%s\",\"midware\":\"nginx/1.25.5\",\"vulns\":{\"swagger leak\":{\"name\":\"swagger leak\",\"detail\":{\"path\":[\"/swagger-ui.html\"]},\"severity\":1}},\"extracteds\":{\"domain\":[\"%s\",\"cdn-%d.example.internal\"]}}\n",
			ip,
			port,
			protocol,
			status,
			title,
			host,
			host,
			rows,
		)
		builder.WriteString(line)
		rows++
	}
	builder.WriteString("[\"done\"]\n")

	blob := []byte(builder.String())
	data := LoadResultFile(bytes.NewReader(blob))
	rd, ok := data.(*ResultsData)
	if !ok || rd == nil {
		tb.Fatalf("unexpected result type %T", data)
	}

	return benchmarkDataset{
		blob: blob,
		rows: rows,
		rd:   rd,
	}
}

func BenchmarkLoadResultFile(b *testing.B) {
	for _, tc := range benchmarkSizes {
		b.Run(tc.name, func(b *testing.B) {
			ds := getBenchmarkDataset(b, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(ds.blob)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchLoadSink = LoadResultFile(bytes.NewReader(ds.blob))
			}
		})
	}
}

func BenchmarkResultsDataToFormat(b *testing.B) {
	for _, tc := range benchmarkSizes {
		b.Run(tc.name+"/plain", func(b *testing.B) {
			ds := getBenchmarkDataset(b, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(ds.blob)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchStringSink = ds.rd.ToFormat(false)
			}
		})

		b.Run(tc.name+"/color", func(b *testing.B) {
			ds := getBenchmarkDataset(b, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(ds.blob)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchStringSink = ds.rd.ToFormat(true)
			}
		})
	}
}

func BenchmarkResultsDataToJson(b *testing.B) {
	for _, tc := range benchmarkSizes {
		b.Run(tc.name, func(b *testing.B) {
			ds := getBenchmarkDataset(b, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(ds.blob)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchStringSink = ds.rd.ToJson()
			}
		})
	}
}

func BenchmarkResultsDataGroupBySortedIP(b *testing.B) {
	for _, tc := range benchmarkSizes {
		b.Run(tc.name, func(b *testing.B) {
			ds := getBenchmarkDataset(b, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(ds.blob)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchMapSink, benchSliceSink = ds.rd.groupBySortedIP()
			}
		})
	}
}
