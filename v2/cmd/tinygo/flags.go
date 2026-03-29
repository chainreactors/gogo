//go:build tinygo
// +build tinygo

package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/chainreactors/gogo/v2/core"
)

func parseRunnerArgs(args []string) (*core.Runner, bool, error) {
	runner := newTinyGoRunner()

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			return runner, true, nil
		case arg == "--":
			if i+1 < len(args) {
				return nil, false, fmt.Errorf("unexpected positional argument: %s", args[i+1])
			}
			return runner, false, nil
		case strings.HasPrefix(arg, "--"):
			name, value, hasValue := splitLongArg(arg[2:])
			nextValue := func() (string, error) {
				if hasValue {
					return value, nil
				}
				if i+1 >= len(args) {
					return "", fmt.Errorf("missing value for --%s", name)
				}
				i++
				return args[i], nil
			}

			switch name {
			case "ip":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.IP = v
			case "exclude":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Exclude = v
			case "exclude-file":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.ExcludeList = v
			case "port":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Ports = v
			case "port-config":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.PortConfig = v
			case "list":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.ListFile = v
			case "json":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.JsonFile = v
			case "filter-or":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.FilterOr = v
			case "workflow":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.WorkFlowName = v
			case "format":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.FormatterFilename = v
			case "file":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Filename = v
			case "path":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.FilePath = v
			case "output":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Outputf = v
			case "file-output":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.FileOutputf = v
			case "output-delimiter":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.OutputDelimiter = v
			case "af":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.AutoFile = v
			case "hf":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.HiddenFile = v
			case "compress":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Compress = v
			case "tee":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Tee = v
			case "quiet":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Quiet = v
			case "no-guess":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.NoGuess = v
			case "mod":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Mod = v
			case "ping":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Ping = v
			case "no":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.NoScan = v
			case "sp":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.PortProbe = v
			case "ipp":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.IpProbe = v
			case "spray":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.PortSpray = v
			case "no-spray":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.NoSpray = v
			case "exploit-name":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.ExploitName = v
			case "ef":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.ExploitFile = v
			case "ff":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.FingerFile = append(runner.FingerFile, v)
			case "payload":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Payloads = append(runner.Payloads, v)
			case "attack-type":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.AttackType = v
			case "extract":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Extract = append(runner.Extract, v)
			case "opsec":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Opsec = v
			case "filter":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Filters = append(runner.Filters, v)
			case "output-filter":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.OutputFilters = append(runner.OutputFilters, v)
			case "scan-filter":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.ScanFilters = append(runner.ScanFilters, v)
			case "key":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Key = v
			case "version":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Ver = v
			case "print":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Printer = v
			case "debug":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Debug = v
			case "plugin-debug":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.PluginDebug = v
			case "proxy":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				runner.Proxy = append(runner.Proxy, v)
			case "exploit":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				runner.Exploit = v
			case "verbose":
				v, err := parseLongBool(name, hasValue, value)
				if err != nil {
					return nil, false, err
				}
				if v {
					runner.Verbose = append(runner.Verbose, true)
				}
			case "thread":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, false, fmt.Errorf("invalid value for --thread: %s", v)
				}
				runner.Threads = n
			case "timeout":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, false, fmt.Errorf("invalid value for --timeout: %s", v)
				}
				runner.Delay = n
			case "ssl-timeout":
				v, err := nextValue()
				if err != nil {
					return nil, false, err
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, false, fmt.Errorf("invalid value for --ssl-timeout: %s", v)
				}
				runner.HttpsDelay = n
			default:
				return nil, false, fmt.Errorf("unknown flag: --%s", name)
			}
		case strings.HasPrefix(arg, "-"):
			rest := arg[1:]
			if rest == "" {
				return nil, false, fmt.Errorf("unexpected argument: %s", arg)
			}
			for pos := 0; pos < len(rest); pos++ {
				flag := rest[pos]
				switch flag {
				case 'L':
					runner.IsListInput = true
				case 'J':
					runner.IsJsonInput = true
				case 'W':
					runner.IsWorkFlow = true
				case 'C':
					runner.Compress = true
				case 'q':
					runner.Quiet = true
				case 'n':
					runner.NoScan = true
				case 's':
					runner.PortSpray = true
				case 'e':
					runner.Exploit = true
				case 'v':
					runner.Verbose = append(runner.Verbose, true)
				case 'i', 'p', 'l', 'j', 'w', 'F', 'f', 'o', 'O', 'm', 'E', 'P', 'k', 't', 'd', 'D':
					value, consumed, err := consumeShortValue(rest, pos, args, &i)
					if err != nil {
						return nil, false, err
					}
					switch flag {
					case 'i':
						runner.IP = value
					case 'p':
						runner.Ports = value
					case 'l':
						runner.ListFile = value
					case 'j':
						runner.JsonFile = value
					case 'w':
						runner.WorkFlowName = value
					case 'F':
						runner.FormatterFilename = value
					case 'f':
						runner.Filename = value
					case 'o':
						runner.Outputf = value
					case 'O':
						runner.FileOutputf = value
					case 'm':
						runner.Mod = value
					case 'E':
						runner.ExploitName = value
					case 'P':
						runner.Printer = value
					case 'k':
						runner.Key = value
					case 't':
						n, err := strconv.Atoi(value)
						if err != nil {
							return nil, false, fmt.Errorf("invalid value for -t: %s", value)
						}
						runner.Threads = n
					case 'd':
						n, err := strconv.Atoi(value)
						if err != nil {
							return nil, false, fmt.Errorf("invalid value for -d: %s", value)
						}
						runner.Delay = n
					case 'D':
						n, err := strconv.Atoi(value)
						if err != nil {
							return nil, false, fmt.Errorf("invalid value for -D: %s", value)
						}
						runner.HttpsDelay = n
					}
					if consumed {
						pos = len(rest)
					}
				default:
					return nil, false, fmt.Errorf("unknown flag: -%c", flag)
				}
			}
		default:
			return nil, false, fmt.Errorf("unexpected positional argument: %s", arg)
		}
	}

	return runner, false, nil
}

func newTinyGoRunner() *core.Runner {
	return &core.Runner{
		InputOption: core.InputOption{
			Ports: "top1",
		},
		OutputOption: core.OutputOption{
			Outputf:         "default",
			FileOutputf:     "default",
			OutputDelimiter: "\t",
		},
		SmartOption: core.SmartOption{
			Mod:       "default",
			PortProbe: "default",
			IpProbe:   "default",
		},
		ConfigOption: core.ConfigOption{
			Delay:      2,
			HttpsDelay: 2,
		},
	}
}

func splitLongArg(arg string) (string, string, bool) {
	if idx := strings.IndexByte(arg, '='); idx >= 0 {
		return arg[:idx], arg[idx+1:], true
	}
	return arg, "", false
}

func parseLongBool(name string, hasValue bool, value string) (bool, error) {
	if !hasValue {
		return true, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for --%s: %s", name, value)
	}
	return b, nil
}

func consumeShortValue(rest string, pos int, args []string, index *int) (string, bool, error) {
	if pos+1 < len(rest) {
		return rest[pos+1:], true, nil
	}
	if *index+1 >= len(args) {
		return "", false, fmt.Errorf("missing value for -%c", rest[pos])
	}
	*index = *index + 1
	return args[*index], false, nil
}

func printUsage(w io.Writer) {
	io.WriteString(w, "Usage: gogo-tinygo [options]\n")
	io.WriteString(w, core.Usage())
	io.WriteString(w, "\n\nTinyGo notes:\n")
	io.WriteString(w, "  - TLS certificate/domain extraction is disabled.\n")
	io.WriteString(w, "  - The dedicated cmd/tinygo entrypoint avoids go-flags at startup.\n")
}
