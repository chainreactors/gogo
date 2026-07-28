package core

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chainreactors/gogo/v2/engine"
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/utils"
)

func TestTargetGeneratorReadsCountersAtomically(t *testing.T) {
	config := pkg.NewDefaultConfig(pkg.DefaultRunnerOption)
	config.Ctx = context.Background()
	gen := NewTargetGenerator(config)
	ports := make([]string, 20000)
	for i := range ports {
		ports[i] = strconv.Itoa(i + 1)
	}

	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				atomic.AddInt32(&engine.RunSum, 1)
				atomic.AddInt32(&Opt.AliveSum, 1)
			}
		}
	}()

	for range gen.generatorDispatch(utils.ParseCIDRs([]string{"127.0.0.1/32"}), ports) {
	}
	close(stop)
	writers.Wait()
}
