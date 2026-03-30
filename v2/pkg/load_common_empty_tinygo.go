//go:build tinygo && emptytemplates
// +build tinygo,emptytemplates

package pkg

import (
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

var (
	FingerEngine         *fingers.FingersEngine
	FingerprintHubEngine *fingerprinthub.FingerPrintHubEngine
	Extractor            []*parsers.Extractor
	Extractors           = make(parsers.Extractors)
	ExtractRegexps       = map[string][]*parsers.Extractor{}
)

func LoadFinger([]string) error {
	resources.PrePort = utils.PrePort

	engine, err := fingers.NewEngine(fingers.Fingers{}, nil)
	if err != nil {
		return err
	}
	FingerEngine = engine

	hub, err := fingerprinthub.NewFingerPrintHubEngine([]byte("[]"), []byte("[]"))
	if err != nil {
		return err
	}
	FingerprintHubEngine = hub

	return nil
}

func LoadPortConfig(string) error {
	utils.PrePort = utils.NewPortPreset(nil)
	resources.PrePort = utils.PrePort
	return nil
}

func LoadExtractor() error {
	Extractor = nil
	Extractors = make(parsers.Extractors)
	ExtractRegexps = map[string][]*parsers.Extractor{}
	return nil
}

func LoadWorkFlow() WorkflowMap {
	return WorkflowMap{}
}

type WorkflowMap map[string][]*Workflow

func (m WorkflowMap) Choice(name string) []*Workflow {
	return nil
}
