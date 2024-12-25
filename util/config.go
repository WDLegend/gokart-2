// Copyright 2021 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// ConfigType stores booleans for GoKart analysis configuration
type ConfigType struct {
	GlobalsSafe   bool
	OutputSarif   bool
	OutputJSON    bool
	Debug         bool
	Verbose       bool
	ExitCode      bool
	WebMode       bool
	SourceYMLPath string
	SinkYMLPath   string
	OutputPath    string
}

// ConfigFile stores the values parsed from the configuration file
type ConfigFile struct {
	Analyzers map[string]Analyzer `yaml:"analyzers"`
	Sources   Sources             `yaml:"sources"`
}

// Analyzer stores an analyzer parsed from the configuration file
type Analyzer struct {
	Doc       string              `yaml:"doc"`
	Message   string              `yaml:"message"`
	VulnCalls map[string][]string `yaml:"vuln_calls"`
}

// Sources stores the untrusted sources parsed from the configuration file
type Sources struct {
	Variables    map[string][]string `yaml:"variables"`
	Functions    map[string][]string `yaml:"functions"`
	Types        map[string][]string `yaml:"types"`
	WebModeFuncs map[string][]string `yaml:"webModeFuncs"`
	// For compatibility with older analyzer.yml format
	OldSrcs *Sources `yaml:"sources"`
}

type SinksConfig struct {
	CmdInjectionFuncs map[string][]string `yaml:"cmd_injection_funcs"`
	SqlInjectionFuncs map[string][]string `yaml:"sql_injection_funcs"`
	SsrfFuncs         map[string][]string `yaml:"ssrf_funcs"`
	Rsa               map[string][]string `yaml:"rsa_vul_funcs"`
	TraversalFuncs    map[string][]string `yaml:"traversal_funcs"`
}

var (
	FilesFound      = 0
	VulnGlobalVars  map[string][]string
	VulnGlobalFuncs map[string][]string
	VulnTypes       map[string][]string
	//go:embed sources.yml
	DefaultSourcesContent []byte
	//go:embed sinks.yml
	DefaultSinksContent []byte
)

var (
	configDir string
	once      sync.Once
)

var (
	Config     ConfigType
	ScanConfig ConfigFile
	Sinks      SinksConfig
)

func LoadScanConfig() {
	configBytes, err := ioutil.ReadFile(Config.SourceYMLPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(configBytes, &ScanConfig); err != nil {
		log.Fatal(err)
	}

	configBytes, err = ioutil.ReadFile(Config.SinkYMLPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(configBytes, &Sinks); err != nil {
		log.Fatal(err)
	}

	// If OldSrcs isn't nil, then the config file is in the old format and we unnest the values
	if ScanConfig.Sources.OldSrcs != nil {
		ScanConfig.Sources.Functions = ScanConfig.Sources.OldSrcs.Functions
		ScanConfig.Sources.Variables = ScanConfig.Sources.OldSrcs.Variables
		ScanConfig.Sources.Types = ScanConfig.Sources.OldSrcs.Types
		// Set OldSrcs to nil to let the garbage collector clean it up
		ScanConfig.Sources.OldSrcs = nil
	}

	if Config.Debug {
		log.Println("Beginning list of default sources defined in yml:")
		for pkg, fn := range ScanConfig.Sources.Functions {
			log.Printf("Functions %s in package %s\n", fn, pkg)
		}

		if len(ScanConfig.Analyzers) > 0 {
			log.Println("\nBeginning list of analyzers defined in yml:")
			for name, values := range ScanConfig.Analyzers {
				log.Printf("Name:    %s\n", name)
				log.Printf("Doc:     %s\n", values.Doc)
				log.Printf("Message: %s\n", values.Message)
				log.Println("Vuln Calls:")
				for pkg, fn := range values.VulnCalls {
					log.Printf("Functions %s in package %s\n", fn, pkg)
				}
			}
		}
		log.Printf("\n\n")
	}
	VulnGlobalVars = ScanConfig.Sources.Variables

	if Config.WebMode {
		VulnGlobalFuncs = ScanConfig.Sources.WebModeFuncs
	} else {
		VulnGlobalFuncs = ScanConfig.Sources.Functions
	}

	VulnTypes = ScanConfig.Sources.Types
}

// InitConfig() parses the flags and sets the corresponding Config variables
func InitConfig(globals bool, sarif bool, json bool, verbose bool, debug bool, output_path string, sourceYml string, sinkYml string, exitCode bool, webMode bool) {
	if sourceYml == "" {
		sourceYml = getDefaultConfigPath("sources.yml")
	} else if _, err := os.Stat(sourceYml); err != nil {
		log.Fatalf("failed to find the provided config file at %s: %v", sourceYml, err)
	}
	if !(json || sarif) {
		fmt.Printf("Using config found at %s\n", sourceYml)
	}

	if sinkYml == "" {
		sinkYml = getDefaultConfigPath("sinks.yml")
	} else if _, err := os.Stat(sinkYml); err != nil {
		log.Fatalf("failed to find the provided config file at %s: %v", sinkYml, err)
	}
	if !(json || sarif) {
		fmt.Printf("Using config found at %s\n", sinkYml)
	}

	Config.GlobalsSafe = !globals
	Config.OutputSarif = sarif
	Config.OutputJSON = json
	Config.Debug = debug
	Config.Verbose = verbose
	Config.ExitCode = exitCode
	Config.OutputPath = ""
	Config.WebMode = webMode

	// get the absolute path of the output file to avoid issues when changing working directory for loading packages
	if output_path != "" {
		abs_output_path, err := filepath.Abs(output_path)
		if err != nil {
			log.Fatal(err)
		}
		Config.OutputPath = abs_output_path
	}
	Config.SourceYMLPath = sourceYml
	Config.SinkYMLPath = sinkYml
	LoadScanConfig()
}

// getDefaultConfigPath gets the path to the default configuration file and creates it if it doesn't yet exist.
func getDefaultConfigPath(file string) string {
	setConfigDir()
	yamlPath := filepath.Join(configDir, file)

	// If ~/.gokart/analyzers.yml doesn't exist, create it with the default config
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Printf("Initializing default config at %s\n", yamlPath)
		if file == "sources.yml" {
			if err := ioutil.WriteFile(yamlPath, DefaultSourcesContent, 0o744); err != nil {
				log.Fatalf("failed to write default config to %s: %v", yamlPath, err)
			}
		} else {
			if err := ioutil.WriteFile(yamlPath, DefaultSinksContent, 0o744); err != nil {
				log.Fatalf("failed to write default config to %s: %v", yamlPath, err)
			}
		}
	} else if err != nil {
		// If the error returned by os.Stat is not ErrNotExist
		log.Fatalf("failed to initialize default config: %v", err)
	}
	return yamlPath
}

// setConfigDir initializes the configDir variable upon its first invocation, does nothing otherwise.
func setConfigDir() {
	once.Do(func() {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to get home directory: %v", err)
		}
		configDir = filepath.Join(userHomeDir, ".gokart")
		if err = os.MkdirAll(configDir, 0o744); err != nil {
			log.Fatalf("failed to create config directory %s: %v", configDir, err)
		}
	})
}
