package util

import (
	"golang.org/x/tools/go/ssa"
)

var Cg CallGraph

var Prog *ssa.Program

var AnalyzedCalls []*ssa.Call

// 存储Call类型为Parameter的instr，用于未来的指针分析（因为是backward的分析）
var ParameterCallMap map[string]*ssa.Call

var AnalyzedSinks []*ssa.Function

func InitCallgraph(ssaFuncs []*ssa.Function) {
	// Builds SSA model of Go code
	//ssaFuncs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	if !IsInitialized() {
		Cg = make(CallGraph)
	}

	// Fills in call graph
	for _, fn := range ssaFuncs {
		Cg.AnalyzeFunction(fn)
	}

	if ParameterCallMap == nil {
		ParameterCallMap = make(map[string]*ssa.Call)
	}

}

func IsInitialized() bool {
	if Cg == nil {
		return false
	} else {
		return true
	}
}
