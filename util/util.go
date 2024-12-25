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

/*
Package util implements underlying functionality for building and traversing call graphs,
configuraing and building analyzers and generating findings
*/
package util

import (
	"bufio"
	"bytes"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"runtime"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"

	"github.com/segmentio/fasthash/fnv1a"
)

type ReturnSet = []ssa.Value

// ReturnValues returns a set of the return values of the function
func ReturnValues(fn *ssa.Function) []ReturnSet {
	res := []ReturnSet{}

	for _, block := range fn.DomPreorder() {
		// 检查是否为返回块
		if len(block.Succs) != 0 {
			continue
		}

		// 检查是否包含 return 指令
		if ret, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
			// 仅在有返回值时追加
			if len(ret.Results) > 0 {
				res = append(res, ret.Results[:])
			}
		}
	}

	return res
}

// CGRelation is a struct that contains information about an instruction and a function in the call graph
type CGRelation struct {
	Instr   *ssa.Call
	Fn      *ssa.Function
	Closure *ssa.MakeClosure
}
type CallGraph map[string][]CGRelation

// AnalyzeFunction updates the CallGraph to contain relations between callee and caller functions. This should be called once on every function in a local package
func (cg CallGraph) AnalyzeFunction(fn *ssa.Function) {
	for _, block := range fn.DomPreorder() {
		for _, instr := range block.Instrs {
			cg.AnalyzeFunctionRecursive(fn, instr)
		}
	}
}

func (cg CallGraph) AnalyzeFunctionRecursive(fn *ssa.Function, instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.Call:
		if instr.Call.StaticCallee() != nil {
			calleeName := instr.Call.StaticCallee().String()
			//特殊情况，StaticCall且是MakeClosure。
			if value, ok := instr.Call.Value.(*ssa.MakeClosure); ok {
				cg[calleeName] = append(cg[calleeName], CGRelation{instr, fn, value})
			} else {
				cg[calleeName] = append(cg[calleeName], CGRelation{instr, fn, nil})
			}
		} else if iface, ok := instr.Call.Value.(*ssa.MakeInterface); ok {
			// 动态接口调用
			cg.analyzeDynamicInterfaceCall(iface, instr, fn, Prog)
		} else if _, ok := instr.Call.Value.(*ssa.Call); ok {
			cg.analyzeCallUntilNonCall(instr, fn, instr)
		}

		//// 除此之外，要对每种情况的参数都做判断，看是否为高阶函数。（高阶函数为参数的情况）不会写，先空着。
		//else if _, ok := instr.Call.Value.(*ssa.Parameter); ok {
		//ParameterCallMap[instr.Call.Value.Parent().String()] = instr
		//}

		//for _, arg := range instr.Call.Args {
		//	if value, ok := ParameterCallMap[instr.Call.Value.String()]; ok {
		//		if function, ok := instr.Call.Value.(*ssa.Function); ok {
		//			if _, ok := arg.(*ssa.Function); ok {
		//				cg[arg.String()] = append(cg[arg.String()], CGRelation{value, function, nil})
		//			}
		//
		//			if closure, ok := arg.(*ssa.MakeClosure); ok {
		//				cg[closure.Fn.String()] = append(cg[closure.Fn.String()], CGRelation{value, function, closure})
		//			}
		//
		//			if call, ok := arg.(*ssa.Call); ok {
		//				cg.analyzeCallUntilNonCall(call, function, call)
		//			}
		//		}
		//
		//	}
		//}

	}
}

// 小缺陷：该函数假定所有的恶意高阶函数都被调用。如果存在使用，但未调用的情况，则会产生误报。但一般正式项目里不会有这类弱智代码吧，所以不改了。
func (cg CallGraph) analyzeCallUntilNonCall(instr *ssa.Call, parentFn *ssa.Function, rootInstr *ssa.Call) {
	// 检查当前调用是否是有效的 Call
	if instr.Call.Value == nil {
		return // 结束条件：没有有效的调用目标
	}

	for _, call := range AnalyzedCalls {
		if call == rootInstr {
			return
		}
	}

	// 检查当前调用是否是另一个 Call
	if temp, ok := instr.Call.Value.(*ssa.Call); ok {
		// 如果是嵌套调用，继续递归处理
		cg.analyzeCallUntilNonCall(temp, parentFn, rootInstr)
		return
	}

	// 检查当前调用是否是一个函数
	if temp2, ok2 := instr.Call.Value.(*ssa.Function); ok2 {

		// 遍历函数的所有基本块和指令
		for _, block := range temp2.Blocks {
			for _, instruct := range block.Instrs {
				switch innerInstr := instruct.(type) {
				case *ssa.Call:
					// 如果是调用，递归处理
					cg.analyzeCallUntilNonCall(innerInstr, parentFn, rootInstr)
				case *ssa.MakeClosure:
					// 如果是闭包，记录到调用图
					cg[innerInstr.Fn.String()] = append(cg[innerInstr.Fn.String()], CGRelation{rootInstr, parentFn, innerInstr})
					AnalyzedCalls = append(AnalyzedCalls, rootInstr)
				case *ssa.Return:
					// 如果返回值包含函数，记录到调用图
					for _, result := range innerInstr.Results {
						if resFn, ok := result.(*ssa.Function); ok {
							cg[resFn.String()] = append(cg[resFn.String()], CGRelation{rootInstr, parentFn, nil})
							AnalyzedCalls = append(AnalyzedCalls, rootInstr)
						}
					}
				}
			}
		}
	}
}

func (cg CallGraph) analyzeDynamicInterfaceCall(iface *ssa.MakeInterface, instr *ssa.Call, caller *ssa.Function, prog *ssa.Program) {
	// 获取接口类型
	ifaceType := iface.Type().Underlying()

	// 查找接口的所有实现，包括嵌入式字段
	implementations := cg.findImplementationsWithEmbeddedFields(ifaceType, prog)

	// 将动态调用的可能目标加入调用图
	for _, impl := range implementations {
		calleeName := impl.String()
		cg[calleeName] = append(cg[calleeName], CGRelation{instr, impl, nil})
	}
}

func (cg CallGraph) findImplementationsWithEmbeddedFields(ifaceType types.Type, prog *ssa.Program) []*ssa.Function {
	var implementations []*ssa.Function

	// 遍历所有包和成员
	for _, pkg := range prog.AllPackages() {
		for _, member := range pkg.Members {
			typ, ok := member.(*ssa.Type)
			if !ok {
				continue
			}

			// 获取类型信息
			underlyingType := typ.Type()

			// 检查值类型和指针类型是否实现接口
			checkTypes := []types.Type{
				underlyingType,                   // 值类型
				types.NewPointer(underlyingType), // 指针类型
			}

			for _, checkType := range checkTypes {
				if types.Implements(checkType, ifaceType.(*types.Interface)) {
					implementations = append(implementations, cg.getMethodsFromType(checkType, prog)...) // 获取方法集
				}

				// 检查嵌入式字段
				structType, ok := checkType.Underlying().(*types.Struct)
				if ok {
					for i := 0; i < structType.NumFields(); i++ {
						field := structType.Field(i)
						if field.Anonymous() { // 嵌入字段
							embeddedType := field.Type()
							if types.Implements(embeddedType, ifaceType.(*types.Interface)) {
								implementations = append(implementations, cg.getMethodsFromType(embeddedType, prog)...) // 嵌入字段的方法
							}
							if pointerType := types.NewPointer(embeddedType); types.Implements(pointerType, ifaceType.(*types.Interface)) {
								implementations = append(implementations, cg.getMethodsFromType(pointerType, prog)...)
							}
						}
					}
				}
			}
		}
	}

	return implementations
}

func (cg CallGraph) getMethodsFromType(typ types.Type, prog *ssa.Program) []*ssa.Function {
	var methods []*ssa.Function

	methodSet := prog.MethodSets.MethodSet(typ)
	for i := 0; i < methodSet.Len(); i++ {
		method := prog.MethodValue(methodSet.At(i))
		if method != nil {
			methods = append(methods, method)
		}
	}

	return methods
}

// ResolveParam returns the caller nodes of a parameter. This is used for tracing parameters back to their source.
func (cg CallGraph) ResolveParam(p *ssa.Parameter) []*ssa.Value {
	// Determine which argument we are in the parent function
	pFunc := p.Parent()
	pIdx := -1
	for i, arg := range pFunc.Params {
		if p.Pos() == arg.Pos() {
			pIdx = i
		}
	}
	// Check if pFunc is a method with a receiver
	isReceiver := pFunc.Signature.Recv() != nil && pIdx == 1

	// 如果不是接收者，调整索引
	if isReceiver {
		pIdx-- // 调整索引以匹配调用中的参数
	}

	var callerNodes []*ssa.Value
	// 遍历调用关系，提取对应的调用参数

	for _, rel := range cg[pFunc.String()] {
		//if rel.Instr == nil {
		//	return cg.ResolveParam()
		//}
		if rel.Instr == nil {
			for _, rel2 := range cg[rel.Fn.String()] {
				callerNodes = append(callerNodes, &rel2.Instr.Call.Args[pIdx])
			}
		} else {
			callerNodes = append(callerNodes, &rel.Instr.Call.Args[pIdx])
		}

	}
	return callerNodes
}

func (cg CallGraph) ResolveFreeVar(fv *ssa.FreeVar) []*ssa.Value {
	// 从FreeVar获取其父函数（通常是一个闭包）
	pFunc := fv.Parent()
	var callerNodes []*ssa.Value

	for _, rel := range cg[pFunc.String()] {
		if rel.Closure != nil {
			for _, value := range rel.Closure.Bindings {
				callerNodes = append(callerNodes, &value)
			}
		}

	}
	return callerNodes
}

// Memoize hashes an ssa.Value and then adds it to the Taint Map while updating the metadata
func (ta TaintAnalyzer) Memoize(val *ssa.Value, vulnerable bool) {
	switch (*val).(type) {
	case *ssa.Phi:
		// Don't want to memoize Phi nodes as recursion will then not check all edges
	default:
		// hash the ssa.Value
		hash := SSAvalToHash(val)
		// get the current map status
		map_status := ta.taint_map[hash]
		// increment the count
		new_count := map_status.Count + 1
		// create the new MapData struct
		mapping := MapData{Mapped: map_status.Mapped, Vulnerable: map_status.Vulnerable, Count: new_count}
		// update the Taint Map
		ta.taint_map[hash] = mapping
	}

}

// SSAvalToHash returns the hash of an ssa.Value to be used in the Taint Map
func SSAvalToHash(val *ssa.Value) uint64 {
	// convert the de-referenced ssa.Value to a byte array
	b_arrayPointer := []byte(fmt.Sprintf("%v", *val))
	// convert the byte array to a string
	val_string := string(b_arrayPointer)
	// if the ssa.Value has a parent, add that to the val_string to be used in the hash. Otherwise just hash the val_string
	if (*val).Parent() != nil {
		b_arrayParent := (*val).Parent().String()
		val_string += b_arrayParent
	}

	// hash the val_string
	hash := fnv1a.HashString64(val_string)
	return hash
}

// GrabSourceCode retrieves the specified line of source code from the specified file
func GrabSourceCode(filename string, lineNumber int) string {

	fileHandle, _ := os.Open(filename)
	defer fileHandle.Close()

	var buff bytes.Buffer
	scanner := bufio.NewScanner(fileHandle)
	scanner.Split(bufio.ScanLines)

	counter := 0

	for scanner.Scan() {
		counter++
		if lineNumber == counter {
			buff.WriteString(scanner.Text())
			break
		}
	}
	return buff.String()
}

// GenerateTaintedCode returns a TaintedCode struct that stores information (source code, filename, linenumber) for a line of code
func GenerateTaintedCode(pass *analysis.Pass, parent *ssa.Function, position token.Pos, pathID []int, isEnd bool) TaintedCode {
	vulnerable_code := pass.Fset.Position(position)

	// Evaluate $GOROOT environment variable so correct filepath is generated.
	expanded_filename := os.ExpandEnv(vulnerable_code.Filename)
	if _, err := os.Stat(expanded_filename); os.IsNotExist(err) {
		if strings.Contains(vulnerable_code.Filename, "$GOROOT") {
			vulnerable_code.Filename = strings.Replace(vulnerable_code.Filename, "$GOROOT", runtime.GOROOT(), 1)
		} else {
			vulnerable_code.Filename = "WARNING: Could not find the file at path: " + vulnerable_code.Filename
		}
	} else {
		vulnerable_code.Filename = expanded_filename
	}

	vulnerable_source_code := GrabSourceCode(vulnerable_code.Filename, vulnerable_code.Line)

	var parent_function_name string
	var parent_function_args string
	if parent == nil {
		parent_function_name = "<no parent>"
		parent_function_args = "<no parent - no args>"
	} else {
		parent_function_name = parent.Name()
		parent_function_args = strings.Split(parent.Signature.String(), "func")[1]
	}
	tainted_code := TaintedCode{
		SourceCode:     vulnerable_source_code,
		SourceFilename: vulnerable_code.Filename,
		SourceLineNum:  vulnerable_code.Line,
		ParentFunction: parent_function_name + " " + parent_function_args,
		PathID:         pathID,
		IsEnd:          isEnd,
	}
	return tainted_code
}
