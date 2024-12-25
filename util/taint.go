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
	"go/token"
	"log"
	"strings"

	"golang.org/x/tools/go/analysis"

	"golang.org/x/tools/go/ssa"
)

// TaintedCode is a struct that contains information about the vulnerable line of code
type TaintedCode struct {
	SourceCode     string
	SourceFilename string
	SourceLineNum  int
	ParentFunction string
	PathID         []int
	IsEnd          bool
}

// MapData is a struct that contains information about each hash
type MapData struct {
	Mapped     bool // whether a hash has already been mapped
	Vulnerable bool // whether a hash has been found vulnerable
	Count      int  // the number of times a hash has been visited
}

// TaintAnalyzer is a struct that contains information about each taint analyzer
type TaintAnalyzer struct {
	taint_map   map[uint64]MapData
	TaintSource []TaintedCode
	pass        *analysis.Pass
	location    token.Pos
}

// CreateTaintAnalyzer returns a new TaintAnalyzer struct
func CreateTaintAnalyzer(pass *analysis.Pass, location token.Pos) TaintAnalyzer {
	return TaintAnalyzer{
		make(map[uint64]MapData),
		[]TaintedCode{},
		pass,
		location,
	}
}

// ContainsTaint analyzes the ssa.Value, recursively traces the value to all possible sources, and returns True if any of the sources are vulnerable. It returns False otherwise.
func (ta *TaintAnalyzer) ContainsTaint(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph) bool {
	return ta.ContainsTaintRecurse(startCall, val, cg, 0, []ssa.Value{}, []int{0})
}

// 和tabby一样的是，gokart也没有用逆拓扑（GI），而是用递归来解决问题。
// pathID 用来处理多路径输出，但是我搞的算法容易造成路径爆炸（指数级增长），暂时先不实现了。
func (ta *TaintAnalyzer) ContainsTaintRecurse(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph, depth int, visitedMutable []ssa.Value, pathID []int) bool {
	var isEnd bool

	if *val == nil {
		return false
	}
	if Config.Debug {
		out := ""
		for i := 0; i < depth; i++ {
			out += "  "
		}
		log.Printf("%s%s (%T)\n", out, *val, *val)
	}

	call, isCall := (*val).(*ssa.Call)
	if isCall {
		//A function call cannot become tainted from itself This is due to a bug with how we handle referrers. Since we
		//check all function calls, past and future, we need to make sure to ignore the starting function call
		//This makes sure we dont duplicate findings by having one parameter infect other parameters
		if startCall == &call.Call {
			return false
		}
	}

	//We have already seen this buffer, assume its fine
	for _, visitedVal := range visitedMutable {
		if *val == visitedVal {
			return false
		}
	}

	// Memoize the ssa.Value
	map_status1 := ta.taint_map[SSAvalToHash(val)]
	ta.Memoize(val, map_status1.Vulnerable)
	// Store the memoization status in map_status
	map_status := ta.taint_map[SSAvalToHash(val)]

	// if the ssa.Value hash has been seen over fifty times, return false because it is likely an infinite loop
	if map_status.Count > 20 {
		if Config.Debug {
			log.Printf("Overflow detected, breaking the infinite loop")
		}

		return false
	}
	// if the ssa.Value hash has already been mapped, return it's vulnerable status
	if map_status.Mapped {
		return map_status.Vulnerable
	}

	//default set vulnerable to false, this may not be necessary anymore
	vulnerable := false

	switch expr := (*val).(type) {
	case *ssa.Const:
		vulnerable = false
	case *ssa.Parameter:
		// Check if this function call is part of the tainted function source list
		globalPkgName := (expr).Parent().Pkg.Pkg.Name()
		if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
			for _, funcName := range val {
				if (expr).Name() == funcName {
					vulnerable = true
				}
			}
		}

		for pkg, types_ := range VulnTypes {
			for _, type_ := range types_ {
				if strings.TrimPrefix(expr.Type().String(), "*") == pkg+"."+type_ {
					vulnerable = true
				}
			}
		}

		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		if len(values) > 0 {
			for i, value := range values {
				if ta.ContainsTaintRecurse(startCall, value, cg, depth+1, visitedMutable, append(pathID, i)) {
					vulnerable = true
				}
			}

		}
	case *ssa.FreeVar: //闭包相关，gokart未实现这个功能。
		//vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)

		// 获取自由变量所属的函数（通常是闭包或其父函数）
		globalPkgName := (expr).Parent().Pkg.Pkg.Name()

		// 检查是否这个自由变量属于敏感函数的一部分
		if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
			for _, funcName := range val {
				if (expr).Name() == funcName {
					vulnerable = true
				}
			}
		}

		// 检查自由变量的类型是否在敏感类型列表中
		for pkg, types_ := range VulnTypes {
			for _, type_ := range types_ {
				if strings.TrimPrefix(expr.Type().String(), "*") == pkg+"."+type_ {
					vulnerable = true
				}
			}
		}

		// 对自由变量进行敏感性分析
		var values []*ssa.Value
		values = cg.ResolveFreeVar(expr)

		if len(values) > 0 {
			for i, value := range values {
				if ta.ContainsTaintRecurse(startCall, value, cg, depth+1, visitedMutable, append(pathID, i)) {
					vulnerable = true
				}
			}
		}
	case *ssa.Function: //函数变量，goakrt未实现该功能
		// Assume that the user cannot create their own functions
		vulnerable = false
	case *ssa.Field:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.Next: //Iterator相关
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.Iter, cg, depth+1, visitedMutable, pathID)
	case *ssa.TypeAssert:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.Range:
		vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.Phi: //合并数据流的情况
		mapping := MapData{Mapped: true, Vulnerable: false}
		ta.taint_map[SSAvalToHash(val)] = mapping
		for _, edge := range (*expr).Edges {

			// this if statement is to prevent infiinite loop
			if edge != expr {
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &edge, cg, depth+1, visitedMutable, pathID)
			}
		}
	case *ssa.UnOp:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.BinOp:
		result1 := ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, append(pathID, 0))
		result2 := ta.ContainsTaintRecurse(startCall, &expr.Y, cg, depth+1, visitedMutable, append(pathID, 1))
		vulnerable = result1 || result2
	case *ssa.Extract: //处理多返回值，expr.Tuple是返回值列表
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Tuple, cg, depth+1, visitedMutable, pathID)
	case *ssa.Call: // 处理函数调用
		callFunc, ok := (expr.Call.Value).(*ssa.Function)
		if ok { // 判断是否为source
			globalPkgName := callFunc.Pkg.Pkg.Path()
			if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
				for _, funcName := range val {
					if callFunc.Name() == funcName {
						vulnerable = true
						isEnd = true
					}
				}
			}
		}
		//为什么这里一定是Static的？不是会咋样？？
		//此处改成了*ssa.Function. 我在callgraph构建部分已经解决了不少特殊情况，这里直接改成Function看看。
		if dest, ok := expr.Call.Value.(*ssa.Function); dest != nil && ok {
			returns := ReturnValues(dest)

			/* If return values of function can't be determined then we run under the assumption
			 * that if you can trust the arguments to the function, then you can trust the return value of the function.
			 */
			if len(returns) > 0 {
				for _, retval := range returns {
					if len(retval) > 0 {
						//只处理单返回值情况。
						vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &retval[0], cg, depth+1, visitedMutable, pathID)
					}
				}
			} else {
				for i, arg := range expr.Call.Args {
					//防止和fieldaddr发生死循环。假设不是嵌入式字段的情况，必须有一个UnOp（点号），而不是直接FieldAddr
					//TODO 看看这个检测能不能改到visitedMutable里。
					if _, ok := arg.(*ssa.FieldAddr); ok {
						continue
					}

					if ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable, append(pathID, i)) { //loop C
						vulnerable = true
					}
				}
			}
		} else {
			for _, arg := range expr.Call.Args { //其他情况。
				vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable, pathID) //loop C
			}
		}
	case *ssa.Slice: // 对切片的每个元素都做了处理
		valSlice := ssa.Slice(*expr)
		valSliceX := valSlice.X
		vulnerable = ta.ContainsTaintRecurse(startCall, &valSliceX, cg, depth+1, visitedMutable, pathID) //loop D
		//原作者真的测试过这部分内容吗？要不是好奇测试一下，恐怕就略过了。根本不行呀。
		refs := valSlice.Referrers()
		for _, ref := range *refs {
			if indexAddr, ok := ref.(*ssa.IndexAddr); ok {
				for _, instr := range *indexAddr.Referrers() {
					if store, isStore := instr.(*ssa.Store); isStore {
						newMutable := make([]ssa.Value, len(visitedMutable)+1)
						copy(newMutable, visitedMutable)
						newMutable = append(newMutable, *val)
						vulnerable = ta.ContainsTaintRecurse(startCall, &store.Val, cg, depth+1, newMutable, pathID)
					}

				}
			}

			//expr, isVal := ref.(ssa.Value)
			//if isVal {
			//	newMutable := make([]ssa.Value, len(visitedMutable)+1)
			//	copy(newMutable, visitedMutable)
			//	newMutable = append(newMutable, *val)
			//	if ta.ContainsTaintRecurse(startCall, &expr, cg, depth+1, newMutable, append(pathID, i)) {
			//		vulnerable = true
			//	}
			//}
		}
	case *ssa.MakeSlice:
		// MakeSlice is only used for new allocations and, as such, is
		// inherently safe.
		vulnerable = false
	case *ssa.Convert:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.ChangeType:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.MakeInterface:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.MakeMap:
		//这里应该会有误报，mapUpdate没考虑先后顺序。后续可以写个算法
		//MakeMap的Refferers有MakeMap, MapUpdate和MapLookUp, 只需要关注第二个即可。
		referrers := *expr.Referrers()
		for i, instr := range referrers {
			if mapUpdate, ok := instr.(*ssa.MapUpdate); ok {
				isKeyVul := ta.ContainsTaintRecurse(startCall, &mapUpdate.Key, cg, depth+1, visitedMutable, append(pathID, i))
				isValueVul := ta.ContainsTaintRecurse(startCall, &mapUpdate.Value, cg, depth+1, visitedMutable, append(pathID, i))
				vulnerable = isKeyVul || isValueVul
			}
		}
	case *ssa.MakeClosure:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.Fn, cg, depth+1, visitedMutable, pathID)
		for i, val := range expr.Bindings {
			if ta.ContainsTaintRecurse(startCall, &val, cg, depth+1, visitedMutable, append(pathID, i)) {
				vulnerable = true
			}
		}
		//这部分重点关注，有可能导致漏报
	case *ssa.Lookup:
		// Traces not only the collection but also the source of the index
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable, pathID)
	case *ssa.Index:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID) || ta.ContainsTaintRecurse(startCall, &expr.Index, cg, depth+1, visitedMutable, pathID)
	case *ssa.ChangeInterface:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.IndexAddr:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
	case *ssa.FieldAddr:
		vulnerable = ta.ContainsTaintRecurse(startCall, &expr.X, cg, depth+1, visitedMutable, pathID)
		//嵌入式字段的情况：
		refs := *expr.Referrers()
		for i, ref := range refs {
			if call, ok := ref.(*ssa.Call); ok {
				var value ssa.Value = call
				if ta.ContainsTaintRecurse(startCall, &value, cg, depth+1, visitedMutable, append(pathID, i)) {
					vulnerable = true
				}
			}
		}

		if Config.WebMode {
			//beego框架中的Source, Context对象的第三个（也就是Request，此时Field=2)
			//由于这个source不是call，所以未来最好改到配置文件里
			//TODO: 非Call类型的Source改到配置文件里
			tmp := expr.X.Type().String()
			tmp2 := expr.Field
			if tmp == "*github.com/beego/beego/v2/server/web/context.Context" && tmp2 == 2 {
				vulnerable = true
			}
		}

	case *ssa.Alloc:
		// Check all the references to this memory
		alloc_refs := expr.Referrers()
		vulnerable = false

		mapping := MapData{Mapped: true, Vulnerable: false}
		ta.taint_map[SSAvalToHash(val)] = mapping

		for alloc_item := range *alloc_refs {
			alloc_ref := (*alloc_refs)[alloc_item]

			switch instr := (alloc_ref).(type) {
			case *ssa.IndexAddr:
				for indexaddr_ref_idx := range *instr.Referrers() {
					indexaddr_ref := (*instr.Referrers())[indexaddr_ref_idx]
					switch instr2 := (indexaddr_ref).(type) {
					// If the variable is assigned to something else, check
					// the new assignment
					case *ssa.Store:
						if ta.ContainsTaintRecurse(startCall, &instr2.Val, cg, depth+1, visitedMutable, pathID) { //loop A -- I think this might be causing the problem
							vulnerable = true
						}
					}
				}

			case *ssa.FieldAddr:

				vulnerable = ta.processStructStoreRecurse(startCall, val, cg, depth, visitedMutable, instr, 0, vulnerable, pathID)
			case *ssa.MakeClosure:
				continue
			case *ssa.MakeInterface:
				// 带方法的结构体，作为参数被传递并调用，就会有这种情况。

				for _, ins := range *instr.Referrers() {
					if call, ok := ins.(*ssa.Call); ok {
						var value ssa.Value = call
						vulnerable = ta.ContainsTaintRecurse(startCall, &value, cg, depth+1, visitedMutable, pathID)
					}
				}
			}

			var items []*ssa.Value
			visitedFuncs := make(map[*ssa.Function]bool)
			operand_items := alloc_ref.Operands(items)
			for _, operand_item := range operand_items {
				// 这一步考虑引用传递的情况，测试了gosec的引用传递，其实误报率也挺高的，根本没分析过程，和我这块写的差不多。
				// 但是需要考虑不为*ssa.Function的情况，又要写一大堆。
				// TODO: 除了*ssa.Function，还有其他情况的，但暂时先不考虑
				if _, ok := (*operand_item).(*ssa.Function); ok {
					vulnerable = vulnerable || ta.analyzeFunction(operand_item, VulnGlobalFuncs, 0, visitedFuncs)
				}

				if ta.ContainsTaintRecurse(startCall, operand_item, cg, depth+1, visitedMutable, pathID) {
					vulnerable = true
				}
			}
		}
	case *ssa.Global:
		//global变量处理，暂时不看了。
		vulnerable = !Config.GlobalsSafe
		globalPkgName := (expr).Package().Pkg.Name()
		if Config.Debug {
			log.Println("expr", expr, expr.Package())
			log.Println("gloablPkgName", globalPkgName, *val)
			log.Println(VulnGlobalVars)
		}

		if val, ok := VulnGlobalVars[globalPkgName]; ok {
			for _, funcName := range val {
				if (expr).Name() == funcName {
					if Config.Debug {
						log.Println(expr.Name())
						log.Println(funcName)
					}

					vulnerable = true
				}
			}
		}
	case nil:
		vulnerable = false
	default:
		vulnerable = true
		if Config.Debug {
			log.Printf("Unknown SSA type found: %T\n", expr)
		}
	}

	// Memoize the ssa.Value along with whether or not it is vulnerable
	ta.Memoize(val, vulnerable)

	/* If the taint analysis reaches a vulnerable ssa.Value,
	 * then store the information about the state to display to the analyst as untrusted input.
	 */
	if vulnerable {
		tempTaintedCode := GenerateTaintedCode(ta.pass, (*val).Parent(), (*val).Pos(), pathID, isEnd)
		if tempTaintedCode.SourceLineNum > 0 {

			//这个判断导致没法多路输出路径。
			//有两个想法，1是对CallGraph的CGRelation加一个isVul的判断。最后在CallGraph里寻找路径输出。可以不注释这段。
			//另一个想法是直接在递归里添加pathID,最后存到TaintSource里，稍微改下输出算法就行了。

			// Make sure that we don't output duplicate source code lines in Verbose Output
			//duplicateSourceCode := false
			//for _, current := range ta.TaintSource {
			//	if tempTaintedCode.SourceLineNum == current.SourceLineNum {
			//		duplicateSourceCode = true
			//		break
			//	}
			//}

			//if !duplicateSourceCode {
			ta.TaintSource = append(ta.TaintSource, tempTaintedCode)
			//}
		}
	}

	return vulnerable
}

// 处理嵌套结构体
func (ta TaintAnalyzer) processStructStoreRecurse(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph, depth int, visitedMutable []ssa.Value, instr *ssa.FieldAddr, maxDepth int, vulnerable bool, pathID []int) bool {
	if maxDepth > 3 {
		return vulnerable
	}

	refs := *instr.Referrers()
	for _, ref := range refs {
		expr, isStore := (ref).(*ssa.Store)
		if isStore {
			newMutable := make([]ssa.Value, len(visitedMutable)+1)
			copy(newMutable, visitedMutable)
			newMutable = append(newMutable, *val)
			vulnerable = vulnerable || ta.ContainsTaintRecurse(startCall, &expr.Val, cg, depth, newMutable, pathID)
			return vulnerable
		}

		if refInstr, ok := ref.(*ssa.FieldAddr); ok {
			vulnerable = ta.processStructStoreRecurse(startCall, val, cg, depth, visitedMutable, refInstr, maxDepth+1, vulnerable, pathID)
		}
	}

	return vulnerable
}

func (ta TaintAnalyzer) analyzeFunction(operandItem *ssa.Value, VulnGlobalFuncs map[string][]string, depth int, visitedFuncs map[*ssa.Function]bool) bool {
	if depth > 10 { // 防止无限递归
		return false
	}

	if operandItem == nil {
		return false
	}

	function, ok := (*operandItem).(*ssa.Function)
	if !ok {
		return false
	}

	// 检查是否已分析过该函数
	if visitedFuncs[function] {
		return false
	}

	visitedFuncs[function] = true
	defer delete(visitedFuncs, function) // 分析完后清理标记

	for _, block := range function.Blocks {
		for _, instr := range block.Instrs {
			// 检查指令是否为函数调用
			if expr, ok := instr.(*ssa.Call); ok {
				callFunc, ok := expr.Call.Value.(*ssa.Function)
				if !ok {
					continue
				}

				// 检查是否为 Source
				globalPkgName := callFunc.Pkg.Pkg.Path()
				if val, ok := VulnGlobalFuncs[globalPkgName]; ok {
					for _, funcName := range val {
						if callFunc.Name() == funcName {
							return true // 找到漏洞 Source
						}
					}
				} else {
					// 递归分析
					if ta.analyzeFunction(&expr.Call.Value, VulnGlobalFuncs, depth+1, visitedFuncs) {
						return true
					}
				}
			}
		}
	}

	return false
}
