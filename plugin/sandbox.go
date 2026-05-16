package plugin

import (
	"fmt"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/ast"
	"github.com/yuin/gopher-lua/parse"
)

var forbiddenFunctions = []string{
	"dofile", "loadfile", "load", "loadstring",
	"collectgarbage", "newproxy",
}

var forbiddenGlobals = []string{
	"debug", "os", "io", "package",
}

type PermissionType string

const (
	PermExec      PermissionType = "exec"       // 执行外部程序 (python, node 等)
	PermFileRead  PermissionType = "file_read"  // 读取本地文件
	PermFileWrite PermissionType = "file_write" // 写入本地文件
	PermNetwork   PermissionType = "network"    // 访问网络
	PermSystem    PermissionType = "system"     // 系统操作 (os包危险函数)
)

type PermissionRequest struct {
	Type        PermissionType    `json:"type"`        // 权限类型
	Description string            `json:"description"` // 可读描述
	Details     map[string]string `json:"details"`     // 附加信息 (URL, 文件路径, 命令等)
}

type PermissionCallback func(req PermissionRequest) bool

type SecurityConfig struct {
	Timeout            int
	MaxMemoryMB        int
	PermissionCallback PermissionCallback
	PreAuthorized      map[PermissionType]bool
}

func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Timeout:       5000,
		MaxMemoryMB:   64,
		PreAuthorized: map[PermissionType]bool{},
	}
}

type Sandbox struct {
	config *SecurityConfig
}

func NewSandbox(config *SecurityConfig) *Sandbox {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	return &Sandbox{config: config}
}

func (s *Sandbox) RequestPermission(req PermissionRequest) bool {
	// 预授权检查
	if s.config.PreAuthorized != nil && s.config.PreAuthorized[req.Type] {
		return true
	}

	// 无回调则拒绝所有
	if s.config.PermissionCallback == nil {
		return false
	}

	return s.config.PermissionCallback(req)
}

func (s *Sandbox) ValidateScript(script string) error {
	reader := strings.NewReader(script)
	chunk, err := parse.Parse(reader, "<script>")
	if err != nil {
		return fmt.Errorf("parse script failed: %v", err)
	}

	if err := s.checkAST(chunk); err != nil {
		return err
	}
	return nil
}

func (s *Sandbox) checkAST(stmts []ast.Stmt) error {
	for _, stmt := range stmts {
		if err := s.checkStmt(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sandbox) checkStmt(stmt ast.Stmt) error {
	switch st := stmt.(type) {
	case *ast.FuncCallStmt:
		if err := s.checkExpr(st.Expr); err != nil {
			return err
		}
	case *ast.AssignStmt:
		for _, expr := range st.Lhs {
			if err := s.checkExpr(expr); err != nil {
				return err
			}
		}
		for _, expr := range st.Rhs {
			if err := s.checkExpr(expr); err != nil {
				return err
			}
		}
	case *ast.LocalAssignStmt:
		for _, expr := range st.Exprs {
			if err := s.checkExpr(expr); err != nil {
				return err
			}
		}
	case *ast.IfStmt:
		if err := s.checkExpr(st.Condition); err != nil {
			return err
		}
		if err := s.checkAST(st.Then); err != nil {
			return err
		}
		if err := s.checkAST(st.Else); err != nil {
			return err
		}
	case *ast.WhileStmt:
		if err := s.checkExpr(st.Condition); err != nil {
			return err
		}
		if err := s.checkAST(st.Stmts); err != nil {
			return err
		}
	case *ast.FuncDefStmt:
		if st.Func != nil {
			if err := s.checkExpr(st.Func); err != nil {
				return err
			}
			if err := s.checkAST(st.Func.Stmts); err != nil {
				return err
			}
		}
	case *ast.ReturnStmt:
		for _, expr := range st.Exprs {
			if err := s.checkExpr(expr); err != nil {
				return err
			}
		}
	case *ast.DoBlockStmt:
		if err := s.checkAST(st.Stmts); err != nil {
			return err
		}
	case *ast.RepeatStmt:
		if err := s.checkExpr(st.Condition); err != nil {
			return err
		}
		if err := s.checkAST(st.Stmts); err != nil {
			return err
		}
	case *ast.GenericForStmt:
		if err := s.checkAST(st.Stmts); err != nil {
			return err
		}
	case *ast.NumberForStmt:
		if err := s.checkAST(st.Stmts); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sandbox) checkExpr(expr ast.Expr) error {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.FuncCallExpr:
		if err := s.checkExpr(e.Func); err != nil {
			return err
		}
		if e.Receiver != nil {
			if err := s.checkExpr(e.Receiver); err != nil {
				return err
			}
		}
		for _, arg := range e.Args {
			if err := s.checkExpr(arg); err != nil {
				return err
			}
		}
	case *ast.IdentExpr:
		name := e.Value
		for _, forbidden := range forbiddenGlobals {
			if name == forbidden {
				return fmt.Errorf("function denied: %s", name)
			}
		}
		for _, forbidden := range forbiddenFunctions {
			if name == forbidden {
				return fmt.Errorf("dangerous function denied: %s()", forbidden)
			}
		}
	case *ast.AttrGetExpr:
		if err := s.checkExpr(e.Object); err != nil {
			return err
		}
		if err := s.checkExpr(e.Key); err != nil {
			return err
		}
		if ident, ok := e.Object.(*ast.IdentExpr); ok && ident.Value == "_G" {
			var keyValue string
			switch key := e.Key.(type) {
			case *ast.StringExpr:
				keyValue = key.Value
			case *ast.IdentExpr:
				keyValue = key.Value
			}
			for _, forbidden := range forbiddenFunctions {
				if keyValue == forbidden {
					return fmt.Errorf("dangerous function denied: _G.%s 或 _G[\"%s\"]", forbidden, forbidden)
				}
			}
		}
	case *ast.FunctionExpr:
		if err := s.checkAST(e.Stmts); err != nil {
			return err
		}
	case *ast.TableExpr:
		for _, field := range e.Fields {
			if err := s.checkExpr(field.Key); err != nil {
				return err
			}
			if err := s.checkExpr(field.Value); err != nil {
				return err
			}
		}
	case *ast.UnaryLenOpExpr:
		if err := s.checkExpr(e.Expr); err != nil {
			return err
		}
	case *ast.UnaryMinusOpExpr:
		if err := s.checkExpr(e.Expr); err != nil {
			return err
		}
	case *ast.UnaryNotOpExpr:
		if err := s.checkExpr(e.Expr); err != nil {
			return err
		}
	case *ast.ArithmeticOpExpr:
		if err := s.checkExpr(e.Lhs); err != nil {
			return err
		}
		if err := s.checkExpr(e.Rhs); err != nil {
			return err
		}
	case *ast.RelationalOpExpr:
		if err := s.checkExpr(e.Lhs); err != nil {
			return err
		}
		if err := s.checkExpr(e.Rhs); err != nil {
			return err
		}
	case *ast.LogicalOpExpr:
		if err := s.checkExpr(e.Lhs); err != nil {
			return err
		}
		if err := s.checkExpr(e.Rhs); err != nil {
			return err
		}
	case *ast.StringConcatOpExpr:
		if err := s.checkExpr(e.Lhs); err != nil {
			return err
		}
		if err := s.checkExpr(e.Rhs); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sandbox) SetupSandbox(L *lua.LState) {
	for _, forbidden := range forbiddenGlobals {
		L.SetGlobal(forbidden, lua.LNil)
	}
	for _, forbidden := range forbiddenFunctions {
		L.SetGlobal(forbidden, lua.LNil)
	}
}

func (s *Sandbox) ExecuteWithSandbox(L *lua.LState, script string, _ time.Duration) error {
	timeoutDuration := time.Duration(s.config.Timeout) * time.Millisecond
	done := make(chan error, 1)

	go func() {
		done <- L.DoString(script)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeoutDuration):
		return fmt.Errorf("script execution timeout: (%v)", timeoutDuration)
	}
}

func CreateSecureEnvironment(config *SecurityConfig) *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})

	lua.OpenBase(L)
	lua.OpenTable(L)
	lua.OpenString(L)
	lua.OpenMath(L)
	lua.OpenCoroutine(L)
	lua.OpenOs(L)

	sandbox := NewSandbox(config)
	sandboxOsFunctions(L, sandbox)
	sandbox.SetupSandbox(L)

	return L
}

func sandboxOsFunctions(L *lua.LState, sandbox *Sandbox) {
	osTable := L.GetGlobal("os").(*lua.LTable)

	dangerousFuncs := []string{"execute", "exit", "getenv", "remove", "rename", "tmpname"}

	for _, funcName := range dangerousFuncs {
		origFunc := osTable.RawGetString(funcName)
		if origFunc.Type() != lua.LTFunction {
			continue
		}
		origFn := origFunc.(*lua.LFunction)
		name := funcName // 创建闭包副本

		osTable.RawSetString(name, L.NewFunction(func(L *lua.LState) int {
			if !sandbox.RequestPermission(PermissionRequest{
				Type:        PermSystem,
				Description: "系统操作: os." + name,
				Details:     map[string]string{"function": name},
			}) {
				L.Push(lua.LNil)
				L.Push(lua.LString("permission denied: system"))
				return 2
			}

			numArgs := L.GetTop()
			L.Push(origFn)
			for i := 1; i <= numArgs; i++ {
				L.Push(L.Get(i))
			}
			L.Call(numArgs, -1)
			return L.GetTop()
		}))
	}
}
