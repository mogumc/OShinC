package plugin

import (
	"fmt"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/ast"
	"github.com/yuin/gopher-lua/parse"
)

// 禁止直接调用的危险函数名
var forbiddenFunctions = []string{
	"dofile", "loadfile", "load", "loadstring",
	"collectgarbage", "newproxy",
}

// 禁止访问的全局表/变量名
var forbiddenGlobals = []string{
	"debug", "os", "io", "package",
}

type PermissionType string

const (
	PermExec      PermissionType = "exec"       // 执行外部程序 (python, node 等)
	PermFileRead  PermissionType = "file_read"  // 读取本地文件
	PermFileWrite PermissionType = "file_write" // 写入本地文件
	PermNetwork   PermissionType = "network"    // 访问网络
)

type PermissionRequest struct {
	Type        PermissionType    `json:"type"`        // 权限类型
	Description string            `json:"description"` // 可读描述
	Details     map[string]string `json:"details"`     // 附加信息 (URL, 文件路径, 命令等)
}

// 返回 true 表示允许, false 表示拒绝
type PermissionCallback func(req PermissionRequest) bool

type SecurityConfig struct {
	// 超时设置 (毫秒)
	Timeout int

	// 最大内存使用 (MB)
	MaxMemoryMB int

	// 权限回调：当脚本请求敏感操作时，由宿主程序决定是否允许
	// 为 nil 时所有敏感操作均被拒绝
	PermissionCallback PermissionCallback

	// 预授权列表：跳过回调直接允许的权限类型
	// 相当于安全配置中的白名单
	PreAuthorized map[PermissionType]bool
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

// RequestPermission 请求权限：检查预授权或调用回调
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

// ValidateScript 使用AST解析验证脚本安全性，检测危险函数调用
func (s *Sandbox) ValidateScript(script string) error {
	reader := strings.NewReader(script)
	chunk, err := parse.Parse(reader, "<script>")
	if err != nil {
		return fmt.Errorf("脚本解析失败: %v", err)
	}

	if err := s.checkAST(chunk); err != nil {
		return err
	}
	return nil
}

// checkAST 遍历AST检测危险函数调用
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
		// 检查 Receiver.Method 调用方式（如 os.execute）
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
		// 检查是否引用了危险全局变量
		for _, forbidden := range forbiddenGlobals {
			if name == forbidden {
				return fmt.Errorf("检测到禁止使用全局变量: %s", name)
			}
		}
		// 检查是否为危险函数名（用于检测 func() 调用）
		for _, forbidden := range forbiddenFunctions {
			if name == forbidden {
				return fmt.Errorf("检测到禁止调用的危险函数: %s()", forbidden)
			}
		}
	case *ast.AttrGetExpr:
		if err := s.checkExpr(e.Object); err != nil {
			return err
		}
		if err := s.checkExpr(e.Key); err != nil {
			return err
		}
		// 检查 _G["load"] 或 _G.load 等绕过方式
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
					return fmt.Errorf("检测到通过 _G 访问危险函数: _G.%s 或 _G[\"%s\"]", forbidden, forbidden)
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

// SetupSandbox 设置Lua沙箱环境
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
		return fmt.Errorf("脚本执行超时 (%v)", timeoutDuration)
	}
}

func CreateSecureEnvironment(config *SecurityConfig) *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})

	// 仅加载安全的库
	lua.OpenBase(L)      // 基础函数（print, pairs, ipairs 等）
	lua.OpenTable(L)     // table 库
	lua.OpenString(L)    // string 库
	lua.OpenMath(L)      // math 库
	lua.OpenCoroutine(L) // coroutine 库

	sandbox := NewSandbox(config)
	sandbox.SetupSandbox(L)

	return L
}
