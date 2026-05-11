package plugin

import (
	"fmt"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// PermissionType 权限类型枚举
type PermissionType string

const (
	PermExec      PermissionType = "exec"       // 执行外部程序 (python, node 等)
	PermFileRead  PermissionType = "file_read"   // 读取本地文件
	PermFileWrite PermissionType = "file_write"  // 写入本地文件
	PermNetwork   PermissionType = "network"     // 访问网络
)

// PermissionRequest 权限请求
type PermissionRequest struct {
	Type        PermissionType    `json:"type"`        // 权限类型
	Description string            `json:"description"`  // 可读描述
	Details     map[string]string `json:"details"`      // 附加信息 (URL, 文件路径, 命令等)
}

// PermissionCallback 权限回调函数
// 返回 true 表示允许, false 表示拒绝
type PermissionCallback func(req PermissionRequest) bool

// SecurityConfig 安全配置
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

	// 禁止的Lua全局变量
	ForbiddenGlobalVariables []string
}

// DefaultSecurityConfig 默认安全配置
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Timeout:    5000,
		MaxMemoryMB: 64,
		PreAuthorized: map[PermissionType]bool{},
		ForbiddenGlobalVariables: []string{
			"debug", "loadfile", "dofile", "loadstring",
			"collectgarbage", "newproxy",
		},
	}
}

// Sandbox 沙箱环境
type Sandbox struct {
	config *SecurityConfig
}

// NewSandbox 创建新的沙箱
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

// ValidateScript 验证脚本安全性
func (s *Sandbox) ValidateScript(script string) error {
	dangerousPatterns := []string{
		"dofile", "loadfile", "load", "loadstring",
		"debug.",
		"collectgarbage", "newproxy",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(script, pattern) {
			return fmt.Errorf("检测到危险函数调用: %s", pattern)
		}
	}

	return nil
}

// SetupSandbox 设置Lua沙箱环境
func (s *Sandbox) SetupSandbox(L *lua.LState) {
	for _, forbidden := range s.config.ForbiddenGlobalVariables {
		L.SetGlobal(forbidden, lua.LNil)
	}
}

// ExecuteWithSandbox 在沙箱中执行脚本
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

// CreateSecureEnvironment 创建安全环境
func CreateSecureEnvironment(config *SecurityConfig) *lua.LState {
	L := lua.NewState()

	sandbox := NewSandbox(config)
	sandbox.SetupSandbox(L)

	return L
}
