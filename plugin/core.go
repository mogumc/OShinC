package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

type PluginRequest struct {
	Method  string                 `json:"method"`
	Action  string                 `json:"action"`
	Params  map[string]interface{} `json:"params"`
	Script  string                 `json:"script"`
	Timeout int                    `json:"timeout"` // milliseconds
	Mode    string                 `json:"mode"`
}

type PluginResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
	Time    int64       `json:"time"`
}

type Core struct {
	securityConfig *SecurityConfig
	sandbox        *Sandbox
	LogWriter      io.Writer
}

func NewCore() *Core {
	config := DefaultSecurityConfig()
	return &Core{
		securityConfig: config,
		sandbox:        NewSandbox(config),
		LogWriter:      os.Stdout,
	}
}

func NewCoreWithConfig(config *SecurityConfig) *Core {
	return &Core{
		securityConfig: config,
		sandbox:        NewSandbox(config),
		LogWriter:      os.Stdout,
	}
}

func ExecuteScript(script string, params map[string]interface{}) (interface{}, error) {
	core := NewCore()
	req := PluginRequest{
		Method: "main",
		Params: params,
		Script: script,
		Mode:   "direct",
	}
	resp := core.Execute(req)
	if resp.Code != 0 {
		return nil, fmt.Errorf("execution failed: %s", resp.Message)
	}
	return resp.Data, nil
}

func ExecuteScriptWithConfig(script string, params map[string]interface{}, config *SecurityConfig) (interface{}, error) {
	core := NewCoreWithConfig(config)
	req := PluginRequest{
		Method: "main",
		Params: params,
		Script: script,
		Mode:   "direct",
	}
	resp := core.Execute(req)
	if resp.Code != 0 {
		return nil, fmt.Errorf("execution failed: %s", resp.Message)
	}
	return resp.Data, nil
}

func ExecuteRoute(script string, action string, params map[string]interface{}) (interface{}, error) {
	core := NewCore()
	req := PluginRequest{
		Action: action,
		Params: params,
		Script: script,
		Mode:   "route",
	}
	resp := core.Execute(req)
	if resp.Code != 0 {
		return nil, fmt.Errorf("execution failed: %s", resp.Message)
	}
	return resp.Data, nil
}

func ExecutePipeline(script string, params map[string]interface{}) (interface{}, error) {
	core := NewCore()
	req := PluginRequest{
		Params: params,
		Script: script,
		Mode:   "pipeline",
	}
	resp := core.Execute(req)
	if resp.Code != 0 {
		return nil, fmt.Errorf("execution failed: %s", resp.Message)
	}
	return resp.Data, nil
}

func (c *Core) Execute(req PluginRequest) PluginResponse {
	startTime := time.Now()

	if err := c.validateRequest(req); err != nil {
		return PluginResponse{
			Code:    -1,
			Message: fmt.Sprintf("Invalid request: %v", err),
			Time:    time.Since(startTime).Milliseconds(),
		}
	}

	if err := c.sandbox.ValidateScript(req.Script); err != nil {
		return PluginResponse{
			Code:    -5,
			Message: fmt.Sprintf("Script security check failed: %v", err),
			Time:    time.Since(startTime).Milliseconds(),
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = c.securityConfig.Timeout
	}

	L := CreateSecureEnvironment(c.securityConfig)
	defer L.Close()

	c.registerBuiltinFunctions(L)

	if err := c.sandbox.ExecuteWithSandbox(L, req.Script, time.Duration(timeout)*time.Millisecond); err != nil {
		return PluginResponse{
			Code:    -2,
			Message: fmt.Sprintf("Script execution error: %v", err),
			Time:    time.Since(startTime).Milliseconds(),
		}
	}

	mode := req.Mode
	if mode == "" {
		mode = "direct"
	}

	var result interface{}
	var err error

	switch mode {
	case "direct":
		if req.Method == "" {
			req.Method = "main"
		}
		result, err = c.callLuaFunction(L, req.Method, req.Params)
	case "route":
		if req.Action == "" {
			req.Action = "default"
		}
		result, err = c.routeByAction(L, req.Action, req.Params)
	case "pipeline":
		result, err = c.executePipeline(L, req.Params)
	default:
		return PluginResponse{
			Code:    -4,
			Message: fmt.Sprintf("Unknown execution mode: %s", mode),
			Time:    time.Since(startTime).Milliseconds(),
		}
	}

	if err != nil {
		return PluginResponse{
			Code:    -3,
			Message: fmt.Sprintf("Execution error: %v", err),
			Time:    time.Since(startTime).Milliseconds(),
		}
	}

	return PluginResponse{
		Code:    0,
		Message: "success",
		Data:    result,
		Time:    time.Since(startTime).Milliseconds(),
	}
}

func (c *Core) validateRequest(req PluginRequest) error {
	if req.Script == "" {
		return fmt.Errorf("script is required")
	}
	return nil
}

func (c *Core) registerBuiltinFunctions(L *lua.LState) {
	L.SetGlobal("request_permission", L.NewFunction(func(L *lua.LState) int {
		permType := L.CheckString(1)
		desc := L.OptString(2, "")
		pt := PermissionType(permType)
		if desc == "" {
			desc = string(pt)
		}
		L.Push(lua.LBool(c.sandbox.RequestPermission(PermissionRequest{
			Type:        pt,
			Description: desc,
		})))
		return 1
	}))

	L.SetGlobal("http_request", L.NewFunction(func(L *lua.LState) int {
		url := L.CheckString(1)
		method := L.OptString(2, "GET")
		body := L.OptString(3, "")

		if !c.sandbox.RequestPermission(PermissionRequest{
			Type:        PermNetwork,
			Description: "网络请求: " + method + " " + url,
			Details:     map[string]string{"url": url, "method": method},
		}) {
			L.Push(lua.LString(""))
			L.Push(lua.LString("permission denied: network"))
			return 2
		}

		result, err := c.httpRequest(url, method, body)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf(`{"error":"%s"}`, err.Error())))
			return 1
		}

		L.Push(lua.LString(string(result)))
		return 1
	}))

	L.SetGlobal("json_parse", L.NewFunction(func(L *lua.LState) int {
		jsonStr := L.CheckString(1)

		var data interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}

		luaVal := c.goToLuaValue(L, data)
		L.Push(luaVal)
		return 1
	}))

	L.SetGlobal("json_stringify", L.NewFunction(func(L *lua.LState) int {
		val := L.CheckAny(1)

		goVal := c.luaToGoValue(val)
		jsonBytes, err := json.Marshal(goVal)
		if err != nil {
			L.Push(lua.LString(""))
			L.Push(lua.LString(err.Error()))
			return 2
		}

		L.Push(lua.LString(string(jsonBytes)))
		return 1
	}))

	logWriter := c.LogWriter
	if logWriter == nil {
		logWriter = os.Stdout
	}
	L.SetGlobal("log", L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		fmt.Fprintf(logWriter, "[Lua Log] %s\n", msg)
		return 0
	}))

	L.SetGlobal("execute_external", L.NewFunction(func(L *lua.LState) int {
		program := L.CheckString(1)
		scriptOrArg := L.OptString(2, "")

		if !c.sandbox.RequestPermission(PermissionRequest{
			Type:        PermExec,
			Description: "执行外部程序: " + program,
			Details:     map[string]string{"program": program, "arg": scriptOrArg},
		}) {
			L.Push(lua.LString(""))
			L.Push(lua.LString("permission denied: exec"))
			return 2
		}

		stdout, err := c.executeExternal(program, scriptOrArg)
		if err != nil {
			L.Push(lua.LString(stdout))
			L.Push(lua.LString(err.Error()))
			return 2
		}

		L.Push(lua.LString(stdout))
		return 1
	}))

	L.SetGlobal("read_file", L.NewFunction(func(L *lua.LState) int {
		filePath := L.CheckString(1)

		if !c.sandbox.RequestPermission(PermissionRequest{
			Type:        PermFileRead,
			Description: "读取文件: " + filePath,
			Details:     map[string]string{"path": filePath},
		}) {
			L.Push(lua.LString(""))
			L.Push(lua.LString("permission denied: file_read"))
			return 2
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			L.Push(lua.LString(""))
			L.Push(lua.LString(err.Error()))
			return 2
		}

		L.Push(lua.LString(string(content)))
		return 1
	}))

	L.SetGlobal("write_file", L.NewFunction(func(L *lua.LState) int {
		filePath := L.CheckString(1)
		content := L.CheckString(2)

		if !c.sandbox.RequestPermission(PermissionRequest{
			Type:        PermFileWrite,
			Description: "写入文件: " + filePath,
			Details:     map[string]string{"path": filePath},
		}) {
			L.Push(lua.LBool(false))
			L.Push(lua.LString("permission denied: file_write"))
			return 2
		}

		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			L.Push(lua.LBool(false))
			L.Push(lua.LString(err.Error()))
			return 2
		}

		L.Push(lua.LBool(true))
		return 1
	}))
}

func (c *Core) executeExternal(program string, scriptOrArg string) (string, error) {
	var cmd *exec.Cmd

	if strings.HasSuffix(scriptOrArg, ".py") || strings.HasSuffix(scriptOrArg, ".js") ||
		strings.HasSuffix(scriptOrArg, ".lua") || strings.HasSuffix(scriptOrArg, ".sh") ||
		strings.HasSuffix(scriptOrArg, ".bat") {
		cmd = exec.Command(program, scriptOrArg)
	} else {
		switch strings.ToLower(program) {
		case "python", "python3":
			cmd = exec.Command(program, "-c", scriptOrArg)
		case "node", "nodejs":
			cmd = exec.Command(program, "-e", scriptOrArg)
		case "lua":
			cmd = exec.Command(program, "-e", scriptOrArg)
		default:
			cmd = exec.Command(program, scriptOrArg)
		}
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (c *Core) httpRequest(url, method, body string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OShin-core/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(result))
	}

	return result, nil
}

func (c *Core) callLuaFunction(L *lua.LState, methodName string, params map[string]interface{}) (interface{}, error) {
	fn := L.GetGlobal(methodName)
	if fn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("function '%s' not found", methodName)
	}

	args := make([]lua.LValue, 0)
	if params != nil {
		luaParams := L.NewTable()
		for key, value := range params {
			luaParams.RawSetString(key, c.goToLuaValue(L, value))
		}
		args = append(args, luaParams)
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, args...); err != nil {
		return nil, err
	}

	ret := L.Get(-1)
	L.Pop(1)

	return c.luaToGoValue(ret), nil
}

func (c *Core) routeByAction(L *lua.LState, action string, params map[string]interface{}) (interface{}, error) {
	routes := L.GetGlobal("routes")
	if routes.Type() != lua.LTTable {
		return nil, fmt.Errorf("routes table not found")
	}

	handler := routes.(*lua.LTable).RawGetString(action)
	if handler.Type() != lua.LTFunction {
		return nil, fmt.Errorf("handler for action '%s' not found", action)
	}

	args := make([]lua.LValue, 0)
	if params != nil {
		luaParams := L.NewTable()
		for key, value := range params {
			luaParams.RawSetString(key, c.goToLuaValue(L, value))
		}
		args = append(args, luaParams)
	}

	if err := L.CallByParam(lua.P{
		Fn:      handler.(lua.LValue),
		NRet:    1,
		Protect: true,
	}, args...); err != nil {
		return nil, err
	}

	ret := L.Get(-1)
	L.Pop(1)

	return c.luaToGoValue(ret), nil
}

func (c *Core) executePipeline(L *lua.LState, params map[string]interface{}) (interface{}, error) {
	pipelineFn := L.GetGlobal("pipeline")
	if pipelineFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("pipeline function not found")
	}

	args := make([]lua.LValue, 0)
	if params != nil {
		luaParams := L.NewTable()
		for key, value := range params {
			luaParams.RawSetString(key, c.goToLuaValue(L, value))
		}
		args = append(args, luaParams)
	}

	if err := L.CallByParam(lua.P{
		Fn:      pipelineFn.(lua.LValue),
		NRet:    1,
		Protect: true,
	}, args...); err != nil {
		return nil, err
	}

	ret := L.Get(-1)
	L.Pop(1)

	return c.luaToGoValue(ret), nil
}

func (c *Core) goToLuaValue(L *lua.LState, val interface{}) lua.LValue {
	switch v := val.(type) {
	case nil:
		return lua.LNil
	case bool:
		if v {
			return lua.LTrue
		}
		return lua.LFalse
	case int:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []interface{}:
		tbl := L.NewTable()
		for i, item := range v {
			tbl.RawSetInt(i+1, c.goToLuaValue(L, item))
		}
		return tbl
	case map[string]interface{}:
		tbl := L.NewTable()
		for key, item := range v {
			tbl.RawSetString(key, c.goToLuaValue(L, item))
		}
		return tbl
	default:
		return lua.LString(fmt.Sprintf("%v", v))
	}
}

func (c *Core) luaToGoValue(val lua.LValue) interface{} {
	switch v := val.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LNumber:
		return float64(v)
	case lua.LString:
		return string(v)
	case *lua.LTable:
		if c.isLuaTableArray(v) {
			arr := make([]interface{}, 0)
			v.ForEach(func(_ lua.LValue, val lua.LValue) {
				arr = append(arr, c.luaToGoValue(val))
			})
			return arr
		}
		m := make(map[string]interface{})
		v.ForEach(func(key lua.LValue, val lua.LValue) {
			if str, ok := key.(lua.LString); ok {
				m[string(str)] = c.luaToGoValue(val)
			}
		})
		return m
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (c *Core) isLuaTableArray(tbl *lua.LTable) bool {
	maxN := tbl.MaxN()
	return maxN > 0 && maxN == tbl.Len()
}
