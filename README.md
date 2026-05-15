# OShinC

Go + Lua 脚本执行引擎，提供安全沙箱环境和权限控制。支持两种调用方式：**CLI 直接调用** 和 **FFI 共享库调用**。

## 架构

```
plugin/
  core.go      - 执行引擎 (Lua 脚本执行、内置函数注册)
  sandbox.go   - 安全沙箱 (权限模型、脚本验证、环境隔离)
cmd/
  cli/         - 命令行工具 (直接调用 plugin 包)
  ffi/         - FFI 共享库 (cgo 导出 C 接口，供 Python/Node 等调用)
test/
  oshin_core.py        - Python 调用封装 (ctypes)
  example.py           - Python 调用示例
  test_permission.py   - 权限系统测试
  test.lua             - Lua 功能测试脚本
```

## 安全模型

脚本通过 `request_permission()` 主动请求权限，宿主程序通过回调决定是否允许：

| 权限类型 | 说明 |
|---|---|
| `exec` | 执行外部程序 (Python/Node/Lua 等) |
| `network` | 网络访问 (HTTP 请求) |
| `file_read` | 读取本地文件 |
| `file_write` | 写入本地文件 |

```lua
-- 脚本中使用
local ok = request_permission("network", "访问外部API")
if ok then
    local data = http_request("https://api.example.com/data")
    -- ...
end
```

权限请求流程：
1. 脚本调用 `request_permission(type, description)`
2. 沙箱检查 **预授权白名单** → 若命中则直接放行
3. 否则调用 **宿主程序回调** → 由宿主程序询问用户
4. 无回调且未预授权 → 默认拒绝

## 调用方式

### 1. Go 直接调用

```go
import "oshin-core/plugin"

core := plugin.NewCore()
resp := core.Execute(plugin.PluginRequest{
    Script: `function main(params) return {sum = params.a + params.b} end`,
    Params: map[string]interface{}{"a": 10, "b": 20},
    Mode:   "direct",
})
// resp.Data = map[string]interface{}{"sum": float64(30)}
```

带权限控制：
```go
config := plugin.DefaultSecurityConfig()
config.PermissionCallback = func(req plugin.PermissionRequest) bool {
    fmt.Printf("请求权限: %s (%s)\n", req.Type, req.Description)
    return true // 允许所有
}
config.PreAuthorized = map[plugin.PermissionType]bool{
    plugin.PermNetwork: true,  // 预授权网络权限
}

core := plugin.NewCoreWithConfig(config)
resp := core.Execute(req)
```

### 2. CLI 命令行

编译：
```bash
set CGO_ENABLED=1
go build -o oshin-cli.exe ./cmd/cli/
```

#### 直接执行

```bash
# 直接执行 Lua 脚本
oshin-cli.exe test/simple.lua

# 指定模式和动作
oshin-cli.exe test/simple.lua route add
oshin-cli.exe test/simple.lua pipeline

# 传递参数
oshin-cli.exe test/simple.lua direct main '{"a":10,"b":20}'
```

输出格式为 JSON，方便程序解析：
```json
{"code":0, "message":"success", "data":{...}, "time":123}
```

#### 交互模式

```bash
oshin-cli.exe

# 命令列表
oshin-cli> help

# 执行脚本 (直接模式)
oshin-cli> exec test/simple.lua

# 执行脚本 (路由模式)
oshin-cli> exec test/simple.lua route add

# 执行脚本 (管道模式)
oshin-cli> exec test/simple.lua pipeline

# 退出
oshin-cli> exit
```

#### JSON 模式（供外部程序调用）

通过 `--json` 标志启用 JSON 模式：从 stdin 读取请求 JSON，将结果 JSON 输出到 stdout。Lua 的 `log()` 输出到 stderr，不干扰 stdout 的 JSON 解析。

```bash
# 请求格式
echo '{"script":"...", "script_file":"path", "mode":"direct", "action":"", "params":{}, "timeout":5000}' | oshin-cli.exe --json

# 输出格式
{"code":0, "message":"success", "data":{...}, "time":123}
```

**字段说明：**

| 请求字段 | 类型 | 说明 |
|---|---|---|
| `script` | string | Lua 脚本内容（与 `script_file` 二选一） |
| `script_file` | string | Lua 脚本文件路径（与 `script` 二选一，优先级低） |
| `mode` | string | `direct`（默认）/ `route` / `pipeline` |
| `action` | string | 路由模式下的动作名称 |
| `params` | object | 传递给脚本的参数 |
| `timeout` | int | 超时时间（毫秒） |

**示例：**

```bash
# 基本调用
echo '{"script":"function main(p) return {greeting=\"Hello \" .. p.name} end", "params":{"name":"World"}}' | oshin-cli.exe --json

# 从文件加载脚本
echo '{"script_file":"test/simple.lua", "params":{"name":"test"}}' | oshin-cli.exe --json

# 路由模式
echo '{"script_file":"test/simple.lua", "mode":"route", "action":"add", "params":{"a":10,"b":20}}' | oshin-cli.exe --json

# 管道模式
echo '{"script_file":"test/simple.lua", "mode":"pipeline", "params":{"value":42}}' | oshin-cli.exe --json
```

**Shell 调用示例：**

```bash
# PowerShell
$json = '{"script":"function main(p) return {ok=true} end"}'
$json | oshin-cli.exe --json | ConvertFrom-Json

# Bash
result=$(echo '{"script":"function main(p) return {ok=true} end"}' | ./oshin-cli.exe --json)
echo $result
```

#### 与 FFI 模式的区别

| 特性 | CLI 直接模式 | CLI JSON 模式 | FFI 共享库 |
|---|---|---|---|
| 调用方式 | 命令行参数 | 子进程 + stdin/stdout | 函数调用 |
| 权限回调 | 无（默认拒绝） | 无（默认拒绝） | 支持 C 回调 |
| 性能 | 较低（进程开销） | 较低（进程开销） | 高（无进程开销） |
| 适用场景 | 开发调试、简单脚本 | 脚本编排、CI/CD | 应用内嵌入、高性能场景 |

CLI 安全模型：
- 脚本通过 `request_permission(type, description)` 主动请求权限
- CLI 模式下默认拒绝所有敏感操作（无权限回调）
- 脚本应在执行敏感操作前先调用 `request_permission()` 检查权限

### 3. FFI 共享库 (Python/Node/C 等)

编译 DLL：
```bash
set CGO_ENABLED=1
go build -buildmode=c-shared -o oshin.dll ./cmd/ffi/
```

导出 C 接口：
| 函数 | 说明 |
|---|---|
| `OShinExecute(script, params_json, mode, config_json)` | 执行脚本 |
| `OShinSetPermissionCallback(callback)` | 注册权限回调 |
| `OShinFreeString(str)` | 释放返回字符串 |
| `OShinVersion()` | 版本号 |

## Python 绑定

```python
from oshin_core import OShinCore

# 带权限回调
def my_perm(perm_type, description, details):
    print(f"请求: {description}")
    return input("允许? (y/n): ").lower() == "y"

oshin = OShinCore(lib_path="oshin.dll", permission_callback=my_perm)

# 直接执行
r = oshin.execute_direct(
    'function main(params) return {greeting = "Hello, " .. params.name .. "!"} end',
    {"name": "World"},
)

# 路由模式
r = oshin.execute_route(script, "action_name", params)

# 预授权
r = oshin.execute(script, params, pre_authorized=["network", "exec"])
```

运行示例：
```bash
python test/example.py
python test/test_permission.py
```

## 执行模式

| 模式 | 说明 | 入口 |
|---|---|---|
| `direct` | 直接调用 `main(params)` 或指定函数 | `PluginRequest.Method` |
| `route` | 通过 `routes` 表按 action 路由 | `PluginRequest.Action` |
| `pipeline` | 执行 `pipeline(params)` 管道 | 固定入口 |

## 内置 Lua 函数

| 函数 | 说明 |
|---|---|
| `request_permission(type, desc)` | 请求权限 (返回 true/false) |
| `http_request(url, method, body)` | HTTP 请求 |
| `execute_external(program, code)` | 执行外部程序 |
| `read_file(path)` | 读取文件 |
| `write_file(path, content)` | 写入文件 |
| `json_parse(str)` | JSON 解析 |
| `json_stringify(val)` | JSON 序列化 |
| `log(msg)` | 日志输出 |
