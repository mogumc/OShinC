package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"oshin-core/plugin"
)

// jsonMode 通过 --json 标志开启 JSON 模式
var jsonMode *bool

// CLI 命令行工具结构
type CLI struct {
	core   *plugin.Core
	reader *bufio.Reader
}

// CLIRequest extends PluginRequest with optional file loading
type CLIRequest struct {
	plugin.PluginRequest
	ScriptFile string `json:"script_file"` // 可选：从文件加载脚本，优先级低于 Script
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	config := parseConfig()
	core := plugin.NewCoreWithConfig(config)
	return &CLI{
		core:   core,
		reader: bufio.NewReader(os.Stdin),
	}
}

// parseConfig parses command-line flags into SecurityConfig
func parseConfig() *plugin.SecurityConfig {
	config := plugin.DefaultSecurityConfig()

	timeout := flag.Int("timeout", config.Timeout, "脚本执行超时时间 (毫秒)")
	maxMemory := flag.Int("max-memory", config.MaxMemoryMB, "最大内存使用 (MB)")
	jsonMode = flag.Bool("json", false, "JSON模式: 从stdin读取请求JSON，输出结果JSON")

	flag.Parse()

	config.Timeout = *timeout
	config.MaxMemoryMB = *maxMemory

	return config
}

// Run 启动CLI交互循环
func (c *CLI) Run() {
	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n退出CLI...")
		os.Exit(0)
	}()

	fmt.Println("=== OShin-core ===")
	fmt.Println("命令:")
	fmt.Println("  exec <脚本文件> [模式] [动作]  - 执行Lua脚本")
	fmt.Println("  help                           - 显示帮助信息")
	fmt.Println("  exit                           - 退出程序")
	fmt.Println()

	for {
		fmt.Print("oshin-cli> ")
		input, err := c.reader.ReadString('\n')
		if err != nil {
			fmt.Println("\n退出CLI...")
			return
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "exec":
			if len(parts) < 2 {
				fmt.Println("用法: exec <脚本文件> [模式] [动作]")
				continue
			}
			c.executeScript(parts[1:])
		case "help":
			c.showHelp()
		case "exit", "quit":
			fmt.Println("退出CLI...")
			return
		default:
			fmt.Printf("未知命令: %s (输入help查看帮助)\n", parts[0])
		}
	}
}

// executeScript 执行Lua脚本
func (c *CLI) executeScript(args []string) {
	scriptFile := args[0]
	mode := "direct"
	action := ""

	if len(args) > 1 {
		mode = args[1]
	}
	if len(args) > 2 {
		action = args[2]
	}

	// 读取脚本文件
	script, err := os.ReadFile(scriptFile)
	if err != nil {
		fmt.Printf("读取脚本文件失败: %v\n", err)
		return
	}

	// 构建请求
	request := plugin.PluginRequest{
		Script:  string(script),
		Mode:    mode,
		Action:  action,
		Params:  make(map[string]interface{}),
		Timeout: 5000, // 默认5秒超时
	}

	// 如果是交互模式，允许用户输入参数
	if mode == "direct" || mode == "route" {
		fmt.Println("请输入参数 (JSON格式，可选，直接回车跳过):")
		paramInput, _ := c.reader.ReadString('\n')
		paramInput = strings.TrimSpace(paramInput)

		if paramInput != "" {
			var params map[string]interface{}
			if err := json.Unmarshal([]byte(paramInput), &params); err != nil {
				fmt.Printf("JSON解析失败: %v\n", err)
				return
			}
			request.Params = params
		}
	}

	// 执行脚本
	resp := c.core.Execute(request)

	// 输出 JSON 结果
	c.outputJSON(resp)
}

// runJSON 从 stdin 读取完整 JSON 请求，输出 JSON 结果（供外部程序调用）
func (c *CLI) runJSON() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		c.outputJSON(plugin.PluginResponse{
			Code:    -1,
			Message: "读取stdin失败: " + err.Error(),
			Data:    nil,
		})
		return
	}

	var req CLIRequest
	if err := json.Unmarshal(input, &req); err != nil {
		c.outputJSON(plugin.PluginResponse{
			Code:    -1,
			Message: "JSON解析失败: " + err.Error(),
			Data:    nil,
		})
		return
	}

	// 如果指定了 script_file，从文件加载脚本
	if req.ScriptFile != "" && req.Script == "" {
		script, err := os.ReadFile(req.ScriptFile)
		if err != nil {
			c.outputJSON(plugin.PluginResponse{
				Code:    -1,
				Message: "读取脚本文件失败: " + err.Error(),
				Data:    nil,
			})
			return
		}
		req.Script = string(script)
	}

	// 填充默认值
	if req.Mode == "" {
		req.Mode = "direct"
	}
	if req.Params == nil {
		req.Params = make(map[string]interface{})
	}

	// JSON 模式下将 Lua log() 重定向到 stderr，保持 stdout 纯净的 JSON 输出
	c.core.LogWriter = os.Stderr

	resp := c.core.Execute(req.PluginRequest)
	c.outputJSON(resp)
}

// outputJSON 输出 JSON 响应到 stdout
func (c *CLI) outputJSON(resp plugin.PluginResponse) {
	output, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "{\"code\":-1,\"message\":\"JSON序列化失败: %v\"}\n", err)
		return
	}
	fmt.Println(string(output))
}

// showHelp 显示帮助信息
func (c *CLI) showHelp() {
	fmt.Println("OShin-core 插件CLI工具帮助:")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  exec <脚本文件> [模式] [动作]  - 执行Lua脚本")
	fmt.Println("    脚本文件: Lua脚本文件路径")
	fmt.Println("    模式: direct (默认), route, pipeline")
	fmt.Println("    动作: 路由模式下的动作名称")
	fmt.Println()
	fmt.Println("  help                           - 显示此帮助信息")
	fmt.Println("  exit                           - 退出程序")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  exec test/simple.lua              - 执行simple.lua (直接模式)")
	fmt.Println("  exec test/simple.lua route add    - 执行路由模式，动作为add")
	fmt.Println("  exec test/simple.lua pipeline     - 执行管道模式")
	fmt.Println()
	fmt.Println("安全模型:")
	fmt.Println("  - 脚本通过 request_permission(type) 主动请求权限")
	fmt.Println("  - 权限类型: exec, network, file_read, file_write")
	fmt.Println("  - 无回调时默认拒绝所有敏感操作")
	fmt.Println("  - 支持预授权白名单跳过回调")
	fmt.Println()
	fmt.Println("JSON模式 (供外部程序调用):")
	fmt.Println("  --json   从stdin读取请求JSON，输出结果JSON到stdout")
	fmt.Println("  请求格式: {\"script\":\"...\", \"script_file\":\"path\", \"mode\":\"direct\", \"action\":\"\", \"params\":{}, \"timeout\":5000}")
	fmt.Println("  输出格式: {\"code\":0, \"message\":\"success\", \"data\":{}, \"time\":123}")
	fmt.Println()
	fmt.Println("  示例:")
	fmt.Println("    echo {\"script\":\"function main(p) return {ok=true} end\"} | oshin-cli --json")
	fmt.Println("    echo {\"script_file\":\"test/simple.lua\", \"params\":{\"name\":\"test\"}} | oshin-cli --json")
}

func main() {
	cli := NewCLI()

	if jsonMode != nil && *jsonMode {
		// JSON 模式：从 stdin 读取完整请求，输出结果 JSON
		cli.runJSON()
	} else {
		// 交互模式
		cli.Run()
	}
}
