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

var jsonMode *bool

type CLI struct {
	core   *plugin.Core
	reader *bufio.Reader
}

type CLIRequest struct {
	plugin.PluginRequest
	ScriptFile string `json:"script_file"`
}

func NewCLI() *CLI {
	config := parseConfig()
	core := plugin.NewCoreWithConfig(config)
	return &CLI{
		core:   core,
		reader: bufio.NewReader(os.Stdin),
	}
}

func parseConfig() *plugin.SecurityConfig {
	config := plugin.DefaultSecurityConfig()

	timeout := flag.Int("timeout", config.Timeout, "脚本执行超时时间 (毫秒)")
	maxMemory := flag.Int("max-memory", config.MaxMemoryMB, "最大内存使用 (MB)")
	jsonMode = flag.Bool("json", false, "JSON模式: 从stdin读取请求JSON，输出结果JSON")
	showHelpFlag := flag.Bool("help", false, "显示帮助信息")

	flag.Parse()

	if *showHelpFlag {
		fmt.Println("OShin-core 插件CLI工具帮助:")
		fmt.Println()
		fmt.Println("用法:")
		fmt.Println("  oshin-cli <脚本文件> [模式] [动作] [参数JSON]  - 直接执行Lua脚本")
		fmt.Println("  oshin-cli --json                               - JSON模式 (供外部程序调用)")
		fmt.Println("  oshin-cli                                      - 进入交互模式")
		fmt.Println("  oshin-cli --help                               - 显示此帮助信息")
		fmt.Println()
		fmt.Println("直接执行模式:")
		fmt.Println("  脚本文件: Lua脚本文件路径")
		fmt.Println("  模式: direct (默认), route, pipeline")
		fmt.Println("  动作: 路由模式下的动作名称")
		fmt.Println("  参数JSON: 传递给脚本的参数，JSON格式")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  oshin-cli test/simple.lua                     - 执行simple.lua")
		fmt.Println("  oshin-cli test/simple.lua route add           - 路由模式，动作为add")
		fmt.Println("  oshin-cli test/simple.lua pipeline            - 管道模式")
		fmt.Println("  oshin-cli test/simple.lua direct main '{\"a\":10,\"b\":20}' - 传递参数")
		os.Exit(0)
	}

	config.Timeout = *timeout
	config.MaxMemoryMB = *maxMemory

	return config
}

func (c *CLI) Run() {
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

	script, err := os.ReadFile(scriptFile)
	if err != nil {
		fmt.Printf("读取脚本文件失败: %v\n", err)
		return
	}

	request := plugin.PluginRequest{
		Script:  string(script),
		Mode:    mode,
		Action:  action,
		Params:  make(map[string]interface{}),
		Timeout: 5000,
	}

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

	resp := c.core.Execute(request)

	c.outputJSON(resp)
}

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

	if req.Mode == "" {
		req.Mode = "direct"
	}
	if req.Params == nil {
		req.Params = make(map[string]interface{})
	}

	c.core.LogWriter = os.Stderr
	resp := c.core.Execute(req.PluginRequest)
	c.outputJSON(resp)
}

func (c *CLI) outputJSON(resp plugin.PluginResponse) {
	output, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "{\"code\":-1,\"message\":\"JSON序列化失败: %v\"}\n", err)
		return
	}
	fmt.Println(string(output))
}

func (c *CLI) runDirect(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: oshin-cli <脚本文件> [模式] [动作] [参数JSON]")
		return
	}

	scriptFile := args[0]
	if _, err := os.Stat(scriptFile); os.IsNotExist(err) {
		fmt.Printf("脚本文件不存在: %s\n", scriptFile)
		return
	}

	script, err := os.ReadFile(scriptFile)
	if err != nil {
		fmt.Printf("读取脚本文件失败: %v\n", err)
		return
	}

	mode := "direct"
	action := ""
	params := make(map[string]interface{})

	if len(args) > 1 {
		mode = args[1]
	}
	if len(args) > 2 {
		action = args[2]
	}
	if len(args) > 3 {
		paramStr := args[3]
		if paramStr != "" {
			if err := json.Unmarshal([]byte(paramStr), &params); err != nil {
				fmt.Printf("参数JSON解析失败: %v\n", err)
				return
			}
		}
	}

	request := plugin.PluginRequest{
		Script:  string(script),
		Mode:    mode,
		Action:  action,
		Params:  params,
		Timeout: 5000,
	}

	c.core.LogWriter = os.Stderr
	resp := c.core.Execute(request)
	c.outputJSON(resp)
}

func (c *CLI) showHelp() {
	fmt.Println("OShin-core 插件CLI工具帮助:")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  oshin-cli <脚本文件> [模式] [动作] [参数JSON]  - 直接执行Lua脚本")
	fmt.Println("  oshin-cli --json                               - JSON模式 (供外部程序调用)")
	fmt.Println("  oshin-cli                                      - 进入交互模式")
	fmt.Println()
	fmt.Println("直接执行模式:")
	fmt.Println("  脚本文件: Lua脚本文件路径")
	fmt.Println("  模式: direct (默认), route, pipeline")
	fmt.Println("  动作: 路由模式下的动作名称")
	fmt.Println("  参数JSON: 传递给脚本的参数，JSON格式")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  oshin-cli test/simple.lua              - 执行simple.lua (直接模式)")
	fmt.Println("  oshin-cli test/simple.lua route add    - 执行路由模式，动作为add")
	fmt.Println("  oshin-cli test/simple.lua pipeline     - 执行管道模式")
	fmt.Println("  oshin-cli test/simple.lua direct main '{\"a\":10,\"b\":20}' - 传递参数")
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
		cli.runJSON()
	} else if len(flag.Args()) > 0 {
		cli.runDirect(flag.Args())
	} else {
		cli.Run()
	}
}
