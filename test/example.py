#!/usr/bin/env python3
"""
OShin-core Python 调用示例

演示安全模型：脚本通过 request_permission() 主动请求权限，
宿主程序通过 permission_callback 决定是否允许。
"""

import sys
import os

# 确保能找到模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oshin_core import OShinCore, PERM_EXEC, PERM_NETWORK, PERM_FILE_READ, PERM_FILE_WRITE


def main():
    dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "oshin.dll")

    # ─── 权限回调函数 ───
    # 自动允许所有权限，生产环境中应询问用户
    def auto_allow(perm_type, description, details):
        print(f"  [权限请求] {description} -> 自动允许")
        return True

    oshin = OShinCore(lib_path=dll_path, permission_callback=auto_allow)

    # ─── 示例1: 基本调用 ───
    print("=== 示例1: 基本调用 ===")
    r = oshin.execute_direct(
        'function main(params) return {greeting = "Hello, " .. params.name .. "!"} end',
        {"name": "World"},
    )
    print(f"  结果: {r['data']}\n")

    # ─── 示例2: 路由模式 ───
    print("=== 示例2: 路由模式 ===")
    script2 = """
routes = {}
function routes.add(params)
    return {result = params.a + params.b}
end
"""
    r = oshin.execute_route(script2, "add", {"a": 10, "b": 20})
    print(f"  10 + 20 = {r['data']['result']}\n")

    # ─── 示例3: 调用外部 Python 程序 ───
    print("=== 示例3: 调用外部Python程序 ===")
    r = oshin.execute_direct("""
function main(params)
    local output = execute_external("python", "print('Hello from Python!')")
    return {output = output}
end
""")
    print(f"  Python输出: {r['data']['output'].strip()}\n")

    # ─── 示例4: 复杂数据类型 ───
    print("=== 示例4: 复杂数据类型 ===")
    script4 = """
function main(params)
    local name = params.name
    local items = params.items
    local total = 0
    for _, v in ipairs(items) do
        total = total + v
    end
    return {name = name, total = total, count = #items}
end
"""
    r = oshin.execute(script4, {"name": "test", "items": [10, 20, 30]}, mode="direct")
    print(f"  name={r['data']['name']}, total={r['data']['total']}, count={r['data']['count']}\n")

    # ─── 示例5: 脚本主动请求权限（无回调时被拒绝）───
    print("=== 示例5: 脚本主动请求权限（无回调 = 拒绝）===")
    oshin_noperm = OShinCore(lib_path=dll_path)  # 无回调
    script5 = """
function main(params)
    local ok = request_permission("network", "访问外部API")
    if ok then
        return {status = "granted"}
    else
        return {status = "denied"}
    end
end
"""
    r = oshin_noperm.execute_direct(script5)
    print(f"  权限状态: {r['data']['status']}\n")

    # ─── 示例6: 模拟用户交互的权限回调 ───
    print("=== 示例6: 模拟用户交互的权限回调 ===")
    def interactive_perm(perm_type, description, details):
        # 在实际应用中，这里会弹出对话框询问用户
        print(f"  [权限请求] {description}")
        # 演示：仅允许 file_read
        allowed = (perm_type == PERM_FILE_READ)
        print(f"  [决策] {'允许' if allowed else '拒绝'}")
        return allowed

    oshin_interactive = OShinCore(lib_path=dll_path, permission_callback=interactive_perm)
    script6 = """
function main(params)
    local read_ok = request_permission("file_read", "读取配置文件")
    local exec_ok = request_permission("exec", "执行外部程序")
    return {
        file_read = read_ok and "允许" or "拒绝",
        exec = exec_ok and "允许" or "拒绝"
    }
end
"""
    r = oshin_interactive.execute_direct(script6)
    print(f"  结果: {r['data']}\n")

    print("=== 全部示例完成 ===")


if __name__ == "__main__":
    main()
