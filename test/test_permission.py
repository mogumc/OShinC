#!/usr/bin/env python3
"""
OShin-core 权限系统测试

验证新的安全模型：
1. 无回调时默认拒绝
2. 有回调时正确授权
3. 预授权白名单
4. 脚本 request_permission 与回调交互
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oshin_core import OShinCore, PERM_EXEC, PERM_NETWORK, PERM_FILE_READ, PERM_FILE_WRITE

dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "oshin.dll")

PASS_COUNT = 0
FAIL_COUNT = 0


def assert_test(name, condition):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  PASS: {name}")
    else:
        FAIL_COUNT += 1
        print(f"  FAIL: {name}")


def test_no_callback():
    """无回调时 request_permission 返回 false"""
    print("=== 测试1: 无回调（默认拒绝） ===")
    oshin = OShinCore(lib_path=dll_path)
    r = oshin.execute_direct("""
function main(p)
    local net = request_permission("network", "网络请求")
    local exec = request_permission("exec", "执行程序")
    local fread = request_permission("file_read", "读文件")
    local fwrite = request_permission("file_write", "写文件")
    return {network=net, exec=exec, file_read=fread, file_write=fwrite}
end
""")
    data = r["data"]
    assert_test("network 拒绝", data["network"] == False)
    assert_test("exec 拒绝", data["exec"] == False)
    assert_test("file_read 拒绝", data["file_read"] == False)
    assert_test("file_write 拒绝", data["file_write"] == False)
    print()


def test_allow_all():
    """回调全部允许"""
    print("=== 测试2: 回调全部允许 ===")
    oshin = OShinCore(lib_path=dll_path, permission_callback=lambda *a: True)
    r = oshin.execute_direct("""
function main(p)
    local net = request_permission("network", "网络请求")
    local exec = request_permission("exec", "执行程序")
    local fread = request_permission("file_read", "读文件")
    local fwrite = request_permission("file_write", "写文件")
    return {network=net, exec=exec, file_read=fread, file_write=fwrite}
end
""")
    data = r["data"]
    assert_test("network 允许", data["network"] == True)
    assert_test("exec 允许", data["exec"] == True)
    assert_test("file_read 允许", data["file_read"] == True)
    assert_test("file_write 允许", data["file_write"] == True)
    print()


def test_selective_allow():
    """回调选择性允许"""
    print("=== 测试3: 回调选择性允许 ===")

    def selective(perm_type, desc, details):
        return perm_type in (PERM_NETWORK, PERM_FILE_READ)

    oshin = OShinCore(lib_path=dll_path, permission_callback=selective)
    r = oshin.execute_direct("""
function main(p)
    return {
        network = request_permission("network", "网络请求"),
        exec = request_permission("exec", "执行程序"),
        file_read = request_permission("file_read", "读文件"),
        file_write = request_permission("file_write", "写文件"),
    }
end
""")
    data = r["data"]
    assert_test("network 允许", data["network"] == True)
    assert_test("exec 拒绝", data["exec"] == False)
    assert_test("file_read 允许", data["file_read"] == True)
    assert_test("file_write 拒绝", data["file_write"] == False)
    print()


def test_pre_authorized():
    """预授权白名单跳过回调"""
    print("=== 测试4: 预授权白名单 ===")
    # 回调拒绝所有，但预授权放行 network 和 exec
    oshin = OShinCore(
        lib_path=dll_path,
        permission_callback=lambda *a: False,
    )
    r = oshin.execute(
        """
function main(p)
    return {
        network = request_permission("network", "网络请求"),
        exec = request_permission("exec", "执行程序"),
        file_read = request_permission("file_read", "读文件"),
    }
end
""",
        pre_authorized=["network", "exec"],
    )
    data = r["data"]
    assert_test("network 预授权通过", data["network"] == True)
    assert_test("exec 预授权通过", data["exec"] == True)
    assert_test("file_read 回调拒绝", data["file_read"] == False)
    print()


def test_callback_receives_details():
    """回调能收到完整的权限请求信息"""
    print("=== 测试5: 回调收到详细信息 ===")
    received = []

    def tracking(perm_type, desc, details):
        received.append({"type": perm_type, "desc": desc, "details": details})
        return True

    oshin = OShinCore(lib_path=dll_path, permission_callback=tracking)
    r = oshin.execute_direct("""
function main(p)
    request_permission("network", "访问 httpbin.org")
    request_permission("exec", "运行 python3")
    return {ok = true}
end
""")
    assert_test("回调被调用2次", len(received) == 2)
    assert_test("第1次是 network", received[0]["type"] == "network")
    assert_test("第1次描述正确", "httpbin" in received[0]["desc"])
    assert_test("第2次是 exec", received[1]["type"] == "exec")
    assert_test("第2次描述正确", "python3" in received[1]["desc"])
    print()


if __name__ == "__main__":
    test_no_callback()
    test_allow_all()
    test_selective_allow()
    test_pre_authorized()
    test_callback_receives_details()

    print("=" * 40)
    print(f"结果: {PASS_COUNT} 通过, {FAIL_COUNT} 失败")
    if FAIL_COUNT > 0:
        sys.exit(1)
