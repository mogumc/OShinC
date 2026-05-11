"""
OShin-core Python bindings
通过 ctypes 调用 OShin-core 共享库 (oshin.dll / liboshin.so / liboshin.dylib)

安全模型：
  - 脚本通过 request_permission(type) 主动请求权限
  - 宿主程序通过 permission_callback 决定是否允许
  - 无回调时默认拒绝所有敏感操作
"""

import ctypes
import json
import os
import platform
from typing import Dict, Any, Optional, Callable

# ─── C 回调函数类型定义 ───
# int callback(const char* perm_type, const char* description, const char* details_json)
PERM_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_int,                              # 返回值: 1=允许, 0=拒绝
    ctypes.c_char_p,                           # perm_type
    ctypes.c_char_p,                           # description
    ctypes.c_char_p,                           # details_json
)

# 权限类型常量
PERM_EXEC = "exec"
PERM_NETWORK = "network"
PERM_FILE_READ = "file_read"
PERM_FILE_WRITE = "file_write"

PERM_LABELS = {
    PERM_EXEC: "执行外部程序",
    PERM_NETWORK: "网络访问",
    PERM_FILE_READ: "读取文件",
    PERM_FILE_WRITE: "写入文件",
}


class OShinCore:
    """OShin-core Python wrapper with permission callback support"""

    def __init__(self, lib_path: Optional[str] = None,
                 permission_callback: Optional[Callable[[str, str, dict], bool]] = None):
        """
        Args:
            lib_path:   共享库路径
            permission_callback:
                func(perm_type, description, details) -> bool
                返回 True 允许, False 拒绝
                为 None 则默认拒绝所有未预授权的权限
        """
        if lib_path is None:
            lib_path = self._find_library()

        self.lib = ctypes.CDLL(lib_path)

        # ─── 注册 OShinExecute ───
        self.lib.OShinExecute.restype = ctypes.c_char_p
        self.lib.OShinExecute.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        # ─── 注册 OShinSetPermissionCallback ───
        self.lib.OShinSetPermissionCallback.restype = None
        self.lib.OShinSetPermissionCallback.argtypes = [ctypes.c_void_p]

        # ─── 注册 OShinFreeString ───
        self.lib.OShinFreeString.restype = None
        self.lib.OShinFreeString.argtypes = [ctypes.c_char_p]

        # ─── 注册 OShinVersion ───
        self.lib.OShinVersion.restype = ctypes.c_char_p
        self.lib.OShinVersion.argtypes = []

        # ─── 安装权限回调 ───
        self._perm_callback = None
        if permission_callback is not None:
            self._set_permission_callback(permission_callback)

    def _find_library(self) -> str:
        system = platform.system()
        if system == "Windows":
            lib_name = "oshin.dll"
        elif system == "Darwin":
            lib_name = "liboshin.dylib"
        else:
            lib_name = "liboshin.so"

        search_paths = [
            os.path.dirname(os.path.abspath(__file__)),       # test/
            os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),  # project root
            ".",
            os.getcwd(),
        ]

        for path in search_paths:
            full_path = os.path.join(path, lib_name)
            if os.path.exists(full_path):
                return full_path

        raise FileNotFoundError(
            f"Cannot find {lib_name}. Run: go build -buildmode=c-shared -o {lib_name} ./cmd/ffi/"
        )

    def _set_permission_callback(self, callback):
        """注册权限回调，必须在任何 Execute 之前调用"""
        def _c_callback(c_perm_type, c_desc, c_details):
            perm_type = c_perm_type.decode("utf-8") if c_perm_type else ""
            description = c_desc.decode("utf-8") if c_desc else ""
            details = {}
            if c_details:
                try:
                    details = json.loads(c_details.decode("utf-8"))
                except Exception:
                    pass

            try:
                result = callback(perm_type, description, details)
                return 1 if result else 0
            except Exception:
                return 0

        self._perm_callback = PERM_CALLBACK(_c_callback)
        self.lib.OShinSetPermissionCallback(ctypes.cast(self._perm_callback, ctypes.c_void_p))

    def execute(self, script: str, params: Dict[str, Any] = None,
                mode: str = "direct",
                pre_authorized: list = None,
                timeout: int = 5000) -> Dict[str, Any]:
        """
        Execute a Lua script

        Args:
            script:         Lua 脚本
            params:         参数 dict
            mode:           "direct" / "route:action_name" / "pipeline"
            pre_authorized: 预授权权限列表 ["network", "exec", "file_read", "file_write"]
            timeout:        超时 (毫秒)
        """
        params_json = json.dumps(params or {}).encode("utf-8")

        config = {"timeout": timeout}
        if pre_authorized:
            config["pre_authorized"] = pre_authorized
        config_json = json.dumps(config).encode("utf-8")

        raw = self.lib.OShinExecute(
            script.encode("utf-8"),
            params_json,
            mode.encode("utf-8"),
            config_json,
        )

        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"code": -1, "message": "Failed to parse response", "data": None}

    def execute_direct(self, script: str, params: Dict[str, Any] = None, **kw) -> Dict[str, Any]:
        return self.execute(script, params, mode="direct", **kw)

    def execute_route(self, script: str, action: str,
                      params: Dict[str, Any] = None, **kw) -> Dict[str, Any]:
        """
        Execute script in route mode

        Args:
            script: Lua script code
            action: Route action name (must match a key in the `routes` table)
            params: Parameters to pass to the script
        """
        return self.execute(script, params, mode=f"route:{action}", **kw)

    def execute_pipeline(self, script: str, params: Dict[str, Any] = None, **kw) -> Dict[str, Any]:
        return self.execute(script, params, mode="pipeline", **kw)

    def version(self) -> str:
        return self.lib.OShinVersion().decode("utf-8")
