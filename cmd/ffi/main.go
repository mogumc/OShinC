package main

/*
#include <stdlib.h>

// 宿主程序的权限回调函数类型
// perm_type:     "exec", "network", "file_read", "file_write"
// description:   可读的权限描述
// details_json:  附加信息 JSON (url, path, program 等)
// 返回 1=允许, 0=拒绝
typedef int (*oshin_perm_cb)(const char* perm_type, const char* description, const char* details_json);

static oshin_perm_cb g_perm_callback = NULL;

static void oshin_set_perm_callback(oshin_perm_cb cb) {
    g_perm_callback = cb;
}

static int oshin_check_perm(const char* perm_type, const char* description, const char* details_json) {
    if (g_perm_callback == NULL) return 0;
    return g_perm_callback(perm_type, description, details_json);
}
*/
import "C"

import (
	"encoding/json"
	"strings"
	"unsafe"

	"oshin-core/plugin"
)

//export OShinSetPermissionCallback
// 设置权限回调函数。宿主程序必须在首次 Execute 之前调用。
// callback 签名: int callback(perm_type, description, details_json)
// 返回 1=允许, 0=拒绝
func OShinSetPermissionCallback(cCallback unsafe.Pointer) {
	C.oshin_set_perm_callback(C.oshin_perm_cb(cCallback))
}

//export OShinExecute
// mode 格式: "direct", "route:action_name", "pipeline"
// configJSON 格式: {"timeout":5000,"pre_authorized":["network","exec"]}
func OShinExecute(cScript *C.char, cParams *C.char, cMode *C.char, cConfigJSON *C.char) *C.char {
	script := C.GoString(cScript)
	modeRaw := C.GoString(cMode)

	var params map[string]interface{}
	if cParams != nil {
		paramsJSON := C.GoString(cParams)
		if paramsJSON != "" {
			if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
				resp := plugin.PluginResponse{Code: 1, Message: "Invalid params: " + err.Error()}
				data, _ := json.Marshal(resp)
				return C.CString(string(data))
			}
		}
	}
	if params == nil {
		params = make(map[string]interface{})
	}

	// 解析 configJSON
	config := plugin.DefaultSecurityConfig()
	if cConfigJSON != nil {
		configJSON := C.GoString(cConfigJSON)
		if configJSON != "" {
			var cfgMap map[string]interface{}
			if err := json.Unmarshal([]byte(configJSON), &cfgMap); err == nil {
				if timeout, ok := cfgMap["timeout"].(float64); ok {
					config.Timeout = int(timeout)
				}
				if preAuth, ok := cfgMap["pre_authorized"].([]interface{}); ok {
					config.PreAuthorized = make(map[plugin.PermissionType]bool)
					for _, v := range preAuth {
						if s, ok := v.(string); ok {
							config.PreAuthorized[plugin.PermissionType(s)] = true
						}
					}
				}
			}
		}
	}

	// 设置权限回调：通过 C 层桥接到宿主程序
	config.PermissionCallback = func(req plugin.PermissionRequest) bool {
		detailsJSON, _ := json.Marshal(req.Details)
		cType := C.CString(string(req.Type))
		cDesc := C.CString(req.Description)
		cDetails := C.CString(string(detailsJSON))
		defer C.free(unsafe.Pointer(cType))
		defer C.free(unsafe.Pointer(cDesc))
		defer C.free(unsafe.Pointer(cDetails))

		ret := C.oshin_check_perm(cType, cDesc, cDetails)
		return ret == 1
	}

	// 解析 mode
	mode := modeRaw
	action := ""
	if strings.HasPrefix(modeRaw, "route:") {
		mode = "route"
		action = strings.TrimPrefix(modeRaw, "route:")
	}

	req := plugin.PluginRequest{
		Script: script,
		Mode:   mode,
		Action: action,
		Params: params,
	}
	core := plugin.NewCoreWithConfig(config)
	resp := core.Execute(req)

	data, _ := json.Marshal(resp)
	return C.CString(string(data))
}

//export OShinFreeString
func OShinFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export OShinVersion
func OShinVersion() *C.char {
	return C.CString("1.0.0")
}

func main() {}
