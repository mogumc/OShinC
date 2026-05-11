-- OShin-core 测试脚本
-- 展示插件核心的各种功能

-- 默认处理函数（用于直接模式）
function main(params)
    log("执行main函数...")
    
    return {
        message = "Hello from OShin-core!",
        params_received = params,
        timestamp = os.time(),
        mode = "direct"
    }
end

-- 测试2: HTTP请求功能
function test_http_request(params)
    log("测试HTTP请求功能...")
    
    -- 发送HTTP请求
    local url = params.url or "https://httpbin.org/get"
    local response_str = http_request(url, "GET")
    
    -- 解析JSON响应
    local response, err = json_parse(response_str)
    if not response then
        return {error = "JSON解析失败: " .. (err or "未知错误")}
    end
    
    -- 格式化返回数据
    local result = {
        success = true,
        url = url,
        data = response,
        status = "HTTP请求成功"
    }
    
    return result
end

-- 测试3: JSON处理功能
function test_json_processing(_)
    log("测试JSON处理功能...")
    
    -- 创建复杂数据结构
    local data = {
        users = {
            {id = 1, name = "张三", age = 25},
            {id = 2, name = "李四", age = 30},
            {id = 3, name = "王五", age = 35}
        },
        metadata = {
            total = 3,
            page = 1,
            per_page = 10
        }
    }
    
    -- 序列化为JSON
    local json_str = json_stringify(data)
    
    -- 重新解析验证
    local parsed, err = json_parse(json_str)
    if not parsed then
        return {error = "JSON处理测试失败: " .. (err or "未知错误")}
    end
    
    -- 统计用户数量
    local user_count = 0
    if parsed.users then
        for _ in pairs(parsed.users) do
            user_count = user_count + 1
        end
    end
    
    return {
        success = true,
        original_data = data,
        json_string = json_str,
        parsed_data = parsed,
        user_count = user_count,
        message = "JSON处理功能正常"
    }
end

-- 测试4: 错误处理
function test_error_handling(_)
    log("测试错误处理功能...")
    
    -- 测试无效JSON解析
    local invalid_json = "{invalid json}"
    local result, err = json_parse(invalid_json)
    
    -- 测试HTTP请求错误处理
    local error_response = http_request("http://invalid-url-that-does-not-exist.com", "GET")
    
    return {
        invalid_json_test = {
            input = invalid_json,
            result = result,
            error = err,
            handled = result == nil and err ~= nil
        },
        http_error_test = {
            url = "http://invalid-url-that-does-not-exist.com",
            response = error_response,
            has_error = string.find(error_response, "error") ~= nil
        },
        message = "错误处理功能测试完成"
    }
end

-- 测试5: 综合功能演示
function test_comprehensive(params)
    log("开始综合功能演示...")
    
    -- 1. 接收外部参数
    local input_data = params.data or "默认输入数据"
    
    -- 2. 处理数据
    local processed_data = {
        input = input_data,
        processed = true,
        timestamp = os.time(),
        random_number = math.random(1, 1000)
    }
    
    -- 3. JSON处理
    local json_str = json_stringify(processed_data)
    local parsed, _ = json_parse(json_str)
    
    -- 4. 模拟HTTP请求（使用本地数据）
    local mock_response = json_stringify({
        status = "success",
        data = parsed,
        source = "OShin-core测试"
    })
    
    -- 5. 最终格式化
    local final_result = {
        success = true,
        input = input_data,
        output = parsed,
        mock_http_response = json_parse(mock_response),
        message = "综合功能演示完成",
        execution_info = {
            functions_used = {"json_stringify", "json_parse", "log"},
            data_flow = "输入 -> 处理 -> JSON转换 -> 模拟HTTP -> 格式化输出"
        }
    }
    
    return final_result
end

-- ==================== 新模式示例 ====================

-- 路由模式示例
routes = {
    -- 用户相关处理
    user_create = function(params)
        log("处理用户创建请求")
        
        if not params.username or not params.email then
            return {success = false, error = "缺少必要字段"}
        end
        
        local user = {
            id = math.random(10000, 99999),
            username = params.username,
            email = params.email,
            created_at = os.time(),
            status = "active"
        }
        
        return {
            success = true,
            message = "用户创建成功",
            data = user
        }
    end,
    
    -- 获取用户信息
    user_get = function(params)
        log("处理获取用户信息请求")
        
        local user_id = params.user_id
        if not user_id then
            return {success = false, error = "缺少用户ID"}
        end
        
        -- 模拟从数据库获取用户
        local user = {
            id = user_id,
            username = "user_" .. user_id,
            email = "user" .. user_id .. "@example.com",
            created_at = os.time() - 86400 * 30,  -- 30天前创建
            status = "active"
        }
        
        return {
            success = true,
            data = user
        }
    end,
    
    -- 数据处理
    data_transform = function(params)
        log("处理数据转换请求")
        
        local input_data = params.data
        if not input_data then
            return {success = false, error = "缺少输入数据"}
        end
        
        -- 转换数据
        local transformed = {
            original = input_data,
            processed = true,
            processed_at = os.time(),
            hash = string.format("%08x", math.random(0, 0xFFFFFFFF))
        }
        
        return {
            success = true,
            data = transformed
        }
    end
}

-- 管道模式示例
function pipeline(params)
    log("执行管道模式...")
    
    -- 定义管道步骤
    local steps = {
        -- 步骤1: 验证输入
        function(data)
            log("步骤1: 验证输入数据")
            if not data or not data.value then
                return {success = false, error = "缺少输入值"}
            end
            return {success = true, data = data}
        end,
        
        -- 步骤2: 数据转换
        function(data)
            log("步骤2: 数据转换")
            local value = data.value
            local transformed_value = value * 2 + 10
            return {
                success = true, 
                data = {
                    original = value,
                    transformed = transformed_value,
                    formula = "value * 2 + 10"
                }
            }
        end,
        
        -- 步骤3: 格式化输出
        function(data)
            log("步骤3: 格式化输出")
            return {
                success = true,
                data = {
                    result = data.transformed,
                    formatted = string.format("结果: %d", data.transformed),
                    timestamp = os.time()
                }
            }
        end
    }
    
    -- 执行管道
    local current_data = params
    local step_results = {}
    
    for i, step in ipairs(steps) do
        local step_result = step(current_data)
        table.insert(step_results, {
            step = i,
            success = step_result.success,
            data = step_result.data,
            error = step_result.error
        })
        
        if not step_result.success then
            return {
                success = false,
                error = string.format("管道在步骤 %d 失败: %s", i, step_result.error),
                completed_steps = step_results
            }
        end
        
        current_data = step_result.data
    end
    
    return {
        success = true,
        message = "管道执行完成",
        final_result = current_data,
        steps_completed = #steps,
        step_results = step_results
    }
end

-- 混合模式示例：使用路由处理子任务
function hybrid_handler(params)
    log("执行混合模式...")
    
    local results = {}
    
    -- 创建用户
    local user_result = routes.user_create({
        username = params.username,
        email = params.email
    })
    table.insert(results, {action = "user_create", result = user_result})
    
    if user_result.success then
        -- 获取用户信息
        local get_result = routes.user_get({user_id = user_result.data.id})
        table.insert(results, {action = "user_get", result = get_result})
        
        -- 数据转换
        local transform_result = routes.data_transform({data = get_result.data})
        table.insert(results, {action = "data_transform", result = transform_result})
    end
    
    return {
        success = true,
        message = "混合模式执行完成",
        results = results,
        execution_flow = "创建用户 -> 获取信息 -> 数据转换"
    }
end

-- 高级示例：Lua控制的复杂工作流
function advanced_workflow(params)
    log("执行高级工作流...")
    
    -- 定义工作流步骤
    local workflow = {
        name = "数据处理工作流",
        version = "1.0",
        steps = {}
    }
    
    -- 步骤1: 验证输入
    local validation_step = function(data)
        log("工作流步骤1: 验证输入")
        if not data then
            return {success = false, error = "输入数据为空"}
        end
        
        local validated_data = {
            original = data,
            validated = true,
            validated_at = os.time()
        }
        
        return {success = true, data = validated_data}
    end
    table.insert(workflow.steps, {name = "验证", handler = validation_step})
    
    -- 步骤2: 数据增强
    local enhance_step = function(data)
        log("工作流步骤2: 数据增强")
        
        local enhanced_data = data
        enhanced_data.enhanced = true
        enhanced_data.enhanced_at = os.time()
        enhanced_data.metadata = {
            processor = "OShin-core",
            version = "1.0"
        }
        
        return {success = true, data = enhanced_data}
    end
    table.insert(workflow.steps, {name = "增强", handler = enhance_step})
    
    -- 步骤3: 数据转换
    local transform_step = function(data)
        log("工作流步骤3: 数据转换")
        
        local transformed_data = {
            id = math.random(10000, 99999),
            content = data.original,
            processed = true,
            processed_at = os.time(),
            format = "json"
        }
        
        return {success = true, data = transformed_data}
    end
    table.insert(workflow.steps, {name = "转换", handler = transform_step})
    
    -- 步骤4: 验证输出
    local validate_output_step = function(data)
        log("工作流步骤4: 验证输出")
        
        if not data.id or not data.content then
            return {success = false, error = "输出数据格式错误"}
        end
        
        return {success = true, data = data}
    end
    table.insert(workflow.steps, {name = "验证输出", handler = validate_output_step})
    
    -- 执行工作流
    local current_data = params
    local execution_log = {}
    
    for i, step in ipairs(workflow.steps) do
        log(string.format("执行工作流步骤 %d/%d: %s", i, #workflow.steps, step.name))
        
        local step_result = step.handler(current_data)
        table.insert(execution_log, {
            step = i,
            name = step.name,
            success = step_result.success,
            timestamp = os.time()
        })
        
        if not step_result.success then
            return {
                success = false,
                error = string.format("工作流在步骤 '%s' 失败: %s", step.name, step_result.error),
                workflow = workflow.name,
                completed_steps = #execution_log,
                execution_log = execution_log
            }
        end
        
        current_data = step_result.data
    end
    
    return {
        success = true,
        message = "高级工作流执行完成",
        workflow = {
            name = workflow.name,
            version = workflow.version,
            steps_count = #workflow.steps
        },
        result = current_data,
        execution_log = execution_log,
        execution_summary = {
            total_steps = #workflow.steps,
            completed_steps = #execution_log,
            all_successful = true
        }
    }
end