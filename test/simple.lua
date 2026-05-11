-- 简单的 CLI 测试脚本
-- 用法: exec test/simple.lua
--       exec test/simple.lua route add

function main(params)
    log("执行 main 函数...")
    local name = params.name or "World"
    return {
        message = "Hello, " .. name .. "!",
        timestamp = os.time(),
        mode = "direct"
    }
end

routes = {
    add = function(params)
        log("执行加法...")
        return {result = (params.a or 0) + (params.b or 0)}
    end,

    greet = function(params)
        log("执行问候...")
        local name = params.name or "stranger"
        local hour = os.date("*t").hour
        local greeting
        if hour < 12 then
            greeting = "早上好"
        elseif hour < 18 then
            greeting = "下午好"
        else
            greeting = "晚上好"
        end
        return {message = greeting .. ", " .. name .. "!"}
    end
}

function pipeline(params)
    log("执行管道模式...")
    local input = params.value or 0
    return {result = input * 2 + 1}
end
