--[[
Cheat Engine Lua 脚本：在应用层收包解析入口 0xBF0FC0 下断

目的（二选一，结果决定下一步方向）：
  A. 命中 → 说明消费者跑过；看 head/tail 差值就知道它当时有没有数据。
     差值 = 0 说明它读到空队列（我们写入的块没到它手上，或被别的消费者取走了）。
  B. 一次都不命中 → 说明应用层解析根本不是这个函数，得另找消费者。

函数头（反汇编）：
  bf0fc0  mov eax, 0x4020 / call 0xc128c0   ; 栈检查
  bf0fd9  mov esi, ecx                      ; this = socket
  bf0fdb  call 0xbf02e0 / test al,al / jne  ; al=0 直接 return
  bf0ffa  mov ecx,[esi+0x4e8]  ; tail
  bf1000  sub ecx,[esi+0x4e4]  ; 可用 = tail-head
  bf1006  mov eax,[esi+0x4e4]  ; head

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_parser.log
--]]

local ADDR = 0xBF0FC0
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_parser.log"
local HITS = 0

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(os.date("%H:%M:%S ") .. s .. "\n"); f:close() end
end

local function rd(a)
  if type(a) ~= "number" or a <= 0 or a > 0x7FFFFFFF then return -1 end
  local v = -1
  pcall(function() v = readInteger(a) end)
  return v
end

local function reg(name)
  local ok, v = pcall(function() return _G[name] end)
  if ok and type(v) == "number" then return v end
  return 0
end

function debugger_onBreakpoint()
  HITS = HITS + 1
  local ok, err = pcall(function()
    local esp  = reg("ESP")
    local sock = reg("ECX")        -- thiscall: this = socket
    local ret  = rd(esp)
    local head = rd(sock + 0x4e4)
    local tail = rd(sock + 0x4e8)
    local avail = (tail >= 0 and head >= 0) and (tail - head) or -1
    log(string.format("[%d] caller=%08X sock=%08X head=%d tail=%d avail=%d",
                      HITS, ret, sock, head, tail, avail))
    if avail > 0 and avail < 0x1000 then
      local buf = rd(sock + 0x4e0)
      local n = math.min(avail, 24)
      local b = {}
      for i = 0, n - 1 do b[#b + 1] = string.format("%02X", rd(buf + head + i) & 0xFF) end
      log("     data = " .. table.concat(b, " "))
    end
  end)
  if not ok then log("!! handler error: " .. tostring(err)) end
  if HITS >= 50 then
    log("== 50 hits, removing ==")
    pcall(debug_removeBreakpoint, ADDR)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xC00BD0)
pcall(debug_removeBreakpoint, 0xC034F0)
log("HW-exec bp at parser " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
else
  log("armed. 回游戏点一次登录。")
end
