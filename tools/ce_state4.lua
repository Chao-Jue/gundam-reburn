--[[
Cheat Engine Lua 脚本：验证"点登录后状态会不会变成 4"

假设（本轮要验证的）：
  · socket+0x280 = 连接状态；6 = 刚连上还没发请求
  · 0xBEB310 / 0xBEB590：当 **状态==1 且 [socket+0x9C] != 0** 时 → 状态 = 4
  · 4 = 真正的"取帧 + 造消息对象 + 分发"模式
  ⇒ 如果点登录时这两处被命中，说明客户端确实进了解析模式，
    那问题就只在"内容不对"，而不是"根本不解析"。

这两个地址是低频的（只在状态切换时执行），适合下执行断点。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录，注意观察
  4. 日志：D:\project\gundam-reburn\server\ce_state4.log
--]]

local A1, A2 = 0xBEB310, 0xBEB590
local LOG = "D:\\project\\gundam-reburn\\server\\ce_state4.log"
local HITS = 0

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(os.date("%H:%M:%S ") .. s .. "\n"); f:close() end
end

local function rd(a)
  if type(a) ~= "number" or a <= 0 or a > 0x7FFFFFFF then return -1 end
  local ok, v = pcall(readInteger, a)
  if ok and type(v) == "number" then return v end
  return -1
end

local function reg(name)
  local ok, v = pcall(function() return _G[name] end)
  if ok and type(v) == "number" then return v end
  return 0
end

function debugger_onBreakpoint()
  HITS = HITS + 1
  local ok, err = pcall(function()
    local eip = reg("EIP")
    local esi = reg("ESI")
    log(string.format("[%d] HIT eip=%08X  esi(socket)=%08X  state=%d  [esi+0x9C]=%d",
                      HITS, eip, esi, rd(esi + 0x280), rd(esi + 0x9C)))
  end)
  if not ok then log("!! " .. tostring(err)) end
  if HITS >= 20 then
    log("== 20 hits, removing ==")
    pcall(debug_removeBreakpoint, A1)
    pcall(debug_removeBreakpoint, A2)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
log("HW-exec bp at state->4 sites")
local o1 = pcall(debug_setBreakpoint, A1, 1, bptExecute, bpmDebugRegister)
local o2 = pcall(debug_setBreakpoint, A2, 1, bptExecute, bpmDebugRegister)
log(string.format("0x%X ok=%s   0x%X ok=%s", A1, tostring(o1), A2, tostring(o2)))
log("armed. 回游戏点一次登录（如果一直没命中，说明登录时状态根本没变成 4）。")
