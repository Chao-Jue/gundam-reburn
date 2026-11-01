--[[
Cheat Engine Lua 脚本（第三版）：在 RingWrite 入口下断，抓真实调用路径

为什么换点：
  上一版在 0xBF106D（收包函数里调 RingWrite 的那一行）下断，发 12 帧过去
  **一次都没命中** —— 说明我们的帧并没有走 0xBF0FC0 那条解析路径。
  但探针早就证明 RingWrite(0xC034F0) 本身确实被调用过（日志里有 ring len=16）。
  ⇒ 还有**别的调用点**。直接在 RingWrite 入口下断，看调用者是谁就清楚了。

脚本：
  1. 在 0xC034F0（RingWrite thiscall: ecx=ring, 栈参数 data,len）下硬件执行断点
  2. 每次命中记录：ring / data / len / **调用者返回地址** / 队列四个字段
  3. 最多记 40 次

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_ring.log
--]]

local ADDR = 0xC034F0
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_ring.log"
local HITS = 0

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(os.date("%H:%M:%S ") .. s .. "\n"); f:close() end
end

local function rd(a)
  local v = -1
  pcall(function() v = readInteger(a) end)
  return v
end

function debugger_onBreakpoint()
  HITS = HITS + 1
  local esp = getReg("esp")
  local ring = getReg("ecx")
  local ret  = rd(esp)          -- 返回地址 = 谁调的
  local data = rd(esp + 4)
  local len  = rd(esp + 8)

  log(string.format("[%d] caller=%08X ring=%08X data=%08X len=%d",
                    HITS, ret, ring, data, len))
  if ring > 0 and ring < 0x7FFFFFFF then
    log(string.format("     ring: buf=%08X cap=%d w=%d r=%d",
                      rd(ring + 8), rd(ring + 0xC), rd(ring + 0x10), rd(ring + 0x14)))
  end
  if data > 0 and data < 0x7FFFFFFF and (len or 0) > 0 then
    local n = math.min(len, 24)
    local b = {}
    for i = 0, n - 1 do b[#b + 1] = string.format("%02X", rd(data + i) & 0xFF) end
    log("     data = " .. table.concat(b, " "))
  end

  if HITS >= 40 then
    log("== 40 hits, removing breakpoint ==")
    pcall(debug_removeBreakpoint, ADDR)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then
  debugProcess()
end

log("==================================================")
-- 清掉之前脚本留下的断点
pcall(debug_removeBreakpoint, 0x7D76C0)
pcall(debug_removeBreakpoint, 0xBF106D)
log("HW-exec bp at RingWrite " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
  log("请用管理员身份运行 Cheat Engine。")
else
  log("armed. 回游戏点一次登录。")
end
