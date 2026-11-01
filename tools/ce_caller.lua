--[[
Cheat Engine Lua 脚本（v5）：抓收包函数的调用者（网络线程）

背景：
  · 收包函数在 0xBD5000 附近：密文缓冲(+0x230) → cB 解密 → RingWrite(明文队列 +0x4e0)
  · 真正读队列的只有 0xBF0FC0，但它**从未被调用** ⇒ 登录界面没人消费
  · 需要知道"谁调用收包函数、返回后又做了什么"

做法：在收包函数的**出口 0xBD512A（ret 之前）**下硬件执行断点，
      此时栈顶就是调用者的返回地址；同时扫一段栈兜底
      （CE 的 ESP 在 WOW64 下可能偏，所以两路都记）。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录（会命中多次，因为有多个密文块）
  4. 日志：D:\project\gundam-reburn\server\ce_caller.log
--]]

local ADDR = 0xBD512A
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_caller.log"
local MOD_LO, MOD_HI = 0x400000, 0x1300000

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
  if HITS > 10 then return 1 end

  local esp = reg("ESP")
  local ebx = reg("EBX")
  local ebp = reg("EBP")
  local edi = reg("EDI")

  log(string.format("[%d] esp=%08X ebx=%08X ebp=%08X edi=%08X", HITS, esp, ebx, ebp, edi))
  if esp > 0 and esp < 0x7FFFFFFF then
    log(string.format("     [esp]=%08X  [esp+4]=%08X  [esp+8]=%08X",
                      rd(esp), rd(esp + 4), rd(esp + 8)))
    local found = {}
    for i = 0, 0x80, 4 do
      local v = rd(esp + i)
      if v >= MOD_LO and v < MOD_HI then
        found[#found + 1] = string.format("+%02X:%08X", i, v)
      end
    end
    log("     栈内模块地址 = " .. (#found > 0 and table.concat(found, "  ") or "(none)"))
  end
  if HITS >= 10 then
    log("== 10 hits, removing ==")
    pcall(debug_removeBreakpoint, ADDR)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xBF0FC0)
pcall(debug_removeBreakpoint, 0xC00BD0)
pcall(debug_removeBreakpoint, 0xC034F0)
pcall(debug_removeBreakpoint, 0xBD50A0)
log("HW-exec bp at recv-exit " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
else
  log("armed. 回游戏点一次登录。")
end
