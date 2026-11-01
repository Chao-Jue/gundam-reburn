--[[
Cheat Engine Lua 脚本（v4）：用"扫栈"的办法定位消费者

问题：CE 的**硬件数据断点**在 WOW64 下报告的 EIP 不可靠
      （v3 里对 ring+0x0C 下写断点，EIP 全被报成 0xBD50A0 这个 call 指令）。
办法：数据断点命中时，直接扫栈上的一段（ESP..ESP+0x100），
      把落在模块地址范围（0x400000~0x1300000）的值列出来 ——
      这些就是调用链上的返回地址，消费者必在其中。

流程：
  阶段1  0xBD50A0 执行断点（EIP 可靠）→ 拿 ring（EBX）
  阶段2  对 ring+0x0C（readPos）下**写**断点 → 每次命中扫栈

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录，多等十几秒
  4. 日志：D:\project\gundam-reburn\server\ce_stack.log
--]]

local PRODUCER = 0xBD50A0
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_stack.log"
local MOD_LO, MOD_HI = 0x400000, 0x1300000   -- 主模块地址范围

local STAGE = 1
local RING  = 0
local HITS  = 0

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
  if STAGE == 1 then
    RING = reg("EBX")
    log(string.format("[producer] ring=%08X buf=%08X r=%d w=%d cap=%d",
                      RING, rd(RING + 8), rd(RING + 0x0C), rd(RING + 0x10), rd(RING + 0x14)))
    pcall(debug_removeBreakpoint, PRODUCER)
    STAGE = 2
    local ok = pcall(debug_setBreakpoint, RING + 0x0C, 4, bptWrite, bpmDebugRegister)
    log("[stage2] 对 readPos 下写断点 ok=" .. tostring(ok) .. "，等消费者推进它…")
    return 1
  end

  HITS = HITS + 1
  if HITS > 12 then return 1 end     -- 只分析前 12 次，避免刷屏

  local esp = reg("ESP")
  log(string.format("[write %d] esp=%08X  r=%d w=%d", HITS, esp, rd(RING + 0x0C), rd(RING + 0x10)))
  if esp <= 0 or esp > 0x7FFFFFFF then
    log("     esp 无效，跳过扫栈")
    return 1
  end

  local found = {}
  for i = 0, 0x100, 4 do
    local v = rd(esp + i)
    if v >= MOD_LO and v < MOD_HI then
      found[#found + 1] = string.format("+%02X:%08X", i, v)
    end
  end
  if #found > 0 then
    log("     栈内模块地址 = " .. table.concat(found, "  "))
  else
    log("     栈内没有模块地址（esp 可能不准）")
  end
  if HITS >= 12 then
    log("== 12 writes analysed, removing ==")
    pcall(debug_removeBreakpoint, RING + 0x0C)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xBF0FC0)
pcall(debug_removeBreakpoint, 0xC00BD0)
pcall(debug_removeBreakpoint, 0xC034F0)
log("stage1: HW-exec bp at producer " .. string.format("%08X", PRODUCER))
local ok, err = pcall(debug_setBreakpoint, PRODUCER, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
else
  log("armed. 回游戏点一次登录，多等十几秒。")
end
