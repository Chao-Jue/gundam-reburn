--[[
Cheat Engine Lua 脚本（v3）：确认解密队列到底有没有消费者

已确认的 ring 结构（来自 v2 实测）：
  +08 buf 基址 / +0C **readPos** / +10 writePos / +14 cap(24576) / +18 上限 / +1C 水位
  v2 写完 12 块后 readPos 一直是 0 ⇒ 很可能没人消费。

本版对 **ring+0x0C** 同时下**读**和**写**两个硬件断点：
  · 命中写 → 消费者在推进读指针（说明有人取数据）
  · 命中读 → 消费者在检查还有多少数据
  · 一次都不命中 → **确定没人管这个队列**，登录协议不走这条异步路径，
    必须转去找"同步等待 + 直接解析"的路径

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录（并且**多等十几秒**，消费者可能周期性轮询）
  4. 日志：D:\project\gundam-reburn\server\ce_reader3.log
--]]

local PRODUCER = 0xBD50A0
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_reader3.log"

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
  return -1     -- readInteger 失败时会返回 nil，这里必须兜住，否则 %d 会报错
end

local function reg(name)
  local ok, v = pcall(function() return _G[name] end)
  if ok and type(v) == "number" then return v end
  return 0
end

function debugger_onBreakpoint()
  local eip = reg("EIP")

  if STAGE == 1 then
    RING = reg("EBX")
    log(string.format("[producer] ring=%08X  buf=%08X  r=%d w=%d cap=%d",
                      RING, rd(RING + 8), rd(RING + 0x0C), rd(RING + 0x10), rd(RING + 0x14)))
    pcall(debug_removeBreakpoint, PRODUCER)
    STAGE = 2
    local o1 = pcall(debug_setBreakpoint, RING + 0x0C, 4, bptRead,  bpmDebugRegister)
    local o2 = pcall(debug_setBreakpoint, RING + 0x0C, 4, bptWrite, bpmDebugRegister)
    log(string.format("[stage2] readPos 读断点=%s 写断点=%s  —— 等消费者…",
                      tostring(o1), tostring(o2)))
    return 1
  end

  HITS = HITS + 1
  local eax = reg("EAX"); local ecx = reg("ECX"); local edx = reg("EDX")
  local esi = reg("ESI"); local edi = reg("EDI"); local ebx = reg("EBX")
  log(string.format("[%d] eip=%08X eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X  r=%d w=%d",
                    HITS, eip, eax, ebx, ecx, edx, esi, edi,
                    rd(RING + 0x0C), rd(RING + 0x10)))
  if HITS >= 30 then
    log("== 30 hits, removing ==")
    pcall(debug_removeBreakpoint, RING + 0x0C)
    STAGE = 3
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
  log("armed. 回游戏点一次登录，并多等十几秒（消费者可能是周期性轮询）。")
end
