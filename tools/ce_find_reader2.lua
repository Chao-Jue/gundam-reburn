--[[
Cheat Engine Lua 脚本（v2）：抓解密队列的消费者 —— 改用**写断点**

v1 结果：
  ring(EBX) = 0x38589748
  对 ring+0x14 下**读**断点 → 一次都没命中
  且 ring 字段读出来是 buf=2CDB51D8 cap=0 w=0 r=24576，说明这俩字段的语义
  和我猜的相反（+0x14 可能才是"界限"而不是读指针）。

改法：消费者取走数据后一定会把某个指针**往前推**（写操作），
      所以对 ring+0x10 和 ring+0x14 同时下**写断点**，命中即消费者。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_reader2.log
--]]

local PRODUCER = 0xBD50A0
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_reader2.log"

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
  local eip = reg("EIP")

  if STAGE == 1 then
    local ebx = reg("EBX")
    RING = ebx
    log(string.format("[producer] eip=%08X ring=%08X", eip, ebx))
    log(string.format("           +08=%08X +0C=%d +10=%d +14=%d +18=%d +1C=%d",
                      rd(ebx + 8), rd(ebx + 0xC), rd(ebx + 0x10),
                      rd(ebx + 0x14), rd(ebx + 0x18), rd(ebx + 0x1C)))
    pcall(debug_removeBreakpoint, PRODUCER)
    STAGE = 2
    local ok1 = pcall(debug_setBreakpoint, RING + 0x10, 4, bptWrite, bpmDebugRegister)
    local ok2 = pcall(debug_setBreakpoint, RING + 0x14, 4, bptWrite, bpmDebugRegister)
    log(string.format("[stage2] 写断点 +10 ok=%s, +14 ok=%s", tostring(ok1), tostring(ok2)))
    return 1
  end

  -- 阶段2：有人写了 writePos / readPos
  HITS = HITS + 1
  local eax = reg("EAX")
  local ecx = reg("ECX")
  local edx = reg("EDX")
  local esi = reg("ESI")
  local edi = reg("EDI")
  local ebx = reg("EBX")
  log(string.format("[write %d] eip=%08X eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X",
                    HITS, eip, eax, ebx, ecx, edx, esi, edi))
  log(string.format("            +10=%d +14=%d", rd(RING + 0x10), rd(RING + 0x14)))
  if HITS >= 30 then
    log("== 30 hits, removing ==")
    pcall(debug_removeBreakpoint, RING + 0x10)
    pcall(debug_removeBreakpoint, RING + 0x14)
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
  log("armed. 回游戏点一次登录。")
end
