--[[
Cheat Engine Lua 脚本：抓"解密队列"的消费者

结论回顾：
  · 0xBD50A0 处 RingWrite(ring, 明文块, 16) —— ring 在 EBX
  · 应用层解析 0xBF0FC0 **一次都没被调用**，所以消费者不是它

思路（两阶段）：
  1. 在 0xBD50A0（RingWrite 调用点）下硬件执行断点，命中时取 EBX = ring
  2. 撤掉它，改对 **ring+0x14（readPos）** 下硬件**读**断点
     —— RingWrite 内部结构：buf@+8 / cap@+0xC / writePos@+0x10 / readPos@+0x14
     谁去读 readPos，谁就是从队列取数据的一方
  3. 记录每次读的 EIP 和返回地址 → 那就是消费者

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_reader.log
--]]

local PRODUCER = 0xBD50A0
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_reader.log"

local STAGE = 1
local RING  = 0
local READS = 0

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
  local esp = reg("ESP")
  local eip = reg("EIP")

  if STAGE == 1 then
    -- 命中 RingWrite 调用点：EBX = ring
    local ebx  = reg("EBX")
    local ret  = rd(esp)
    RING = ebx
    log(string.format("[producer] eip=%08X ring(EBX)=%08X caller=%08X", eip, ebx, ret))
    log(string.format("           buf=%08X cap=%d w=%d r=%d",
                      rd(ebx + 8), rd(ebx + 0xC), rd(ebx + 0x10), rd(ebx + 0x14)))

    pcall(debug_removeBreakpoint, PRODUCER)
    STAGE = 2
    local ok, err = pcall(debug_setBreakpoint, RING + 0x14, 4, bptRead, bpmDebugRegister)
    if ok then
      log(string.format("[stage2] 对 readPos(%08X) 下读断点，等消费者来读…", RING + 0x14))
    else
      log("[stage2] 读断点失败: " .. tostring(err))
    end
    return 1
  end

  -- 阶段2：有人读 readPos
  READS = READS + 1
  local ret  = rd(esp)
  local eax  = reg("EAX")
  local ecx  = reg("ECX")
  local edx  = reg("EDX")
  local esi  = reg("ESI")
  log(string.format("[read %d] eip=%08X caller=%08X eax=%08X ecx=%08X edx=%08X esi=%08X",
                    READS, eip, ret, eax, ecx, edx, esi))
  if READS >= 25 then
    log("== 25 reads, removing read breakpoint ==")
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
