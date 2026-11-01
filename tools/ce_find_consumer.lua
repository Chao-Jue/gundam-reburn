--[[
Cheat Engine Lua 脚本（第二版）：找"队列消费者"

背景：
  收包函数 0xBF0FC0 解析完一帧后，在 0xBF106D 调 RingWrite 把 payload 写进
  应用层环形队列（ring = socket + 0x4518）。队列结构：
      ring+0x08 buf / +0x0C cap / +0x10 writePos / +0x14 readPos
  "谁读了 readPos（ring+0x14）" —— 谁就是消费者（把 payload 解析成消息对象的工厂）。

脚本两阶段：
  阶段1  在 0xBF106D 下硬件执行断点（只命中一次）
         命中时：ecx 就是 ring 指针（= socket+0x4518），
                 同时把这次写入的 data / len 记下来（验证我们发的帧格式对不对）。
  阶段2  对 ring+0x14 下**硬件读断点**，记录每次读它的调用者（返回地址），
         那就是消费者。最多记 30 次后自动撤掉，避免刷屏/拖慢。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_consumer.log
--]]

local WRITE_ADDR = 0xBF106D
local LOG        = "D:\\project\\gundam-reburn\\server\\ce_consumer.log"

local STAGE   = 1
local RING    = 0          -- ecx 命中时的 ring 指针
local READS   = 0
local WROTE   = 0

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(os.date("%H:%M:%S ") .. s .. "\n"); f:close() end
end

local function rd(addr)
  local v = -1
  pcall(function() v = readInteger(addr) end)
  return v
end

function debugger_onBreakpoint()
  local esp = getReg("esp")

  if STAGE == 1 then
    -- 断在 call RingWrite 处：ecx = ring，[esp+4] = data，[esp+8] = len
    local ecx  = getReg("ecx")
    local data = rd(esp + 4)
    local len  = rd(esp + 8)
    local ret  = rd(esp)
    RING = ecx
    log(string.format("[write] ring=%08X data=%08X len=%d caller=%08X",
                      ecx, data, len, ret))
    log(string.format("        ring: buf=%08X cap=%d w=%d r=%d",
                      rd(ecx + 8), rd(ecx + 0xC), rd(ecx + 0x10), rd(ecx + 0x14)))
    -- 把这次写入的内容 dump 出来，确认格式
    local bytes = {}
    for i = 0, math.min(len or 0, 32) - 1 do
      bytes[#bytes + 1] = string.format("%02X", rd(data + i) & 0xFF)
    end
    log("        payload = " .. table.concat(bytes, " "))

    -- 撤销阶段1，进入阶段2
    debug_removeBreakpoint(WRITE_ADDR)
    STAGE = 2
    local ok, err = pcall(debug_setBreakpoint, RING + 0x14, 4, bptRead, bpmDebugRegister)
    if ok then
      log(string.format("[stage2] 已对 readPos(%08X) 下读断点，等消费者来读它…", RING + 0x14))
    else
      log("[stage2] 读断点失败: " .. tostring(err))
    end
    return 1
  end

  -- 阶段2：消费者在读 readPos
  READS = READS + 1
  local eip = getReg("eip")
  local caller = rd(esp)
  local eax = getReg("eax")
  local ecx = getReg("ecx")
  local edx = getReg("edx")
  log(string.format("[read %d] eip=%08X 返回到=%08X eax=%08X ecx=%08X edx=%08X",
                    READS, eip, caller, eax, ecx, edx))
  if READS >= 30 then
    log("== 30 reads, removing read breakpoint ==")
    pcall(debug_removeBreakpoint, RING + 0x14)
    STAGE = 3
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then
  debugProcess()
end

log("==================================================")
-- 清掉上一版脚本留下的 0x7D76C0 断点，避免干扰
pcall(debug_removeBreakpoint, 0x7D76C0)
log("stage1: HW-exec bp at " .. string.format("%08X", WRITE_ADDR))
local ok, err = pcall(debug_setBreakpoint, WRITE_ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
  log("请用管理员身份运行 Cheat Engine。")
else
  log("armed. 回游戏点一次登录（会先抓这一次写入，再盯谁读队列）。")
end
