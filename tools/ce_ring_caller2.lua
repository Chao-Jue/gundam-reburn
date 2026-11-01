--[[
Cheat Engine Lua 脚本（第四版）：在 RingWrite 入口下断，抓真实调用路径
（v3 报 `getReg` 不存在 —— CE 的 Lua 里没有这个函数。本版改用 getRegisters()，
  并用 readInteger("esp") 作为兜底。）

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_ring.log

输出示例：
  [1] caller=00BF1072 ring=3AA00740 data=0F12A340 len=11
       ring: buf=0F100000 cap=65536 w=1234 r=1200
       data = 00 0B 00 00 00 C6 D7 7A 61 00 00 00
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
  if type(a) == "number" and (a <= 0 or a > 0x7FFFFFFF) then return -1 end
  pcall(function() v = readInteger(a) end)
  return v
end

-- 取寄存器：优先 getRegisters()，兜底用 readInteger("esp") 这类写法
local function reg(name)
  local v = 0
  local ok, t = pcall(getRegisters)
  if ok and type(t) == "table" then
    if name == "ESP" then v = t.ESP or t.RSP or 0
    elseif name == "ECX" then v = t.ECX or t.RCX or 0
    elseif name == "EAX" then v = t.EAX or t.RAX or 0
    elseif name == "EIP" then v = t.EIP or t.RIP or 0
    end
  end
  if v == 0 then
    pcall(function() v = readInteger("esp") end)   -- CE 支持用寄存器名当地址
  end
  return v
end

function debugger_onBreakpoint()
  HITS = HITS + 1

  local ok, err = pcall(function()
    local esp  = reg("ESP")
    local ring = reg("ECX")
    local ret  = rd(esp)
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
  end)

  if not ok then
    log("!! handler error: " .. tostring(err))
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
pcall(debug_removeBreakpoint, 0x7D76C0)
pcall(debug_removeBreakpoint, 0xBF106D)
pcall(debug_removeBreakpoint, ADDR)     -- 清掉 v3 可能留下的同一个断点
log("HW-exec bp at RingWrite " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
  log("请用管理员身份运行 Cheat Engine。")
else
  log("armed. 回游戏点一次登录。")
end
