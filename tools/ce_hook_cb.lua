--[[
Cheat Engine Lua 脚本：在 cB（下行解密）入口下断，抓接收路径

为什么换点：
  在 RingWrite(0xC034F0) 下断，登录全过程只命中 **1 次**，且 data 是高熵密文
  （caller=0xBEB3A3 → 经由 0xBF87E0），那是**发送方向**。
  说明我们那 12 个下行帧根本没有走到 RingWrite —— 接收路径不在这里。
  cA 用于发送加密、cB 用于接收解密，所以断 cB 得到的一定是**接收**路径。

目标：0xC00BD0（cB 入口，签名 cB(bits, in, sess, out)，见探针 logCrypt）

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_cb.log
--]]

local ADDR = 0xC00BD0
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_cb.log"
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
    local esp = reg("ESP")
    local ecx = reg("ECX")
    local ret = rd(esp)
    -- cB(bits, in, sess, out)：bits=第一个栈参数
    local bits = rd(esp + 4)
    local pin  = rd(esp + 8)
    local sess = rd(esp + 12)
    local pout = rd(esp + 16)
    log(string.format("[%d] caller=%08X ecx=%08X bits=%d in=%08X sess=%08X out=%08X",
                      HITS, ret, ecx, bits, pin, sess, pout))
    if pin > 0 then
      local b = {}
      for i = 0, 15 do b[#b+1] = string.format("%02X", rd(pin + i) & 0xFF) end
      log("     ct  = " .. table.concat(b, " "))
    end
  end)
  if not ok then log("!! handler error: " .. tostring(err)) end
  if HITS >= 60 then
    log("== 60 hits, removing ==")
    pcall(debug_removeBreakpoint, ADDR)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xC034F0)
pcall(debug_removeBreakpoint, 0x7D76C0)
pcall(debug_removeBreakpoint, 0xBF106D)
log("HW-exec bp at cB " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
else
  log("armed. 回游戏点一次登录。")
end
