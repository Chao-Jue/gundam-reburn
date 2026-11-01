--[[
Cheat Engine Lua 脚本（第五版）：在 RingWrite 入口下断，抓真实调用路径

v3 报 `getReg` 不存在；v4 报 `esp` 是 nil（getRegisters/readInteger 都没取到）。
本版按 CE 的三种可能途径依次兜底：
  1) 断点回调里的全局变量 ESP/ECX/EAX/EIP（CE 会自动同步）
  2) getRegisters() 返回的表
  3) readInteger("esp")
任何一路拿到数字就用，全都拿不到就打印一段说明而不是崩。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_ring.log
--]]

local ADDR = 0xC034F0
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_ring.log"
local HITS = 0
local PROBED = false

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(os.date("%H:%M:%S ") .. s .. "\n"); f:close() end
end

local function rd(a)
  if type(a) ~= "number" then return -1 end
  if a <= 0 or a > 0x7FFFFFFF then return -1 end
  local v = -1
  pcall(function() v = readInteger(a) end)
  return v
end

-- 寄存器：三路兜底，永远返回数字
local function reg(name)
  -- 1) 全局变量
  local ok1, v1 = pcall(function() return _G[name] end)
  if ok1 and type(v1) == "number" then return v1 end

  -- 2) getRegisters()
  local ok2, t = pcall(getRegisters)
  if ok2 and type(t) == "table" then
    if type(t[name]) == "number" then return t[name] end
    -- WOW64 下的别名
    local alias = ({ ESP = {"RSP"}, EIP = {"RIP"}, EAX = {"RAX"}, ECX = {"RCX"} })[name]
    if alias then
      for _, k in ipairs(alias) do
        if type(t[k]) == "number" then return t[k] end
      end
    end
  end

  -- 3) readInteger("esp")
  local v3 = nil
  pcall(function() v3 = readInteger(string.lower(name)) end)
  if type(v3) == "number" then return v3 end

  return 0
end

function debugger_onBreakpoint()
  HITS = HITS + 1

  -- 第一次命中时把可用来源探一遍，方便以后排查
  if not PROBED then
    PROBED = true
    local ok, t = pcall(getRegisters)
    log(string.format("[probe] _G.ESP=%s  getRegisters ok=%s (%s)",
        tostring(_G.ESP), tostring(ok),
        (ok and type(t) == "table") and "table" or tostring(t)))
  end

  local ok, err = pcall(function()
    local esp  = reg("ESP")
    local ring = reg("ECX")
    local ret  = rd(esp)
    local data = rd(esp + 4)
    local len  = rd(esp + 8)

    log(string.format("[%d] caller=%08X ring=%08X data=%08X len=%d",
                      HITS, ret, ring, data, len))
    if ring > 0 then
      log(string.format("     ring: buf=%08X cap=%d w=%d r=%d",
                        rd(ring + 8), rd(ring + 0xC), rd(ring + 0x10), rd(ring + 0x14)))
    end
    if data > 0 and (len or 0) > 0 then
      local n = math.min(len, 24)
      local b = {}
      for i = 0, n - 1 do b[#b + 1] = string.format("%02X", rd(data + i) & 0xFF) end
      log("     data = " .. table.concat(b, " "))
    end
  end)

  if not ok then log("!! handler error: " .. tostring(err)) end

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
pcall(debug_removeBreakpoint, ADDR)
log("HW-exec bp at RingWrite " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
  log("请用管理员身份运行 Cheat Engine。")
else
  log("armed. 回游戏点一次登录。")
end
