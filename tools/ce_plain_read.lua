--[[
Cheat Engine Lua：看解密后的明文有没有进队列、有没有被上层拿走

上一轮 0xBD3670 命中 24 次，全是 avail=0，调用者固定是 0xBF9596。
那是 0xBF9580 在空转：
  avail==0 → 直接返回（0xBF95A0 jbe 0xBF967C）
  avail>0  → 交给 [session+0x1C4] 的虚函数 +0x20，再 call [vtable+0x3C] 吃掉
24 次把断点配额用光，发生在状态 3→6 的瞬间，sweep 的帧还没到。

本轮只盯两个「有数据才命中」的点，不再挂热路径：
  0xBD50A5  解密 RingWrite 返回后（明文刚写进环）
  0xBF95A6  avail>0 的分支（上层真的拿到了明文）

不要改状态。

用法：
  1. CE 附加后打开本文件，Ctrl+Enter（会拆掉旧断点）
  2. 假认证服先回 32 字节密钥，再发至少一帧 u32 长度 + 密文
  3. 点一次登录，等十几秒
  4. 日志：D:\project\gundam-reburn\server\ce_plain.log
--]]

local WRITE_RET = 0xBD50A5
local HAS_DATA  = 0xBF95A6
local LOG       = "D:\\project\\gundam-reburn\\server\\ce_plain.log"
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

local function u32(v)
  if type(v) ~= "number" or v < 0 then return 0 end
  return v % 4294967296
end

local function dump_bytes(addr, n)
  local b = {}
  for i = 0, n - 1 do
    local v = rd(addr + i)
    if v < 0 then break end
    b[#b + 1] = string.format("%02X", u32(v) % 256)
  end
  return table.concat(b, " ")
end

local function stack_mods(esp)
  local found = {}
  if esp <= 0 or esp > 0x7FFFFFFF then return "(bad esp)" end
  for i = 0, 0x30, 4 do
    local v = u32(rd(esp + i))
    if v >= MOD_LO and v < MOD_HI then
      found[#found + 1] = string.format("+%02X:%08X", i, v)
    end
  end
  if #found == 0 then return "(none)" end
  return table.concat(found, "  ")
end

function debugger_onBreakpoint()
  local eip = u32(reg("EIP"))
  if eip ~= WRITE_RET and eip ~= HAS_DATA then return 1 end

  HITS = HITS + 1
  if HITS > 24 then
    pcall(debug_removeBreakpoint, WRITE_RET)
    pcall(debug_removeBreakpoint, HAS_DATA)
    return 1
  end

  local ok, err = pcall(function()
    if eip == WRITE_RET then
      local ring = u32(reg("EBX"))
      local session = ring - 0x4E0
      local buf = u32(rd(ring + 8))
      local head = u32(rd(ring + 0x0C))
      local tail = u32(rd(ring + 0x10))
      local state = rd(session + 0x280)
      local src = 0
      if tail >= 16 then src = buf + tail - 16 end
      log(string.format("[%d] WRITE session=%08X state=%d head=%d tail=%d",
                        HITS, session, state, head, tail))
      if src > 0x10000 then
        log("     plain " .. dump_bytes(src, 16))
      end
    else
      local esp = reg("ESP")
      local session = u32(reg("ESI"))
      local ptr = u32(reg("EDI"))
      local avail = u32(rd(esp + 0x0C))
      local listener = u32(rd(session + 0x1C4))
      local lvt = 0
      if listener > 0x10000 then lvt = u32(rd(listener)) end
      log(string.format("[%d] DELIVER session=%08X avail=%d ptr=%08X listener=%08X lvtable=%08X",
                        HITS, session, avail, ptr, listener, lvt))
      if ptr > 0x10000 and avail > 0 and avail < 64 then
        log("     plain " .. dump_bytes(ptr, avail))
      end
      log("     stack " .. stack_mods(esp))
    end
  end)
  if not ok then log("!! handler error: " .. tostring(err)) end
  if HITS >= 24 then
    log("== 24 hits, removing ==")
    pcall(debug_removeBreakpoint, WRITE_RET)
    pcall(debug_removeBreakpoint, HAS_DATA)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
for _, a in ipairs({
  0xBD3670, 0xBD36A0, 0xBD50A0, WRITE_RET, HAS_DATA,
  0xE6408C, 0xE6410C, 0xBF0FC0, 0xBF10F0
}) do
  pcall(debug_removeBreakpoint, a)
end
local ok1 = pcall(debug_setBreakpoint, WRITE_RET, 1, bptExecute, bpmDebugRegister)
local ok2 = pcall(debug_setBreakpoint, HAS_DATA, 1, bptExecute, bpmDebugRegister)
log(string.format("armed WRITE_RET=%s  HAS_DATA=%s", tostring(ok1), tostring(ok2)))
log("空读不再记录。点一次登录，等 sweep 发完。有 WRITE 才说明明文进了队列。")
