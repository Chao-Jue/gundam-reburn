--[[
Cheat Engine Lua 脚本：对 vtable 项 0xE6408C 下内存读断点，抓"谁调用了虚函数 #10"

原理：
  0xBF0FC0（socket 的"取帧解析"）在 vtable 数组里位于 **0xE6408C**。
  任何 `call dword [reg+0x28]` 形式的虚调用，都必须**先读**这一项取函数地址。
  ⇒ 对这一项下硬件**读**断点，命中处就是调用点。

注意：
  · 读断点可能在别处也被读到（比如 RTTI 遍历、调试打印），
    所以每次命中都扫栈，只关心"栈上出现了模块地址"的那几次。
  · 数据断点在 WOW64 下 EIP 不可靠，所以靠扫栈定位。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录
  4. 日志：D:\project\gundam-reburn\server\ce_vt.log
--]]

local VT_ITEM  = 0xE6408C          -- socket 变体 A：值为 0xBF0FC0
local VT_ITEM2 = 0xE6410C          -- socket 变体 B：值为 0xBF10F0（登录用的是加密 socket，很可能走这个）
local LOG     = "D:\\project\\gundam-reburn\\server\\ce_vt.log"
local MOD_LO, MOD_HI = 0x400000, 0x1300000
local HITS    = 0

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
  if HITS > 20 then return 1 end

  local esp = reg("ESP")
  local ok, err = pcall(function()
    local found = {}
    for i = 0, 0x80, 4 do
      local v = rd(esp + i)
      if v >= MOD_LO and v < MOD_HI then
        found[#found + 1] = string.format("+%02X:%08X", i, v)
      end
    end
    log(string.format("[%d] esp=%08X  A[%08X]=%08X  B[%08X]=%08X  栈内模块地址: %s",
        HITS, esp, VT_ITEM, rd(VT_ITEM), VT_ITEM2, rd(VT_ITEM2),
        (#found > 0 and table.concat(found, "  ") or "(none)")))
  end)
  if not ok then log("!! " .. tostring(err)) end

  if HITS >= 20 then
    log("== 20 hits, removing ==")
    pcall(debug_removeBreakpoint, VT_ITEM)
  end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xBEB310)
pcall(debug_removeBreakpoint, 0xBEB590)
pcall(debug_removeBreakpoint, 0xBD512A)
pcall(debug_removeBreakpoint, VT_ITEM)      -- 清掉上一次可能留下的
pcall(debug_removeBreakpoint, VT_ITEM2)
log(string.format("HW-read bp at vtable items 0x%X(=0x%08X) 和 0x%X(=0x%08X)",
                  VT_ITEM, rd(VT_ITEM), VT_ITEM2, rd(VT_ITEM2)))
local ok1 = pcall(debug_setBreakpoint, VT_ITEM,  4, bptRead, bpmDebugRegister)
local ok2 = pcall(debug_setBreakpoint, VT_ITEM2, 4, bptRead, bpmDebugRegister)
log(string.format("A ok=%s  B ok=%s", tostring(ok1), tostring(ok2)))
log("armed. 回游戏点一次登录。")
