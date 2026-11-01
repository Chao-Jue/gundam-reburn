--[[
Cheat Engine Lua 脚本：在消息处理函数 0x7D76C0 上下**硬件执行断点**，
把每次调用时的"消息对象"记下来（不修改任何代码字节，Themida 查不出来）。

用法：
  1. 打开 Cheat Engine -> 点左上角"选择进程" -> 选 GundamOnline_CHINA.exe -> Open
  2. 菜单 View -> Lua console   (或 Ctrl+Alt+L)
  3. 在 Lua 窗口里 File -> Open，选中本文件，然后 Ctrl+Enter 执行
  4. 回游戏点登录
  5. 结果同时打印在 Lua 窗口、并追加到
     D:\project\gundam-reburn\server\ce_msgid.log

关注点：
  - obj   = 消息对象指针（函数第一个参数）
  - vt    = 该对象的 vtable；真正的"消息类型 ID"由 [vt+4] 指向的虚函数返回
  - caller= 返回地址，顺它往上就是"谁构造了这个消息对象"（工厂）
  - obj[0..1C] = 对象前 0x20 字节，用来找类型字段
--]]

local ADDR = 0x7D76C0
local LOG  = "D:\\project\\gundam-reburn\\server\\ce_msgid.log"
local HITS = 0

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then
    f:write(os.date("%H:%M:%S ") .. s .. "\n")
    f:close()
  end
end

function debugger_onBreakpoint()
  HITS = HITS + 1
  local esp = getReg("esp")
  local eax = getReg("eax")
  local ecx = getReg("ecx")

  -- thiscall：this 在 ecx，第一个栈参数在 [esp+4]
  local obj  = 0
  local vt   = 0
  local ret  = 0
  pcall(function() obj = readInteger(esp + 4) end)
  pcall(function() ret = readInteger(esp) end)
  pcall(function() vt  = readInteger(obj) end)

  local fields = {}
  for i = 0, 0x1C, 4 do
    local v = 0
    pcall(function() v = readInteger(obj + i) end)
    fields[#fields + 1] = string.format("%08X", v or 0)
  end

  log(string.format("[%d] obj=%08X vt=%08X caller=%08X this=%08X eax=%08X",
        HITS, obj, vt, ret, ecx, eax))
  log("      obj[+00..+1C] = " .. table.concat(fields, " "))

  -- 只前 50 次，避免刷屏/拖慢
  if HITS >= 50 then
    log("== 50 hits reached, removing breakpoint ==")
    debug_removeBreakpoint(ADDR)
  end
  return 1   -- 1 = 继续运行，不暂停游戏
end

-- 主流程
if not debugger_isDebugging or not debugger_isDebugging() then
  debugProcess()
end

log("==================================================")
log("set HW-exec breakpoint at " .. string.format("%08X", ADDR))
local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
if not ok then
  log("BREAKPOINT FAILED: " .. tostring(err))
  log("如果是 'Access denied'，请用管理员身份运行 Cheat Engine。")
else
  log("breakpoint armed. 现在回游戏点一次登录。")
end
