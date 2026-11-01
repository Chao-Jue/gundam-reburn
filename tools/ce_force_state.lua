--[[
Cheat Engine Lua 脚本：强行把连接状态从 6 改成 4（进入"解析模式"）

原理：
  ring = socket + 0x4E0     （0xBD504A 处的 lea ebx,[edi+0x4E0]）
  ⇒ socket = ring - 0x4E0
  状态字段  = socket + 0x280
  认证标志  = socket + 0x9C

做法：
  1. 在 0xBD50A0（收包时调 RingWrite 的那一行）下执行断点，命中即可拿到 EBX=ring
  2. 算出 socket，读出 状态 / 标志
  3. 把 状态 写成 4（若 标志==0 也一并写成 1）
  4. 立刻撤掉断点，回游戏观察

⚠️ 这属于"硬改客户端状态"，有可能让它逻辑错乱甚至退出。
   但它是目前最快能分清「进不去的解析模式」和「进去了但不认内容」的办法。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 回游戏点一次登录（会打印 socket/状态，然后自动改写）
  4. 观察游戏画面 / 再看日志
  5. 日志：D:\project\gundam-reburn\server\ce_force.log
--]]

local PRODUCER = 0xBD50A0
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_force.log"
local DONE     = false

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
  if DONE then return 1 end
  DONE = true

  local ok, err = pcall(function()
    local ring = reg("EBX")
    local sock = ring - 0x4E0
    local state = rd(sock + 0x280)
    local flag  = rd(sock + 0x9C)

    log(string.format("ring=%08X  socket=%08X  state=%d  flag[+9C]=%d",
                      ring, sock, state, flag))

    if sock <= 0 or sock > 0x7FFFFFFF then
      log("!! socket 地址异常，放弃改写")
      return
    end

    -- 先把标志位补上（状态1+标志!=0 才是进状态4的合法条件）
    if flag == 0 then
      local o1 = pcall(writeInteger, sock + 0x9C, 1)
      log(string.format("write [%08X+9C] = 1  -> %s", sock, tostring(o1)))
    end

    local o2 = pcall(writeInteger, sock + 0x280, 4)
    log(string.format("write [%08X+280] = 4  -> %s", sock, tostring(o2)))
    log(string.format("now  state=%d  flag=%d", rd(sock + 0x280), rd(sock + 0x9C)))

    pcall(debug_removeBreakpoint, PRODUCER)
    log("breakpoint removed. 回游戏看有没有变化（界面跳转/弹窗/再发包）。")
  end)

  if not ok then log("!! handler error: " .. tostring(err)) end
  return 1
end

if not debugger_isDebugging or not debugger_isDebugging() then debugProcess() end

log("==================================================")
pcall(debug_removeBreakpoint, 0xE6408C)
pcall(debug_removeBreakpoint, 0xE6410C)
pcall(debug_removeBreakpoint, PRODUCER)
log(string.format("stage: HW-exec bp at producer 0x%X（登录时命中一次即改写状态）", PRODUCER))
local ok = pcall(debug_setBreakpoint, PRODUCER, 1, bptExecute, bpmDebugRegister)
log("armed=" .. tostring(ok) .. "  回游戏点一次登录。")
