--[[
ce_skip_datadl.lua —— 让客户端跳过"数据表下载"这一步

背景（见 server/接收链路与状态机分析.md 第七节）：
  客户端要下载 74 个服务端数据表。第 1 张 autoexec_sv.cfg 能过，
  第 2 张 msma/msma_weapon_set.csv 不管回什么占位正文都过不去 ——
  表加载器按表强类型校验，抛的异常被 0x544790 的 SEH 帧吞掉，
  于是不报错、不推进，最后 --idle 45 掐线 + L 2:0。

做法：
  在 0x544790（"处理一条下载完成的文件"）装**硬件**执行断点
  （bpmDebugRegister，不改任何代码字节，Themida 看不到）。
  命中时 ecx = 下载管理器，[ecx+8] = std::list 哨兵，哨兵自环 = 空队列。
  默认在第 2 次命中（= 第 2 张表）时把哨兵自环写回，让队列变空，
  看状态机是否因此认为"没有要下的东西"而进下一步。

用法 A（推荐，自动）：
  把本文件放到 "C:\Program Files\Cheat Engine\autorun\"，然后启动 CE。
  脚本会自己轮询、附加、下断点。之后回游戏点登录即可。
用法 B（手动）：
  CE 附加 GundamOnline_CHINA.exe → View → Lua console → 打开本文件 → Ctrl+Enter。

日志：D:\project\gundam-reburn\server\ce_skip.log
--]]

local TARGET   = "GundamOnline_CHINA.exe"
local ADDR     = 0x544790          -- 处理一条下载完成的文件
local LOG      = "D:\\project\\gundam-reburn\\server\\ce_skip.log"
local ACT_ON   = 2                 -- 第几次命中才动手（1=第一张表就清空，2=第二张）
local hits     = 0
local armed    = false
local done     = false
local attached = false

local function log(s)
  print('[skip] ' .. s)
  local f = io.open(LOG, 'a')
  if f then
    f:write(os.date('%H:%M:%S ') .. s .. '\n')
    f:close()
  end
end

local function reg(name)
  local ok, v = pcall(function() return _G[name] end)
  if ok and type(v) == 'number' then return v end
  return nil
end

local function rdptr(a)
  local ok, v = pcall(readPointer, a)
  if ok and type(v) == 'number' then return v end
  return nil
end

local function tryAttach()
  if done then return true end

  if not (debugger_isDebugging and debugger_isDebugging()) then
    local pid = getProcessIDFromProcessName(TARGET)
    if pid == nil or pid == 0 then return false end
    if not attached then
      local ok = openProcess(pid)
      log(string.format('openProcess(%d) -> %s', pid, tostring(ok)))
      if not ok then return false end
      local dok = debugProcess()
      log('debugProcess -> ' .. tostring(dok))
      attached = true
    end
  end

  if not armed then
    local ok, err = pcall(debug_setBreakpoint, ADDR, 1, bptExecute, bpmDebugRegister)
    log(string.format('arm HW-exec bp @%X -> %s %s', ADDR, tostring(ok), tostring(err or '')))
    armed = true
  end
  return true
end

function debugger_onBreakpoint()
  if EIP ~= ADDR then return 1 end

  local ok, err = pcall(function()
    hits = hits + 1
    local mgr = reg('ECX')
    if mgr == nil then log('hit#' .. hits .. ' ECX 读不到'); return end

    local sentinel = rdptr(mgr + 8)
    local head = sentinel and rdptr(sentinel) or nil
    local idx, nm = -1, ''
    if head and sentinel and head ~= sentinel then
      idx = readInteger(head + 0xc) or -1
      nm = readString(head + 0x24, 64) or ''
    end
    log(string.format('hit#%d mgr=%08X sentinel=%s head=%s idx=%d name=%s',
        hits, mgr, sentinel and string.format('%08X', sentinel) or 'nil',
        head and string.format('%08X', head) or 'nil', idx, nm))

    if hits >= ACT_ON and not done then
      done = true
      if sentinel then
        writePointer(sentinel, sentinel)
        writePointer(sentinel + 4, sentinel)
        log('queue emptied (哨兵自环) -> 继续运行')
      end
      pcall(debug_removeBreakpoint, ADDR)
      log('breakpoint removed')
    end
  end)

  if not ok then log('handler error: ' .. tostring(err)) end
  return 1
end

log('==================== 新一次装载 ====================')
log(string.format('target=%s addr=%X act_on_hit=%d', TARGET, ADDR, ACT_ON))

local t = createTimer(nil)
t.Interval = 800
t.OnTimer = function(timer)
  local ok, err = pcall(tryAttach)
  if not ok then log('timer error: ' .. tostring(err)) end
  if done then pcall(function() timer.destroy() end) end
end
