--[[
ce_tbl_trace.lua —— 用 CE（提权）打出"第 2 张表为什么不过"的运行时真相

只打 4 个硬件执行断点（DR 寄存器上限 4 个），全部只记录、不改任何值：

  0x544922  分派 case 1（msma/msma_weapon_set.csv 的处理分支）
            → 命中说明 node 的序号确实是 1，且 [0x1169A48] 表对象可用
  0x9DC930  CMSMAWeaponSetTable::Load
            → 命中说明确实进了这个表的加载器
  0x544DD7  成功推进（摘节点、置完成位）
  0x544E07  清理退出（失败/异常都汇到这里）

判读方法：
  · case1 没命中        → 序号不是 1（分派表对不上）
  · case1 命中、Load 没命中 → 进了分支但没调 Load（对象为空 / 提前 return）
  · Load 命中、advance 没命中、bail 命中 → Load 抛异常或返回失败
  · Load 命中、advance 命中 → 其实成功了，卡点在别处（消息没发出去）

用法：
  1. 把本文件放到 "C:\Program Files\Cheat Engine\autorun\"
  2. **以管理员身份**启动 Cheat Engine（脚本会自己附加、下断点）
  3. 回游戏点一次「登录」
  4. 看 D:\project\gundam-reburn\server\ce_tbl.log
--]]

local TARGET = "GundamOnline_CHINA.exe"
local LOG    = "D:\\project\\gundam-reburn\\server\\ce_tbl.log"

local BPS = {
  {0x544922, 'case1  (分派 序号1)'},
  {0x9DC930, 'Load   (CMSMAWeaponSetTable)'},
  {0x544DD7, 'advance(成功推进)'},
  {0x544E07, 'bail   (清理退出)'},
}

local armed = false
local attached = false

local function log(s)
  print('[tbl] ' .. s)
  local f = io.open(LOG, 'a')
  if f then f:write(os.date('%H:%M:%S ') .. s .. '\n'); f:close() end
end

local function reg(name)
  local ok, v = pcall(function() return _G[name] end)
  if ok and type(v) == 'number' then return v end
  return nil
end

local function tryAttach()
  if not (debugger_isDebugging and debugger_isDebugging()) then
    local pid = getProcessIDFromProcessName(TARGET)
    if pid == nil or pid == 0 then return false end
    if not attached then
      local ok = openProcess(pid)
      log(string.format('openProcess(%d) -> %s', pid, tostring(ok)))
      if not ok then return false end
      debugProcess()
      attached = true
    end
  end
  if not armed then
    for _, bp in ipairs(BPS) do
      local ok, err = pcall(debug_setBreakpoint, bp[1], 1, bptExecute, bpmDebugRegister)
      log(string.format('  arm %08X %-32s -> %s %s', bp[1], bp[2], tostring(ok), tostring(err or '')))
    end
    armed = true
    log('=== 4 个断点就绪，回游戏点登录 ===')
  end
  return true
end

function debugger_onBreakpoint()
  local ok, err = pcall(function()
    local eip = reg('EIP')
    if eip == nil then return end
    if eip == 0x544922 then
      local obj = 0
      local g = 0
      local raw = readInteger(0x1169A48)
      if type(raw) == 'number' then obj = raw; g = 0x1169A48 end
      log(string.format('hit case1  ecx=%s  [0x1169A48]=%s',
          tostring(reg('ECX')), tostring(raw)))
    elseif eip == 0x9DC930 then
      log(string.format('hit Load   ecx(this)=%s  arg=%s',
          tostring(reg('ECX')), tostring(reg('EDX'))))
    elseif eip == 0x544DD7 then
      log('hit advance  ← 成功推进')
    elseif eip == 0x544E07 then
      log('hit bail     ← 清理退出（失败）')
    end
  end)
  if not ok then log('handler error: ' .. tostring(err)) end
  return 1
end

log('==================== 新一次装载 ====================')
local t = createTimer(nil)
t.Interval = 800
t.OnTimer = function(timer)
  local ok, err = pcall(tryAttach)
  if not ok then log('timer error: ' .. tostring(err)) end
  if armed and attached then pcall(function() timer.destroy() end) end
end
