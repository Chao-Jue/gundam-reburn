--[[
Cheat Engine Lua 脚本：把一段代码 dump 成 hex 文本，供离线反汇编。

背景：CE 附加并调试进程时，frida 无法再注入（VirtualAllocEx 返回 5 = 拒绝访问），
      所以改用 CE 自己读内存 —— 纯读，不装断点、不改字节。

本次目标：RingWrite(0xC034F0) 的真实调用者 = 0xBEB3A3，
          dump 0xBEB000 ~ 0xBEB800（2KB）覆盖它周边的函数。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe（调试暂停或不暂停都行）
  2. View -> Lua console (Ctrl+Alt+L) -> File -> Open 本文件 -> Ctrl+Enter
  3. 生成 D:\project\gundam-reburn\server\ce_code.txt（纯 hex 字符串）
--]]

local START = 0xBD4E00
local COUNT = 2048
local OUT   = "D:\\project\\gundam-reburn\\server\\ce_code8.txt"
local META  = "D:\\project\\gundam-reburn\\server\\ce_code8.txt.meta"

local function log(s) print(s) end

local ok, err = pcall(function()
  local t = {}
  for i = 0, COUNT - 1 do
    local b = readBytes(START + i, 1, true)
    t[#t + 1] = string.format("%02x", b[1])
  end
  local hex = table.concat(t)
  local f = io.open(OUT, "w")
  f:write(hex)
  f:close()
  local m = io.open(META, "w")
  m:write(string.format("start=0x%X count=%d\n", START, COUNT))
  m:close()
  log(string.format("dumped %d bytes from 0x%X -> %s", COUNT, START, OUT))
end)

if not ok then
  log("DUMP FAILED: " .. tostring(err))
  log("如果提示 readBytes 失败，请先让游戏跑起来（CE 没暂停）再执行。")
end
