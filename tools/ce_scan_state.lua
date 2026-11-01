--[[
Cheat Engine Lua 脚本：全模块扫描"谁把 socket 状态字段 (+0x280) 设成 4 / 3 / 6"

背景（已确认）：
  · socket+0x280 = 连接状态
  · 状态 3：收 16 字节 → 打印 hex 日志（0xBEB0C0 是 hex 编码器）→ 状态变 6
  · 状态 6：收包/解密/写队列，但**不解析**
  · 状态 4：才走 0xBEFB92 那条"取帧 → 0xBEF9C0 构造消息对象 → 虚表分发"的路
  ⇒ 找到"谁写 4"，就知道客户端在等什么条件。

做法：AOB 扫描 `C7 86 80 02 00 00 XX 00 00 00`（mov dword [esi+0x280], imm32）
      以及 ecx/edi 等寄存器变体，列出命中地址。

用法：
  1. CE（管理员）附加 GundamOnline_CHINA.exe
  2. View -> Lua console -> File -> Open 本文件 -> Ctrl+Enter
  3. 不需要登录（纯扫描）
  4. 结果：D:\project\gundam-reburn\server\ce_state_scan.txt
--]]

local LOG = "D:\\project\\gundam-reburn\\server\\ce_state_scan.txt"

local function log(s)
  print(s)
  local f = io.open(LOG, "a")
  if f then f:write(s .. "\n"); f:close() end
end

local patterns = {
  { name = "state=4 (esi)", pat = "C7 86 80 02 00 00 04 00 00 00" },
  { name = "state=3 (esi)", pat = "C7 86 80 02 00 00 03 00 00 00" },
  { name = "state=6 (esi)", pat = "C7 86 80 02 00 00 06 00 00 00" },
  { name = "state=4 (ecx)", pat = "C7 81 80 02 00 00 04 00 00 00" },
  { name = "state=3 (ecx)", pat = "C7 81 80 02 00 00 03 00 00 00" },
  { name = "state=6 (ecx)", pat = "C7 81 80 02 00 00 06 00 00 00" },
  { name = "state=4 (edi)", pat = "C7 87 80 02 00 00 04 00 00 00" },
  { name = "state=3 (edi)", pat = "C7 87 80 02 00 00 03 00 00 00" },
  { name = "state=6 (edi)", pat = "C7 87 80 02 00 00 06 00 00 00" },
  { name = "state=4 (ebx)", pat = "C7 83 80 02 00 00 04 00 00 00" },
  { name = "state=3 (ebx)", pat = "C7 83 80 02 00 00 03 00 00 00" },
  { name = "state=6 (ebx)", pat = "C7 83 80 02 00 00 06 00 00 00" },
}

log("==================================================")
log("scanning for writes to socket+0x280 ...")

for _, p in ipairs(patterns) do
  local res = nil
  local ok = pcall(function() res = AOBScan(p.pat, "+X*W-C") end)
  if ok and res then
    local n = res.Count
    log(string.format("[%s] %d hit(s)", p.name, n))
    for i = 0, math.min(n, 12) - 1 do
      log("    " .. res[i])
    end
    res.destroy()
  else
    log(string.format("[%s] none", p.name))
  end
end

log("done. 把 ce_state_scan.txt 的内容发回来即可。")
