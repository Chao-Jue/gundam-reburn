# 「通信被切断」的真相：客户端自己崩了（AV），不是协议拒绝

> 2026-10-23 19:45，纯离线产出。结论改变了对整件事的理解。

---

## 1. 先看两个铁证

### 1.1 `vt[0x64]` 错误虚函数 = "记一笔 + 关连接"

`_proto_lounge::error` = `0xAA29C0`，它拼的字符串是：

```
 _proto_lounge::RecvException(function=   ← 0xE0B9DC
 ,code=                                   ← 0xE035E0
 ) close.....                             ← 0xE035E8
```

尾部还有 `call 0xBD21A0(this)`（关连接）。
⇒ **只要走到 `error(handler, code)`，客户端就会主动 close**，
界面上就是我们看到的「服务器通信被切断了 (L0:0)」。

### 1.2 同一时刻，客户端自己写了崩溃记录

`launcher/gundam/机动战士敢达Online/GundamOnline/user/exrep.log`（79 字节，mtime 19:36）：

```
1792755418,0x075e8d71,0x075e8d71
0x778ac75b
0x778ac6e1
,0xc0000005,0
0x42efd4c
```

- `1792755418` = 2026-10-23 19:36:58 —— **正是 `both_t12` 发出的那一刻**；
- `0xc0000005` = **ACCESS_VIOLATION**；
- `0x42efd4c` = 出错时被访问的地址（0x042EFD4C 在 19MB 主模块之外，属堆区，不是代码地址）；
- 格式串在主镜像 `0xDF73A7` = `"%d,0x%08x,%s"`，日志路径串 `0xDF7348` = `user\exrep.log`
  （引用这两处的代码没在明文段找到 → 很可能在 `.vmp0`）。

⇒ **我们发"有机师的机师列表"时，客户端不是拒绝，而是踩了一个空指针/野指针。**

## 2. 这解释了什么

| 现象 | 解释 |
|---|---|
| 全零正文（`zero`）完全静默、连接不断 | 解析成功但两侧记录都是"空"（回调收到 NULL 指针），根本不进填卡片分支 |
| 只要"id + 名字都在"就 0.0 秒断连 | 进了填卡片/切界面分支 → 在堆上解引用了野指针 → AV |
| 断连后没有重连 | AV 之后会话被拆，进了"通信中断"终态 |
| 改 `troops`、改 `result` 都没用 | 崩的不是校验，是客户端自己的 UI 代码 |

⇒ **继续在服务端调字段值，大概率永远调不通**。这条路的上限就是"不崩"，而崩点在客户端内部。

## 3. 下一步的正确方向（还没做）

要修，必须先拿到 **AV 发生的那条指令和调用栈**。三个方案，按侵入性从低到高：

| 方案 | 侵入性 | 说明 |
|---|---|---|
| **A. frida 只装异常处理器** | 极低（**不改任何代码/数据**） | attach 后用 `Process.setExceptionHandler` + `Thread.backtrace`，把 `ExceptionRecord.ExceptionAddress/CauseAddress` 和栈打出来。这是"挂一个 VEH"，不是 inline hook，CPS 校验的是代码字节，不会动。 |
| B. 开 WER LocalDumps | 低（改注册表 HKLM，要管理员） | `LocalDumps\GundamOnline_CHINA.exe` + `DumpType=2`，让系统落完整 minidump。**但前提是异常没被客户端自己的 SEH 处理掉**；从 `exrep.log` 能写出来看，它有自己的处理器，WER 可能不触发。 |
| C. 读 `.vmp0` 里的崩溃上报代码 | 纯离线 | 那两处字符串引用不在明文段，说明写 `exrep.log` 的代码被虚拟化了；代价高、收益低。 |

**建议先走 A**：一次 attach，只加一个异常处理器，崩溃时把 EIP/栈打出来。
拿到 EIP 后回到离线，就能定位到具体是哪段 UI 代码、需要什么数据。

## 4. 顺带确认的日志线索（将来可能有用）

成功分支 `0xAD009C` 之后是一大段**解析日志**，格式串包括：

```
0xE0D848  ')->_proto_lounge_client::recv_pilot_list_get_r( '
0xE036EC  ' (id:'
0xE036F4  'result='
0xE0C114  'pilots_eff={'
0xE8B2AC  ','
```

⇒ 客户端**有**对机师列表的逐字段打印，但它走的是全局 logger 对象
`[0x108D1D0]` 的 vtable `+8`（`call [eax+8]`）。如果能确认这个 logger 往哪儿写
（文件 / OutputDebugString），就能白拿一份"客户端眼里每条记录长什么样"的观测——
比我们现在的黑盒试错强得多。**这条待查**。
