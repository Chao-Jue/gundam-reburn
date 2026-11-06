# 0x5290 表体压缩：突破客户端单帧 16366 B 上限

> 2026-11-06 · 5.0.0.33 客户端真机验证 · 对应改动 `server/fake_auth.py::datafile_block`
> 自测：`python tools/verify_table_compress.py`（纯标准库，不需要客户端）

## TL;DR

表体一大，登录就会弹 `[5:13] 服务器响应被切断` / 停在「正在取得数据」直到 `L 2:0`。
根因不是表内容不合法，而是**客户端单帧最多收 16366 B**，而一张 `msma_settings.csv`
在 269 台机体时已经是 101489 B。协议正文里**本来就有** `u16 compress` 字段，
客户端也真的实现了解压分支；把它用起来即可，无需改客户端、无需分片。

---

## 1. 上限是怎么来的

`0x5290`（`recv_datafile_download_r`）走的是普通休息室数据帧，长度上限按
`max(conn->cap - 0x12, 0x578)` 算，`cap = 0x4000` ⇒ **16366 B**。
这里算的是**整帧明文**（`_kind0` 帧头 + opcode + 正文 + `_align_message` 的 16 字节对齐填充）。

| 阶段 | `msma_settings.csv` | 结果 |
|---|---:|---|
| 40 台机体 | 14727 B | 刚好贴着上限 |
| 269 台机体 | 101489 B | 必炸 |
| 358 台机体 | 131710 B | 必炸 |

表体超限的表现是整轮表下载中断：客户端停在「正在取得数据」，空闲掐线后报
`L 2:0`；50033 客户端会直接弹 `[5:13]`。前面的表都成功、只在这一张卡住，
很容易误判成「这张表的 CSV 格式错了」。

## 2. 为什么不能拆成多帧

`0x5290` 正文逐字段：

```
u32    result          负值时客户端直接丢弃整帧
cstr   filepath\0      与下载队列节点按 wstring 精确匹配
u32    hash            客户端未参与判断
u32    src_bytes       解压后长度（见下）
u16    compress        0 = 直传 / 1 = zlib
u32    bin_len         本次下发的正文字节数
bin    payload
```

**没有 offset、序号、总长中的任何一个。** 而且按
`server/数据表下载-请求逻辑全解.md` §7 的串行流程，客户端收到一帧就当场
解包 → `Load` → `std::map::erase` 节点 → 发下一张表的请求。第一帧处理完节点就没了，
第二帧即使发过去也会因为名字查不到而静默 return。所以**一帧必须等于一整张表**，
多帧下发在这个协议上不成立。

⇒ 唯一出路是让单帧装得下整张表：压缩。

## 3. 客户端解压分支的双向证据

### 3.1 本仓库已有的反编译结论

`server/数据表下载-请求逻辑全解.md` §11 给出的 `FUN_00AF6080`
（`recv_datafile_download_r`）：

```c
void FUN_00af6080(int result, name, hash, size_t raw_len,
                  size_t packed /* 低16位当标记 */, ptr, int body_len)
{
    if (result < 0) return;
    if ((short)packed == 0) {
        FUN_00a4fac0(name, ptr, body_len);      // 直传
    } else if ((short)packed == 1) {
        pv = calloc(raw_len, 1);               // ← 输出缓冲按 src_bytes 开
        FUN_00bd2ab0(ptr, body_len, pv, &packed);   // 解压
        FUN_00a4fac0(name, pv, packed);        // ← 用解压出的实际长度
        free(pv);
    }
}
```

由此确定三个字段的语义：

| 字段 | 含义 | 填错会怎样 |
|---|---|---|
| `src_bytes` | **解压后**长度，客户端 `calloc` 的大小 | 填小了 → 静默截断，且不检查 inflate 返回值 |
| `compress` | 按 `(short)` 判 0 / 1 | 只能填 0 或 1 |
| `bin_len` | **压缩后**长度，inflate 的输入长度 | 不一致 → 解压失败 |

### 3.2 50033 客户端确实静态链了 zlib

`GundamOnline_CHINA.exe`（15,659,840 B）里的明文字符串：

| 文件偏移 | 字符串 |
|---|---|
| `0xA69E40` | `err == Z_OK` |
| `0xA69E52` | `common\zlib.cpp` |
| `0xA6A111` | `deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly` |
| `0xA758C9` | `inflate 1.2.3 Copyright 1995-2005 Mark Adler` |
| `0xBA7A27` | `uncompress` |
| `0xC7DD19` | `zlib1.dll` |

### 3.3 一处容易混淆的地方

`server/反编译-数据表加载链路.md` §5 写过「报文里的压缩标记实际不起作用
（那条 `flag==0` 的分支走不到）」。那里分析的是 **UTF-8 → UTF-16 转码函数
`FUN_00A463C0` 的 `flag` 参数**（调用方恒传 1），和 `0x5290` 帧里的
`u16 compress` 是**两个不同字段**。§11 的 handler 才是帧层结论，两者不矛盾。

另：客户端会把正文当 UTF-8 文本读（某些路径先丢前 2 字节）。压缩的是**完整原始表体**
（含 BOM / 头字节），inflate 后逐字节还原，后续转码逻辑完全不变。

---

## 4. 本 PR 改了什么

只改 `server/fake_auth.py` 的 `datafile_block` 一个函数（对 `main` 的 diff 约 60 行，
文件其余 121 KB 字节不动）。**默认 `MSGO_TABLE_COMPRESS=0`，生成的帧与改动前逐字节一致**，
不会改变现有 66 张表的实验行为。

| 环境变量 | 行为 |
|---|---|
| 不设 / `0` | 原样直传（`compress=0`），默认 |
| `auto` | 表体 ≥ `MSGO_TABLE_COMPRESS_MIN`（默认 2048 B）且 zlib9 后小于原长 80% 才压（推荐） |
| `1` | 强制 zlib9 压缩，连小表也压（做协议验证时用） |

另外无论开关状态，整帧超过 16366 B 时都会打一条明确的 `[table] ... > 16366B` 日志，
省得下次再去猜 `[5:13]`。实现只用标准库 `zlib` / `os`，函数内 import，不新增依赖。

## 5. 用法与回退

```bash
# 行为不变（默认）
python server/fake_auth.py ...

# 启用压缩（Linux/macOS）
MSGO_TABLE_COMPRESS=auto python server/fake_auth.py ...

# 启用压缩（Windows）
set MSGO_TABLE_COMPRESS=auto
python server\fake_auth.py ...

# 纯标准库自测：帧字段、zlib 往返、阈值、src_bytes 陷阱、默认字节等价
python tools/verify_table_compress.py
```

回退：去掉环境变量（或设 `0`）并重启服务端即可，无需回滚任何数据。
`auto` 下压缩失败或压不动时会自动退回直传，不会发出更差的帧。

## 6. 5.0.0.33 真机实测

服务端挂 358 台机体，四张 `msma_*` 表下发（zlib level 9）：

| 表 | 原始 | zlib9 | 压缩率 |
|---|---:|---:|---:|
| `msma/msma_settings.csv` | 131710 B | 12864 B | 9.8% |
| `msma/msma_battle_detail.csv` | 108456 B | 13318 B | 12.3% |
| `msma/msma_model.csv` | 26278 B | 1232 B | 4.7% |
| `msma/msma_weapon_set.csv` | 6647 B | 422 B | 6.3% |

最大帧 **13382 B / 16366 B**，余量 2984 B。真机：机库 `358/358`、52 页、
登录无 `[5:13]`，逐台点开 3D 模型与性能面板正常。

历史对照：269 台时 `settings 101489 → 8976 B`、`battle_detail 79116 → 8192 B`；
387 台时最大帧 14236 B（余 2130 B）——压缩把「45 台封顶」直接抬到了几百台量级。

## 7. 陷阱与边界

1. **`src_bytes` 必须填解压后长度。** 填成压缩后长度时，客户端只开出那么大的缓冲，
   inflate 被静默截断，表看起来「少了一大半」且不报错。`tools/verify_table_compress.py` §6
   用 `zlib.decompressobj(..., max_length=...)` 复现了这一点。
2. **不要试图分片**（§2），也不要指望 `result != 0` 让客户端「跳过这张表」——负值直接丢帧。
3. **235 客户端未做真机验证。** 本仓库的反编译表明它同样有 `compress==1` 分支，
   但 `_kind0` 的注释提到客户端对 `k=1` 的 2 字节长度「只取低 8 位」；
   大帧（>255 B）在 235 上是否受影响需要实测。建议先在 235 上用
   `MSGO_TABLE_COMPRESS=1` 拿一张小表验证解压分支，再逐步放大表体。
   50033 客户端 13382 B 大帧实测正常。
4. 压缩只解决「单帧装不下」，不解决表内容本身的格式/枚举错误。
5. `log()` 的告警文本是纯 ASCII，避免非 UTF-8 日志编码问题。

## 8. 关联

- 协议依据：`server/数据表下载-请求逻辑全解.md` §11、`server/接收链路与状态机分析.md` §7。
- 与客户端侧补丁（authsv 重定向、机库相机）互不冲突：本改动只在服务端 `fake_auth.py`，
  不改客户端任何字节。
