# GundamOnline_CHINA.exe —— RTTI 类名地图（2026-10-17）

> 全量清单：`server/rtti_classes.txt`（2850 条，含文件偏移）

## 0. 怎么拿到的（重要：不需要跑客户端）

之前一直以为"双层壳 → 反汇编垃圾 → 没符号"，所以从没试过直接在磁盘文件上找。
实际上 **MSVC 的 RTTI 类型名是纯 ASCII 明文，压根没被 Themida 加密**：

```
0x00b2f018  .?AVILockObject@es@@
0x00b2f02c  .?AVCNullLockObject@es@@
0x00b2f05c  .?AVrymUIControl@rhyme@@
0x00b2f0d0  .?AVCGameStateStepUpdateBase@@
0x00c88f20  .?AVCGVOProtoAuth@@
```

一条 `.?AV<名字>@@` 就是一个类的 `TypeDescriptor.name`。扫出来 **2850 个类名**，
从 `0x00b2f018` 连续到 `0x00d61ed0`——也就是 `.rdata` 里整片 RTTI 表都在。
（`.??_7` 虚表名 0 命中，是因为 `_7` 只出现在被剥掉的 COFF 符号表里，不代表没有虚表。）

**这意味着：壳只保护了代码段，没保护数据段里的类型信息。** 这一条以后要记住。

## 1. 客户端状态机（按 RTTI 表里的物理顺序）

RTTI 表按编译单元顺序排列，`CGameStateStep*` 这一段几乎就是登录流程本身：

```
CGameStateStepUpdateBase
  → ConnectAuth        连认证服
  → WorldSelect        ★ 选战区（当前卡点）
  → LoginLounge        进大厅
  → PilotSelect        选驾驶员
  → PilotCreate / PilotDelete
  → LoginAuth          账号认证
  → Gacha / TicketBuyGacha
  → LoginBattle → GameBegin → GameStart
  → GameRoundEnd → GameEnd
  → MSMAList → MSMASelect → Respawn → MoveAreaWait → MoveAreaMap
  → RoomEnter/Create/Exit、QuickStart、Kick/KickInGame/KickInResult …
```

**关键推论：`WorldSelect` 排在 `LoginAuth` 之前。**
这和用户"输账号密码之前先选战区"的观察完全一致，也说明
**战区列表不是登录响应的一部分，而是登录的前置输入**——
它必须来自"更早的一次连接"（ConnectAuth）或者本地表。

## 2. 战区相关的类（本次最大收获）

```
CWorldSelectWindow@IF          战区选择窗
CWorldSelectMenu@IF            战区的下拉菜单
CWorldListItem@IF              列表项
WorldItemCreator@IF            列表项工厂
CGameStateStepUpdateWorldSelect  状态机里的"选战区"步
?$TIndexTable@UWORLD_MAP_DATA@@ ★ 战区表（索引表模板）
CWorldMapTable                 ★ 战区表本体
```

`TIndexTable<UWORLD_MAP_DATA>` + `CWorldMapTable` 的组合说明：
**战区是一张"索引表"，有固定行结构 `WORLD_MAP_DATA`**。
索引表在引擎里通常由一个资源文件填充 → 只要找到这张表的内存实例，
把 `rows / count` 读出来，就能知道**客户端认为有几个战区、每个战区的名字/地址/端口在哪**。

这条和之前"`---` / `技术测试区` 两种结果不稳定"能对上：
表没被填（0 行）时下拉是空的；填了 1 行时显示 `技术测试区`；`---` 大概是"已选但无效"的占位。

## 3. 网络层：`ivce`（自研网络库）

```
iVCE / iObject / iBuffer           根接口
iTcpStream / iUdpStream / iLoopbackStream / iProxyStream
iTcpListener / iUdpListener / iProxyListener / iLoopbackListener
iSession / iStreamSession
iSocket / iSocketWrapper / iSocketLocalWrapper / iProxyStream
Poller@kernel / PollerImpl@kernel  事件循环
```

装饰器（管道式叠加，注意是**套娃**结构）：

```
iCryptSession< TcpStream, CamelliaCrypter  >
iCryptSession< TcpStream, RijndaelCrypter  >     (Rijndael = AES)
iCompressSession< LZP,       TcpStream >
iCompressSession< ZLIB,      TcpStream >
iCompressSession< ZLIB, iCryptSession<TcpStream, CamelliaCrypter> >   ← 加密后再压缩
```

**这是 16 字节登录包的关键线索：**

- `CamelliaCrypter` 的块长是 **128 bit = 16 字节**，和实测"客户端第一包正好 16 字节"严丝合缝。
- 会话层是**加密 + 压缩**两条装饰器，说明首包之后的数据是 `[长度头][密文]` 结构。
- 两种算法都在（Camellia / Rijndael），说明**算法是可配置的**（按客户端版本或握手协商）。

→ 下一步只要拿到 `CamelliaCrypter`/`RijndaelCrypter` 的**密钥来源**
（固定常量、还是从 authsv 或握手包派生），16 字节包就能解。

## 4. 协议层：三个域

```
_proto_auth          _proto_auth_client          CGVOProtoAuth
_proto_lounge        _proto_lounge_client        CGVOProtoLounge
_proto_battle        _proto_battle_client        CGVOProtoBattle
```

`_proto_xxx` / `_proto_xxx_client` 成对出现 + `CGVOProtoXxx` 包裹类，
是**IDL 生成代码**的典型形态（服务端/客户端各一套消息定义）。
结合 `CDataTableDownload` 类，说明这张表本身也是**从服务端拉取**的。

## 5. 数据表体系（`TIndexTable<UXxx_DATA>`）

客户端确实内置了一大批数据表的**类型定义**（不是数值）：

```
UMSMA_DATA / UMSMA_MISSIONUNIT_DATA / UMSMA_FIXED_MODULE_DATA / UMSMA_OVER_CUSTOM_DATA
UMECHANIC_MSMA_DATA / UMECHANIC_WEAPON_DATA / UMECHANIC_OVER_CUSTOM_DATA / UMECHANIC_SUCCESS_DATA
UMODULE_DATA / UMODULE_DEVELOP_DATA / UMODULE_BONUS_DATA / UMODULE_RENTAL_DATA
UBULLET_DATA / UPART_DATA / UWEAPON(…) / ULVUP_MSMA_DATA / ULVUP_CLAN_DATA
UCOMMANDER_SUPPORT_DATA / UPILOT_FORM_DATA / UMEDAL_DATA / UBADGE_DATA / UCHARA_FLIGHT_DATA
```

**注意边界：这些只是"表结构"，不是数值，更不是战斗公式。**
和已经确认的"机体/武器/对战计算 100% 在服务端"并不矛盾——
客户端表里最多是 UI 展示用的副本。

## 6. 对当前卡点的意义

| 之前认为 | 现在的实际情况 |
|---|---|
| 逆不了符号 | **2850 个类名白送**，UI/网络/协议/表结构全都能对上号 |
| 战区列表来源不明 | 有 `CWorldMapTable` + `TIndexTable<WORLD_MAP_DATA>`，是**表**，可定位 |
| 登录包算法不明 | 会话层是 **Camellia(16B 块) / Rijndael**，16 字节 = 一个块，高度吻合 |
| 只能盲试 API | 可以按 `CGameStateStepUpdate*` 逐个下钩子，看状态机停在哪一步 |

## 7. 已解析出的 vtable（运行时，模块基址 0x400000）

链路：`类名 → TypeDescriptor(-8) → CompleteObjectLocator → vtable[-1] → 虚函数地址表`。
本次成功解析 12 个（`--scan-rtti` 会自动挑 `CWorld|CAuth|CLogin|CConnect|CGVOProto|Crypter`）：

| 类 | TypeDescriptor | vtable | 首槽（约=析构/首个虚函数） |
|---|---|---|---|
| `CWorldMapTable` | 0x1085bc4 | **0xdf9674** | 0x557a20, 0x9cc590, 0x9d1e40, 0x9d1e70, 0x9cc890, 0x9dee20… |
| `CWorldSelectWindow@IF` | 0xf39450 | **0xd0b3fc** | 0x6e7510, 0x4304e0, …, 0x6e80c0 |
| `CWorldSelectMenu@IF` | 0xf3942c | **0xd0b134** | 0x6e7480, …, 0x972b50 |
| `CWorldListItem@IF` | 0xf39540 | **0xd0b7a4** | 0x6e77f0, … |
| `CLoginWindow@IF` | 0xf39334 | **0xd09c04** | 0x6e3a20, … |
| `CAuthSelectWindow@IF` | 0xf392f0 | **0xd09884** | 0x6e37d0, … |
| `CAuthSelectItem@IF` | 0xf392cc | 0xd094dc | 0x6e0f20, … |
| `CAuthCodeWindow@IF` | 0xf2f3d0 | 0xde744c | 0x967090, … |
| `CConnectListWindow@IF` | 0xf3f72c | 0xd73ca4 | 0x8439d0, … |
| `CConnectDetailSlot@IF` | 0xf3f708 | 0xd73914 | 0x842c30, … |
| `CDataTableDownload` | 0xf31ea4 | 0xcb9edc | 0x545380, 0x4c4c41 |
| `CLoginScene` | 0x1086738 | 0xdf9ee0 | 0x9e80a0, … |

> 地址都是**运行时**的（壳解包后有效），每次启动模块基址固定在 0x400000，可复现。
> 原始结果：`server/hook_runs/rtti_scan.json`。

**有了 vtable 就能反查实例**：在可写内存里搜 vtable 这个 4 字节值。
⚠️ 实测有个坑：**代码页里大量存在 4 字节巧合**（例如 `04 9C D0 00` 正好是
`add al,0x9c` + `rol byte [eax],1`），所以"代码页命中"**不能直接当成构造函数**，
必须回镜像反汇编核验。真正能确认的是 vtable 本身（它由 `mov [esi], <vtable>` 写出）。

## 7.5 ★★ 拿到了**解包后的完整镜像**，静态反汇编已通

`--dump-image` 会在扫描时把主模块整段 + 所有匿名 `r-x` 段落盘到 `server/img_dump/`：

```
main_GundamOnline_CHINA.exe   15,654,912 B   ← 完整镜像，基址 0x400000
anon_*                        共 128 段 / 114.9 MB
```

**镜像里的代码是解密后的真实 x86**（壳把自己解包在内存里）。实测例子：

```asm
; CWorldSelectWindow@IF 的析构（vtable 0xd0b3fc 的 slot 0）
0x6e7510  push esi
0x6e7511  mov  esi, ecx                    ; this = ecx（thiscall）
0x6e7513  mov  dword [esi], 0xd0b3fc       ; 主 vtable
0x6e7519  mov  dword [esi+0x114], 0xd0b3e8 ; 次 vtable（多继承）
0x6e7523  mov  dword [esi+0x154], 0xd0b3d0 ; 再一个 vtable
0x6e752d  call 0x6fd240                    ; 基类析构
0x6e7532  test byte [esp+8], 1             ; 是否 scalar delete
0x6e7537  je   0x6e7542
0x6e7539  push esi / call 0xc11ccd         ; operator delete
0x6e7542  mov  eax, esi / pop esi / ret 4
```

→ **对象布局直接读出来了**：vtable 在 +0、+0x114、+0x154，对象 ≥ 0x158 字节。
这就是"从汇编反推运行中字段"的标准做法，而且是**离线**的，不用一直挂着客户端。

配套工具：`tools/dis_img.py`

```
python tools/dis_img.py --va 0x9cc590 --prologue   # 从函数头反汇编
python tools/dis_img.py --va 0x9cc590 --callers    # 谁引用了这个地址
python tools/dis_img.py --str "authsv"             # 镜像里搜字符串
```

（`--str authsv` 在主镜像里 0 命中 → 该字符串位于运行时才解密的区域，
  或者在被 Themida 单独映射的段里；需要时再针对性 dump。）

## 8. 下一步（按性价比）

1. **离线读 `CWorldMapTable` 的构造与填充**：`tools/dis_img.py --va <它的 ctor>`，
   直接看它从哪个全局/文件填表、`count` 在哪个偏移。
   **这是解决"战区列表空"的最短路径**（不用再盲试网络）。
2. **离线读 `CGameStateStepUpdateWorldSelect`**：看它凭什么判定"列表为空"。
3. **`CamelliaCrypter` 的 key**：vtable 已知思路同上，找它的 ctor/init，
   看密钥是常量还是从握手包派生 —— 这决定 16 字节登录包能否直接解。
4. **镜像里搜协议字符串**（`authsv` 在镜像里 0 命中，说明在运行时才解密的段，
   需要按 `--dump-image` 多 dump 几段，或改为按 `ivce` 的字符串池定位）。
5. 客户端渲染的 UI 文本来自加密资源包 → "请选择战区"这类字符串
   **exe 磁盘里搜不到**（UTF-16/GBK 都 0 命中），只能在运行时堆里抓
   （实测已在 `0xeda76fc` / `0x2797a5e4` 找到 `选择战区`）。

