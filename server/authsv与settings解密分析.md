# 解密资源包带来的关键突破：`authsv.csv` 真身 + `settings/` 全表

> 来源：`D:\project\gundam-reburn\GundamOnline_CHINA_已解密\`（用户下载的 27GB 解密包）
> 日期：2026-10-17

---

## 1. `authsv.csv` —— 战区列表的真格式（一直在找的东西）

`decrypted/settings/authsv.csv`（**236 字节，UTF-8 无 BOM，CRLF**）：

```
#認証サーバーリスト,
#グループID,グループ名(UI表示用),認証サーバーIPアドレス,認証サーバーポート番号,画像ID
#CBTテストサーバー,
1,技术测试区,60.206.12.127,30000,1
2,第二,,,2
```

**格式定了：5 列，`#` 开头是注释行，列序 =**
`组ID, 组名(UI显示), 认证服务器 IP, 端口, 图片ID`

对照一下我们之前瞎猜的 4 列 / 10 列 —— **全都错**，难怪服务端回 200 也填不出列表。

### 五个变体（同一套格式，不同环境）

| 文件 | 内容要点 |
|---|---|
| `authsv.csv` | 国服线上用：`技术测试区=60.206.12.127:30000`、`第二=<空IP>` |
| `authsv_stg.csv` | 测试环境：活动区 `60.206.12.149`、技术测试区 `60.206.12.127`、CBT测试区 `125.211.208.242`、日本 staging `113.43.127.56:30090`、内网 `192.168.6.223:30050` |
| `authsv_wegame.csv` | WeGame 渠道：`60.206.15.117` 的 **30000/30001/30002/30003 四个端口**（同组多端点） |
| `authsv_netcafe.csv` | 网吧活动区 `60.206.12.149:30000` |
| `authsv_develop.csv` | 开发环境 37 条（`113.43.127.56:30090` 等） |

**关键推论：**
1. **第 2 行 `2,第二,,,2` 的 IP 是空的** → 这就是「两个选择，选完之后都是技术测试」的来源：
   组 2 没有 IP，客户端退回默认组。
2. **一个组可以有多个端点**（WeGame 那 4 个端口）→ 协议里"组"和"端点"是分开的，
   写服务端时可以先只实现单端点。
3. 端口默认 **30000**，开发/日本环境用 **30090**，内网 yoda 用 **30050**。

`sv_add.txt` / `sv_add_stg.txt` 是更早的"单服务器地址"方案（`125.211.208.155,30000`），
已被 `authsv.csv` 取代，可作为**协议演进**的旁证。

---

## 2. `download_list.csv` —— 服务端必须下发的数据表清单（写服务端直接用）

这是客户端启动后**从服务端拉取**的数据定义表，共 **77 条**。含义极重：
**这 77 个 CSV 就是服务端的"权威数据面"。**

```
AUTOEXEC,autoexec_sv.cfg
MSMA_WEAPONSET,msma/msma_weapon_set.csv
CHARA_PARAM,msma/msma_settings.csv        ← 机体基础参数
MSMA_BATTLE_DETAIL,msma/msma_battle_detail.csv
WEAPON_BATTLE_DETAIL,item/weapon_battle_detail.csv
WEAPON_SETTING,item/weapon_settings.csv
BULLET,item/bullet.csv                    ← 弹道参数
WRESTLE_PARAM,item/wrestle.csv
BUFF,buff/buff.csv
AI_PARAM,npc/ai_param.csv                 ← AI 参数（做 AI 对战必需）
MISSION_VS/COOP/GROUP/EXTRULE,mission/*.csv
LVUP_*,growth/*.csv
MODULE*,module/*.csv
GACHA / SHOP / REWARD 等,…
```

→ 与用户情报完全吻合：「机体/武器/对战计算全在服务端」。
→ **但这也给了我们一份"服务端要提供什么"的完整契约**，比盲猜协议高效得多。

完整清单见 `server/ref_settings/download_list.csv`。

---

## 3. `str_table.txt` —— 全部 UI 文案（UTF-16LE，257KB）

- 编码 **UTF-16LE**（不是 UTF-8，之前 `grep` 搜不到就是因为这个）。
- 格式：`main_category,sub_category,string_id,string,`
- 关键条目：
  - `60,5,0,战区选择`
  - `60,5,18,当前战区`
  - `60,5,19,请选择当前战区<br>请根据您所在的地区选择相应的战区`
  - `60,5,20,未选择当前战区`
  - `60,29,2,正在取得战区列表`
  - `60,29,3,正在检索战区`
  - `81,1,6,选择战区`

→ 「请选择战区」「当前战区」这些文案**不在 exe 里**（之前搜 exe 零命中），
   是运行时从加密资源包解出来的。这份表可以直接当**运行时字符串→ID 对照表**用。

---

## 4. `error_code.csv` —— 服务端错误码全表（含 9YOU 认证码）

格式：`Code,文本,,内容(游戏内不显示)`

- 认证类：`-8001 … -8199`，映射 `enum YOU9SPEC_STATE`，
  注释直接点名 **「Unified Login Server」**（9you 统一登录服）。
- 例：`-8088 登陆状态超时`、`-8199 认证系统错误`、`-50002 检测到版本错误(C)`、
  `-10004 重置连接状态`（多重登录）。
- ⚠️ 我们之前看到的 **49236 / 49235 / 49234 不在这张表里** —— 那是**驱动/保护层**的
  内部码（XDt 日志水位），跟游戏协议无关，别再混为一谈。

---

## 5. 容器仍然解不开（但现在是"有对照答案"的解不开）

| 项 | 值 |
|---|---|
| `data/settings/0000.dat` | 7,244,395 B，头部高熵 |
| `data/settings.hed` | 5,877 B，`FPMF` + u32 2 + u32 5861 + u32 2 |
| 解密后 `settings/` 69 个文件合计 | 9,809,589 B |

→ 比值 0.74 ⇒ **压缩 + 加密**。
- 已知明文对撞（31 个高区分度串 × utf-8/gbk/shift-jis/utf-16le × 单字节异或 0..255）：
  **只有 1 处巧合命中**（`str_table` 的「战斗」xor 0xb8），不成立。
- `.hed` 周期熵检测：**无任何周期**（整体熵 7.96），说明不是循环异或，是"压缩后加密"。
- 旧结论「xor 0x43 + raw-deflate」**被这次实测否掉**（只解出 81 字节垃圾）。

**结论：容器格式仍未破。** 但已知道 `decrypted/` 就是正确明文，所以现在可以：
1. 拿 `decrypted/` 当"标准答案"做**差分已知明文攻击**（整包 9.8MB 明文对照 7.24MB 密文）；
2. 或者干脆**绕过容器**：hook 引擎的"逻辑文件读取函数"直接返回明文。

---

## 6. 本次运行的实测结果（重要）

用正确格式的假 `authsv.csv`（内容 `1,本地测试区,127.0.0.1,30000,1`）+ hosts 劫持 + `--http-to 127.0.0.1:8080`：

- 假 HTTP 服务**没有收到任何请求**（`server/fake_http.log` 只有 listening 一行）；
- 但登录框的 **「当前战区」显示为 `技术测试区`**（之前一直是 `---`），
  说明**列表来自本地资源包里的 `authsv.csv`，不是来自 HTTP**；
- 也说明 **`---` 那种空状态不是常态**，是某个前置失败时的降级表现。

→ **重要修正**：之前"劫持 authsv.csv 反而列表变空"的实验，问题大概率出在
**CSV 列数/格式不对**（解析失败 ⇒ 清空列表），而不是"客户端不读 HTTP"。
现在格式已知，这条线**值得重做一次**。

---

## 7. 直接可用的结论

1. **16 字节登录包的目标地址已确定**：`60.206.12.127:30000`（组 1）。
2. 只要列表能选中，`--redirect-connect 127.0.0.1:30000` 就能让登录包打到本地，
   `server/world_sniff.py` 直接接住 —— **下一步就是抓这个包**。
3. 服务端要下发的 77 张表已有清单（`download_list.csv`），可从 `decrypted/` 里
   找同名文件当**返回值模板**。
4. UI 文案已全量可得（`str_table.txt`），做服务端回包时的本地化文本有据可依。

---

## 8. 附：本次新增/更新的文件

| 文件 | 说明 |
|---|---|
| `server/ref_settings/` | 从解密包挑出的 7 个关键表（authsv×4、download_list、str_table、world_map） |
| `server/_known_plain.py` | 已知明文对撞脚本（可复用于整包差分） |
| `server/_hed_probe.py` | `.hed` 结构探测（xor + deflate 暴力枚举） |
| `tools/win_shot.py` | 抓指定窗口（PrintWindow / 前台 BitBlt 双路），带 AttachThreadInput 抢前台 |
| `tools/click.py` | SendInput 绝对坐标点击（对 DirectInput 有效） |
| `server/fake_root/launcher/authsv.csv` | **已改成正确 5 列格式** |
