# 5.0.0.33 机库相机注视点修复（看板 X4）

修的是**机库「武器改造 / 强化」界面**的相机，不是战斗镜头。
上游已有的 `docs/CAMERA_HEIGHT_2026-11-05.md` 改的是 `msma_model.csv` 列 1（战斗取景 160→220），
与本补丁改的 `data/script/0000.dat` 里的相机脚本完全无关，两者互不干扰。

---

## 现象与根因

机库改造/强化界面的相机脚本用 `chara.getHeight()` 现算注视点：

```nut
local height = chara.getHeight();
height *= 0.55;          // 本环境该函数返回约 0，0 乘任何数还是 0
target.y += height;      // 注视点停在脚底 ⇒ 镜头又陡又矮
```

视角正常的「装备组」脚本 `L03_CharaSelect_Camera_01.nut` 用的是绝对注视点
`Vec(650, 83, -92)`，固定在胸部高度。把乘算换成绝对值
（`height = 63.30;` ⇒ `target.y ≈ 19.7 + 63.3 = 83`）即可对齐。
**这个 63.3 是取景对齐值，不是官方平衡数据，也不是厘米/米。** 可用 `--height 75.3` 微调。

---

## 给使用者：三步

1. 把 **`修复机库相机.cmd`** 复制到**游戏根目录**——和 `GundamOnline_CHINA.exe` 同一个文件夹。
2. 双击运行（会打印 7 处校验与写入结果，最后 `[4/4] DONE`）。
3. **完整重启客户端**。脚本在启动时读入内存，只重登无效。

> ★ **补丁必须与 exe 同级。** cmd 用 `%~dp0` 自定位；放错目录会中文提示并退出，
> **不写任何字节**。不要新建一层子目录再放进去。
>
> ★ **版本绑定**：cmd 内嵌的 7 条「绝对偏移 + 原密文 + 新密文」硬绑定于
> **MSGO 5.0.0.33 国服客户端、且 `0000.dat` 未被其它补丁改动**的 build。
> 版本不同时，写入前的原密文校验会失败并**整体中止**（`[FAIL] mismatch … Nothing written`），
> 不会写坏文件。换版本请用下面两个 Python 脚本重新生成。
>
> ★ **回滚**：首次运行会生成 `data/script/0000.dat.camera.bak`（只在不存在时创建，
> 保留最初原始档）。把它复制回 `0000.dat` 并重启客户端即可还原。

`修复机库相机.cmd` **零依赖**：不需要 Python、不需要 fpmf.py、不需要密钥表、不联网。

---

## 实现路径

### 1. 为什么必须「等长」

FPMF 归档没有空洞 / 重定位机制：`data/script/0000.dat` 里每条记录的
`offset` / `size` / `resource_key` 都写死在 `data/script.hed` 里，
改任何一条记录的**字节长度**都会让后续所有记录整体错位，客户端读到乱码甚至启动失败。

| 原串 | 字符数 | UTF-16LE 字节数 | 替换 | 字符数 | 字节数 |
|---|---|---|---|---|---|
| `height *= 0.5;` | 14 | 28 | `height = 63.3;` | 14 | 28 |
| `height *= 0.55;` | 15 | 30 | `height = 63.30;` | 15 | 30 |

`.nut` 是 **UTF-16LE 带 BOM**，按「字符数」判断会算错，脚本一律按**字节**校验长度。
`resource_key` 只依赖明文首字节与总长度，两者都没变 ⇒ **不需要改 script.hed**，
脚本里仍显式调用 `calculate_resource_key()` 复核一次。

### 2. 改动范围（7 个脚本，共 41 字节）

```
L03_WeaponWindow_Camera_01.nut      L03_HangarMenu_04.nut
L03_WeaponWindow_Camera_03.nut      Menu_Camera_Hangar_OverCustom_03.nut
L03_HangarMenu_Camera_01.nut        Menu_Camera_Hangar_OverHaul_03.nut
                                    Menu_Camera_Hangar_BuildupMsma_03.nut
```

`L03_CharaSelect_Camera_01.nut`（装备组）本来就是对的，**不动**。

### 3. 为什么补丁只有 5.6KB，不用传 33MB 的 `0000.dat`

只有 41 个字节变了，所以远端只需要 7 条
`绝对偏移 | 字节数 | 原密文(hex) | 新密文(hex) | 脚本名`
（见 `camera_patch.json`）。cmd 把这段 payload 以 **纯 ASCII** 内嵌在
`==== PS_PAYLOAD_BEGIN ====` 标记之后，运行时由 PowerShell 读出执行：

- 先备份 `0000.dat.camera.bak`；
- **逐处比对当前字节 == 原密文**，任一不符 → 整体中止、零写入；已等于新密文的跳过（幂等）；
- 全部校验通过后才一次性写入，写完**逐处回读**核对；
- 文件是 **GBK + 全 CRLF**，不用 `-EncodedCommand`（会被部分环境拦），payload 全 ASCII 避开编码坑。

### 4. 开发者链路（换客户端版本 / 调高度时）

```bash
# ① 干跑看计划（不写字节）
python patch_script_camera.py --game "<游戏根目录>" --fpmf-dir "<含 fpmf.py 的目录>"

# ② 备份 + 等长改写 + 逐条双向回读
python patch_script_camera.py --game "<游戏根目录>" --fpmf-dir "<...>" --apply

# ③ 从 ② 的备份与当前 0000.dat 生成单文件补丁
python make_camera_patch_cmd.py --game "<游戏根目录>" --fpmf-dir "<...>" \
    --backup-root "./_msgo_camera_backup" --out-dir "./camera-patch-dist"

# 其它：--height 75.3 调高度；--restore 从最近备份还原
```

`patch_script_camera.py` 做链路 `script.hed → 记录 → 0000.dat` 的明文改写；
`make_camera_patch_cmd.py` 把「改前/改后密文」按 DAT 绝对偏移抽成 7 条，
渲染出 cmd 与 `camera_patch.json`。两者都用 `--game` / `--fpmf-dir` 参数化，
**不含任何本机绝对路径**。

**依赖分层**：cmd 零依赖；两个 Python 脚本需要 `fpmf.py`（接口：
`load_keys` / `parse_hed` / `read_resource` / `write_resource_inplace` /
`calculate_resource_key`），密钥表从 `GundamOnline_CHINA.exe` 按签名提取。
本仓库的 `tools/fpmf_info.py` 只读明文头，不含读写能力；
本 PR **未附带 fpmf.py**（避免引入第三方移植代码），用 `--fpmf-dir` 指向自备副本即可。
已合并/开放的 PR #1 / #5 中的同类工具用的是同一套接口约定。

---

## 验收证据（本机 11-05 实机）

| 层 | 结果 |
|---|---|
| 静态 | `py_compile` 通过；7 条 `entries` 的偏移/密文与本机已验证版逐字段一致 |
| 生成 | 用真实备份重新跑 `make_camera_patch_cmd.py`，产出 `修复机库相机.cmd` 与本仓库内文件 **sha256 完全一致（5591 B）**，GBK + 全 CRLF、payload 全 ASCII |
| 干跑 | 对真实客户端 `script.hed`（9351 条记录）7 个目标全部命中；已打补丁的机器全部跳过，不再重复写 |
| 写入 | 7/7 处 `write_resource_inplace` 后双向回读一致，长度不变，`resource_key` 不变 |
| 运行时 | 完整重启后，武器改造 / 强化界面注视点抬到胸部，镜头不再压脚底 |

## 兼容性 / 风险 / 回滚

- **只改客户端脚本容器**，与服务端协议、表下发、机库名册无关；不需要重启服务端。
- 与 PR #5 的客户端接入补丁改的是**两个不同归档**：本补丁 `script.hed + script/0000.dat`，
  PR #5 是 `settings.hed + settings/0000.dat`（authsv IP）。两者可同时安装，互不覆盖。
- 上游 `.gitignore` 忽略客户端整包与 `*.zip`/`*.bin`/`*.bak`，因此本 PR **不提交 33MB 的
  `0000.dat`、不提交密钥表、不提交备份**，只交可复现脚本 + 5.6KB 单文件补丁 + 7 条数据。
- 最大风险是**版本错配**：已由「原密文逐处校验 + 整体中止 + 零写入 + 回读」兜住，
  失败时不会破坏 `0000.dat`；回滚见上文 `.camera.bak`。
- 已知限制：`.nut` 里 `height *= 0.x;` 的两种写法已覆盖；若后续客户端改用别的表达式，
  需往 `PATTERNS` / `NUM_WIDTH` 里补一条等长规则，否则脚本会安全跳过并提示。
