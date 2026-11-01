# 里程碑：登录包抓到了 + 战区列表确认由 HTTP 控制

> 2026-10-17 12:50–12:53，配合用户手动点击完成。

---

## 1. 两个 16 字节登录包（原始 hex）

```
12:50:59  4f fa 6e 6b df dd b8 ed 77 4a 04 43 85 f4 aa 0c
12:52:36  b3 bc bd ec 6e 23 55 74 c8 18 aa 4c fa 31 4b 05
```

- 同一账号 `123 / 123`，**两次密文完全不同** ⇒ 每次都有随机量（随机 IV / 时间戳 / nonce 参与）。
- 长度**恒定 16 字节** ⇒ 单块加密（AES/Camellia 一块）或 16 字节哈希。
- 客户端发完 **等 15 秒** 无响应 → 主动 close（`12:50:59 → 12:51:14`，正好 15s，
  与历史上观察到的 17s 一致，差值是 TCP 收尾）。
- 落盘：`server/world_sniff.log`。

**为什么这次能抓到（之前一直抓不到）：**
`--redirect-connect` 依赖 `ws2_32` 的 hook，而 `ws2_32` 的 hook **只有 `--hook-ws2` 才装**。
之前所有轮次都没开这个开关 ⇒ 重定向是空转。这次索性不用重定向 ——
把假 `authsv.csv` 里的 IP 直接写成 `127.0.0.1`，客户端自己就连过来了。

---

## 2. 战区列表 = HTTP 返回的 `authsv.csv`（已用对照实验坐实）

假 HTTP 服务**必须监听 80 端口**（hosts 把 `ms.patch1.9you.com → 127.0.0.1`，
客户端连的是 80，不是 8080）。`server/fake_http.log` 实录：

```
12:50:00 REQ GET /ClientCheck/config.xml?t=202610171250   [Host: ms.patch1.9you.com]  -> 404
12:50:00 REQ GET /wmode/wmode.txt?t=202610171250          [Host: ms.patch1.9you.com]  -> 404
12:50:01 REQ GET /remote/config.txt?t=202610171250        [Host: ms.patch1.9you.com]  -> 404
12:50:20 REQ GET /launcher/authsv.csv?t=6038484           [Host: ms.patch1.9you.com]  -> 200 (199B)
```

**四个端点，全部已知。** 前三个 404 客户端也能继续，说明非致命。

**对照实验结果（决定性）：**

| 我们提供的 authsv.csv | 下拉列表 | 「当前战区」显示 |
|---|---|---|
| 不给（用资源包默认） | 2 项：第一战区（双线）、第二战区（南方电信） | 技术测试区 |
| 1 行 `1,本地测试区,127.0.0.1,30000,1` | **只剩 1 项** | **本地测试区** |

⇒ `authsv.csv` 的**行数**直接决定列表项数，**组名**直接决定显示名。
之前"劫持后反而变空"的病根就是**列数不对**（4 列/10 列猜错）。

⚠️ 遗留疑点：下拉项的标题固定显示「第一战区（双线）」，而「当前战区」显示 CSV 里的组名。
说明**列表项标题另有一套字符串来源**（可能是按图片ID/序号取的固定文案），
要改显示名还得再定位一下（优先级低，不影响选服）。

---

## 3. 现在的完整链路（可复现）

```
1) hosts: 127.0.0.1 ms.patch1.9you.com / ms.9you.com
2) python server/fake_http.py --port 80          # 静态根 server/fake_root/
3) server/fake_root/launcher/authsv.csv 写：
     1,本地测试区,127.0.0.1,30000,1
4) python server/world_sniff.py --port 30000     # 接住登录包（日志 world_sniff.log）
5) python tools/run_hooked.py --no-elevate --hook-ws2 \
     --fake openScm,createService,startService,queryStatus,controlService,openDevice,deviceIo,shell \
     --seconds 600 --retry 6
6) 手动：点「选择战区」→ 确认 → 点「登录」
```

`--http-to` **不再需要**（hosts + 80 端口已经够了，而且更可靠）。

---

## 4. 下一步：定位加密函数

16 字节包既已稳定可得，剩下就是"怎么造一个假的回复/验证它"。
两条路，优先走第一条：

1. **从发送点回溯**（成本最低）
   `ws2_32!send` 的调用栈可以直接给出加密函数的返回地址。
   已在 `xgg_hook.js` 里给 `send` / `WSASend` 加了 `bt`（长度 ≤64 字节时才记，避免刷屏）。
   拿到地址后：
   - 用 `tools/dis_img.py --va <addr> --prologue` 看函数长什么样；
   - 找它引用的 key 常量（`Crypto`/`CamelliaCrypter` 在 RTTI 表里是有的）；
   - 再看它是不是 `Crypto::Encrypt(明文, len)` 这种两参数接口。
2. **在 `CWorldMapTable` 那套思路基础上找会话对象**
   （登录成功后才会建，暂时够不着）。

拿到明文之后要回答的问题：
- 16 字节里哪些是账号、哪些是密码摘要、随机量在哪几个字节；
- 是不是"固定 key + 明文内嵌 nonce"（如果是，服务端**不需要知道随机数**也能解）；
- 服务端回包是不是同一套算法（大概率是，且带自己的 nonce）。

---

## 5. 仍未解决

- 下拉项标题「第一战区（双线）」的来源（另一套字符串）。
- 客户端连上后**期待服务端先说什么**（它只是干等 15 秒，没有任何重试包）。
  → 也就是说：只要我们回一个"看起来对"的包，就能把它推进到下一个状态，
  这是**最容易验证的方向**（可以先用随机/全零 16 字节试，看客户端反应）。
- 容器格式（`settings/0000.dat`）仍未破。
