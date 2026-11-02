# 当前实验机体的数据关联

整理日期：2026-11-02。机器可读快照是 [CURRENT_UNIT_ASSOCIATION.json](CURRENT_UNIT_ASSOCIATION.json)。本文只解释怎么沿 ID 往下查，数值以 JSON 为准。

这是 `--hangar-experiment gm` 的吉姆关联实验，不是原版机型库里的一行。`uniqid`、`msma_id`、`model_id`、武器 `item_id`、Wiki `revision_id` 是五层不同身份。

## 怎么串起来

```text
持有实例 uniqid 777000000001
  └─ msma_id 777001
       ├─ msma_settings.col1 = model_id 101010101
       │    ├─ msma_model.col0
       │    └─ chara/01/01/0101/model/MSM_0101_0101_01.dxg
       ├─ col38 = 777001 → msma_weapon_set → 可装备 item_id
       ├─ col44 = 777104 → 机型盾牌支持
       ├─ col52 = 1450 → 搭载量直接值
       └─ col56..73 模板名 GM_REF_* → msma_battle_detail
实例.weapons / equipped_weapons
  └─ item.csv → weapon_settings
       ├─ col2 资源号 → 图标 d%08d.dds 与 EZ_*.vra
       ├─ 性能列 → weapon_battle_detail 模板 GM_WEAPON_{item_id}_{KIND}
       ├─ col64 → develop/buildup_weapon.csv 决定面板显示哪些项
       └─ col68 → item/bullet.csv（仅有弹数的武器）
```

实例记录本身不携带 `model_id`。客户端用 `msma_id` 查机型定义，再从定义第 1 列复制模型号。因此改模型必须改定义行，只改 299B 记录不会换模。

模型号 `101010101` 来自路径 `01/01/0101` 变体 `01`：前两段合成 `101`，再 `101 * 1000000 + 0101 * 100 + 01`。不能把目录数字直接连成另一个 ID。贴图绑定在 `model_matches.json` 里按网格人工确认，默认色贴图是 `MST_0101_0101_01C.dds`。

## 三份武器名单不要并成一份

| 名单 | 内容 | 作用 |
|---|---|---|
| 可装备集合 | 777101–777103 与 777105–777108，外加盾牌定义 777104 | 下载表。客户端知道这些物品存在 |
| 持有列表 | 种子只有 777101、777102、777103 | `A832.weapons`。解锁就是写入这里 |
| 当前装备 | 种子三个槽分别是上述三把 | `equipped_weapons`，必须是持有列表的子集 |

盾牌 `777104` 写在实例偏移 114，同时写在机型 col44。它不占三个 MAIN 槽。耐久 990 在 `weapon_battle_detail` 的 `GM_SHIELD_HP`，不写进偏移 114。

`777105`–`777108` 只在定义表里。要持有须走解锁，不能靠改武器组冒充已拥有。

## 种子实例上已经有、但还没进入业务的字段

`blueprint_grade=silver` 只存在 JSON 种子，没有编码进 299B。`buildup_count`、7 个 `up_params`、7 个 `develop_params` 会编码，种子全是 0。这 7 槽还不能对应界面上的六项机体强化。

编队槽 `[0, 0]` 表示地面、宇宙各占第一槽。单机 COST 模板是 200；编队容量实验值 1200 在机师详情，不在机体记录。

性能换算（Wiki 面板 → 表内整数）记在 JSON 的 `panel_conversion`。例如威力 1000 入库为 POWER 100，速度 1004 入库为 MOVE `1004 * 1680 / 2000`。WARP_TIME 的 10 是诊断占位，不能当成 Wiki 紧急归投 682。

## 和基地行分开

固定基地是另一套身份：`msma_id=777201`，`model_id=601030301`。不要用吉姆的模型号或实例号去填基地。
