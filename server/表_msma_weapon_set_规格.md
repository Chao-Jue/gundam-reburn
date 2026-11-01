# `msma/msma_weapon_set.csv` 规格（完整反编译结论）

> 来源：Ghidra 反编译 `server/decomp_msma_full.txt`，与 `tools/dis_img.py` 汇编交叉核对。
> 表类 `CMSMAWeaponSetTable`，分派序号 **1**，每行结构 **0x58 = 88 字节**。

## 一、调用链

```
0x544922  case 1  →  vtable[0] = 0x9DC930  CMSMAWeaponSetTable::Load
0x9DC930  Load    →  clear() = 0x9DC860
                  →  0xB08960(text, 跳过前 2 行, 行回调 0x9DC7F0, this, …, 3) == 0
0x9DC7F0  行回调  →  第 0 列首字符 == '#' 就跳过；否则 → 0x551BC0(row)
0x551BC0  行解析  →  按写死的列号取字段 → 收进表（vector + map 索引）
0x5517C0  之后    →  对每个桶做 std::sort（比较器 0x5506E0，只比 [row+0x18]）
```

**重要**：整条链**没有任何范围校验**。`0xB081E0(row, 越界列)` 返回 0，
`0xB082E0(row, 越界列)` 返回空串，两个枚举函数查不到就返回兜底值
（武器组→0，武器种类→27）。也就是说**任意一行都不会被“内容校验”拒掉**。

## 二、列定义（0 基，共 ≥29 列）

| 列 | 类型 | 语义 | 合法取值 |
|---|---|---|---|
| 0 | int | 主键 | 任意，建议 1..N 唯一 |
| 1 | - | 不读 | 留空或 0 |
| 2 | int | 未定 | 任意 |
| 3 | - | 不读 | 留空 |
| **4** | **str** | **武器组** | `MAIN`→0 / `EX`→1 / `SUB`→2 / `0`→9999 / 其它→0 |
| **5** | **str** | **武器种类** | 见下表，未匹配→27 |
| 6 | int | 布尔 | 0/1 |
| 7 | int | 未定 | 任意 |
| 8,10,11 | int | 第 1 组（3 个） | 任意 |
| 9 | - | 不读 | 留空 |
| 12,14,15 | int | 第 2 组 | 任意 |
| 13 | - | 不读 | 留空 |
| 16,18,19 | int | 第 3 组 | 任意 |
| 17 | - | 不读 | 留空 |
| 20,21 | - | 不读 | 留空 |
| 22 | int | 未定（>0 时参与下面的 9999 判断） | 任意 |
| 23 | - | 不读 | 留空 |
| 24 | int | 未定 | 任意 |
| 25 | int | 未定 | 任意 |
| 26 | int | 未定 | 任意 |
| 27 | int | 未定 | 任意 |
| **28** | **str** | **地区** | `ALL` / `CHINA` / `JAPAN`。**`JAPAN` 行被丢弃**，其它任意值都会收 |

> 第 22/24/25/26 列有个特殊分支：
> `if (col22 > 0 && col24 < 1 && col25 < 1 && col26 < 1) col26 = 9999;`
> 看起来是“持续时间/次数”类字段的兜底值。

## 三、第 5 列（武器种类）完整枚举

`FUN_00550AE0` 查表 `0xCBC118`，返回下标值：

| 字符串 | 值 | 字符串 | 值 |
|---|---|---|---|
| MACHINEGUN | 0 | BEAM_SNIPE | 11 |
| MACHINEGUN2 | 1 | TRENCH_MORTAR | 12 |
| MACHINEGUN3 | 2 | REPAIR | 13 |
| SUBMACHINEGUN | 3 | SHIELD | 14 |
| SHOTGUN | 4 | BAZOOKA | 15 |
| BEAM_RIFLE | 5 | MISSILE | 16 |
| BEAM_SPRAYGUN | 6 | HOWITZER | 17 |
| WRESTLE | 7 | LANDMINE | 18 |
| CHARGE_RIFLE | 8 | HAND_THROW | 19 |
| CHARGE_BAZOOKA | 9 | HAND_THROW2 | 20 |
| SNIPER_RIFLE | 10 | RADARPOD | 21 |
| REPAIRPOD | 22 | CAMERAGUN | 23 |
| BULLET_PACK | 24 | AAGPOD | 25 |
| REPAIR_PACK | 26 | `-`（空/未匹配） | 27 |

另有一张 `0xCBC300` 的表（`FUN_00551F00` 使用，VERSUS/WIN/KILL/SCORE_*/RESULT_*/…，
共 46 项，值 1..44、500、999），**本表不用**，但别的表可能会用。

## 四、行的收留规则

```c
if (地区 == "JAPAN") { 丢弃; return; }        // 唯一的内容过滤
find(map, 主键);
if (没找到) { vector.push_back(新行); map.insert; 建两个索引; }
else        { 更新已有行; }
```

**结论：只要一行是合法 CSV，它一定会被收进表。**
所以“表是空的”只能解释为**行解析根本没执行**（`Load` 没被调用，或调用时抛了异常）。

## 五、最小合法样例行（29 列）

```
0,0,0,0,MAIN,MACHINEGUN,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,CHINA
```

（列 0 = 主键；列 4 = MAIN；列 5 = MACHINEGUN；列 28 = CHINA；其余 0）

生成器：`server/gen_msma_weapon_set.py --rows N --region CHINA`
