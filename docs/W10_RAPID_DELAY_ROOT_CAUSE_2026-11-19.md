# W10 射速强化终章：连射速度"1579 满格显示 + 强化MAX 恒亮"根因定案与服务端修复

日期：2026-11-19
范围：服务端（hangar_experiment.py / trainer_weapons.py / catalog_units.py 链路）+ 客户端 RE 定位（辅助证明）
性质：根因研究 + 服务端代码修复 + 原版客户端真机验证

---

## 1. 问题与触发

W10 板块目标：给 GM 目录机体（777001 吉姆系）的头部火神炮武器族（778001/778002/778003）增加"连射速度"强化项。

前期已完成并验证的服务端侧工作：

- 位表 `buildup_weapon.csv` col3=1 限定 778001/778002/778003（客户端强化面板出现"連射速度"栏）；
- `mechanic_weapon.csv` 新增 param2 档（BUILDUP_FAIL/SUCCESS/GREATEST 三段，rate/cost 交替编码）；
- 服务端强化标定率 `PARAMETERS{0:威力35, 1:集弹20, 3:装填35, 4:锁定67, 5:射程35, 8:运行34, 9:效果范围75}`、pTarget n→pair n 直取绑定（六读数实证）、param2=（连射速度, 2, .008186）、容量 = 目录值 × 0.008186 × 100（1466 → 1200）；
- 强化闭环 0x5FAB → 0x0876（结果）→ 0xD563（券库存下发）全部打通。

残留症状：客户端强化面板里"連射速度"行恒为**橙色强化MAX**，无法选中；武器详情面板连射速度恒显示 **1579**（目录/wiki 真值 1466）。

## 2. 根因链（终判）

```
GM 扩展武器生成链（hangar_experiment.py extras 循环）从不生成 rapid_delay_seconds
  └─ performance_templates() 仅在 weapon['rapid_delay_seconds'] 键存在时才输出 RAPIDDELAY 行（CSV84）
       └─ battle_detail 缺 RAPIDDELAY → 客户端 0x55E1C0 把 CSV84 RAPIDDELAY 绑到武器对象 +0x764，缺失即 0
            ├─ 面板显示：f(0) = 满格 1579          ← "1579"的来历
            └─ is_max(0x774BE0) p2 分支：base=0 → (base − 增量) ≤ 0 恒真 → 强化MAX 恒亮 ← "MAX"的来历
```

**"1579"与"强化MAX"同源（字段缺失），不是客户端 int 截断**（此前的"int 直读"推断作废）。

自洽验证（已观察事实全部吻合）：

- 走通用源装备投影的武器（`catalog_units.py:238` 有 delay 逻辑）与训练机机枪（`trainer_weapons.py:43` 显式生成）显示正常；
- 只有 GM 扩展链的 778 族缺字段；
- 目录/存档里不存在 1579 这个数值——它是客户端对 delay=0 的显示（满格）。

## 3. 反演公式与数值表

服务端唯一需要下发的量是每武器一条 float：

```
rapid_delay_seconds = round(2.0 − 连射速度 × 19 / 15000, 4)
```

| 连射速度（面板/wiki） | delay（秒） | 说明 |
|---|---|---|
| 1466 | 0.1431 | 吉姆系头部火神炮（778001/778002/778003） |
| 1447 | 0.1671 | 100mm 机枪族（778004/778005/778006） |
| ≤0 的计算结果 | 字段省略 | 客户端按 0 处理 → 面板满格 + MAX 恒亮 |

公式来源：与 `trainer_weapons.py:43` / `catalog_units.py:238` 同款已验证反演（训练机机枪实测 delay 直接驱动实际射击间隔，1466 ↔ 0.1431s ≈ 7 发/秒）。

## 4. 修复（服务端，hangar_experiment.py GM 扩展循环）

在 extras 循环 `weapon['attributes']` 赋值之后追加（与上述两处同款反演）：

```diff
         weapon['attributes'] = json.loads(attributes)
         if not isinstance(weapon['attributes'], dict):
             raise ValueError(f"目录吉姆武器属性无效：{weapon['name']}")
+        # GM 扩展武器此前从不生成 rapid_delay_seconds，battle_detail 缺 RAPIDDELAY
+        # 行 → 客户端 +0x764 读 0 → 面板显示满格 1579 且 is_max base=0 恒 MAX。
+        if '连射速度' in weapon['attributes']:
+            rapid_delay = round(
+                2.0 - float(weapon['attributes']['连射速度']) * 19 / 15000, 4)
+            if rapid_delay > 0:
+                weapon['rapid_delay_seconds'] = rapid_delay
         try:
```

生成链验证：778001/778002/778003 → 0.1431，778004/778005 → 0.1671；`performance_templates()` 输出 `('RAPIDDELAY', 84, [0.1431])`。

## 5. 真机验证（原版客户端，无任何客户端补丁）

远端账号 111（pilot 2）使用金吉姆（777001 gold，图纸开发产出）：

- 重启服务端后重新登录：武器详情面板连射速度 **1579 → 1466**；
- 强化面板"連射速度"行**解除强化MAX**，可选中、可选券、可执行；
- 强化请求三连发成功：`0x5FAB`（载荷22）→ `0x0876`（结果应答 bodylen=36）+ `0xD563`（券库存下发 bodylen=10），服务端日志 11:26:41 / 11:26:50 / 11:26:56 三次完整闭环；
- **大成功一次 +3**、面板"最大提升 +5"逻辑全正确（用户实测确认）。

配套数据链（同期定案，一并归档）：

- 强化池 `buildup_pools["2"]`（‰）与容量换算 `values[2] = pool × 1000 // 1200`（1200=1466×0.008186×100）精确闭合；
- 大成功档增益 384‰（=400×0.96，tier2 区间 340–400）、成功档 213‰（tier1 区间 160–220）；
- 官方锚点复现：威力 5500 → +193、手雷效果范围 5000 → +376（率 75 官方锚点）、锁定 1000 顶格 MAX 为官方规则；
- 强化公式：`max_rise = trunc(stat × sr × slot × 1e-3 + 0.4) + 1`。

## 6. W10 全链备忘（供作者采纳时参考）

1. **位表** `buildup_weapon.csv` col3=1 限定 778001/778002/778003（col11..20 为槽消耗点数 u32×10，与显示无关）；
2. **档位表** `mechanic_weapon.csv` param2 档（cost/rate 交替 ×10 编码）；
3. **下发** `rapid_delay_seconds` → RAPIDDELAY CSV84 → 客户端 +0x764（本 PR 核心修复）；
4. **is_max 判定**（客户端 RE，0x774BE0）：第一层 `cmp word [esi+param*2+0x6e], 0x3E8`（values≥1000 → MAX，锁定顶格 1000 属官方规则）；第二层 (base−增量) ≤ 0.0 → MAX——服务端把 base（RAPIDDELAY）给对即自然解除；
5. **客户端补丁**（仅本机验证用，上游不需要）：跳转表 0x774C9C param2→恒 false、阈值 0x774BEC 1000→32767、VMP 陷阱过滤器 0x403876 状态强制 0（防第 4 陷阱自杀）。客户端带 VMProtect，.text 自校验触发即故意 AV（0x40388C），运行时补丁需同步中和过滤器——服务端数据路线可完全绕开这一层。

## 7. 兼容性与风险

- 修复只给此前缺字段的 GM 扩展武器**新增**下发量，不改任何既有数值；已正常投影的武器（训练机机枪、通用装备投影）不受影响；
- delay ≤ 0 分支维持"省略字段"语义（与 catalog_units.py 一致）；
- 回滚：删除追加的 6 行即回原状。

## 8. 附：agent-result

见 PR 评论中的 agent-result JSON（operation=pr）与 `docs/agent-results/2026-11-19-rapid-delay-fix-verified.json`。
