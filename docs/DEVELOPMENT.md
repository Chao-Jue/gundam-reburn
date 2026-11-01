# 开发手册

## 当前架构

原版客户端 → 本地HTTP清单与资源入口(fake_http.py) → 加密TCP认证/选区/休息室(fake_auth.py) → 机库(hangar.py) → 预约(xwar_entry.py) → 准备房间与初始场景(local_battle.py)。目前同一认证监听端口按F24B正文路由不同会话；不要将历史30100或早期cn_server网关方案当作当前唯一入口。

fake_auth.py负责帧包装、Camellia演进、表响应、角色保存、会话分发；文件顶部注释保留早期探索历史，应结合当前handler和测试阅读。hangar.py定义资产存储与wire序列化；hangar_experiment.py按开关生成GM参数、武器和任务覆盖；battlefield_bases.py生成本地固定基地行；xwar_entry.py管理正式战预约、凭据和取消；local_battle.py处理房间认证、成员、准备、倒计时、初始场景、点位与出击列表。

fake_http.py提供静态fake_root；cn_server.py/cn_port80.py为早期网关/补丁研究入口。start_game.py为早期启动脚本。tools/run_hooked.py与pilot_hook.js负责注入和本地重定向；ods_listen.py读取调试输出，probe_*用于状态观测；emulate_wire_reader.py执行离线机器码。tools/model_matcher/app.py提供本地HTTP与标注API，dxg.py解析几何，web/app.js负责WebGL与交互。crawl_gundam_wiki.py、repair_wiki_data.py、weapon_icon_match.py负责参考资料。逐文件用途和导入见CODE_INDEX。

## 协议约束

以当前中国客户端读取器为准，refs下其他项目仅作参考。机师记录157B，机库机体wire为299B、武器30B；战斗A5DA无参考版额外is_rankerbattle字段，成员BDD6为179B，退出14C5正文为空。所有长度、字段顺序、NUL字符串、字节序与计数数组须由当前测试/读取器确认。帧能解密、游标消费完全、UI回调安全、资源加载成功、真实业务完成是不同验证层。

OTP绑定user/world/pilot/room，有有效期且禁止重复占用。取消与断开清理房间，重复预约须幂等。新逻辑必须保持普通模式隔离；测试数据使用临时存档。没有数据库或迁移系统，存储是JSON与内存。

## 建议开发顺序

1. 从最新固定基地记录、当前测试和实际handler建立基线，复现用户看到的首个错误。
2. 先验证基地模型601030301在运行客户端中加载、布局与角色关联；记录图案、坐标、点选的真实结果。
3. 在证据完整后接实体生成/出击生命周期，再做运动、武器、命中、伤害和结束结算；不要用预览参数代表战斗能力。
4. 每个独立改动走规范PR，更新数据映射与验证报告。

Bug修复先写可重现测试并确认预期失败，再改实现，同测试复跑通过。功能开发优先最小可验证闭环。禁止覆盖人工匹配、凭目录相似度授予ID，或用无依据字段凑包。

## 验证命令

```powershell
python -m compileall -q server tools exports/gundam-model-matcher start_game.py
python -m unittest discover -s server -p "test_*.py" -v
python -m unittest discover -s tools/model_matcher -p test_matcher.py -v
python -m unittest discover -s tools -p "test_*native*.py" -v
python tools/smoke_local_battle.py
```

原生测试需要Unicorn及私有映像，模型测试需要解码DXG，不具备输入时记录blocked。额外工具测试按改动选择具体文件，不要把全部tools脚本作为可安全执行的测试。浏览器冒烟见tools/model_matcher/smoke_ui.py，需要Playwright和Chrome。生产打包/类型检查目前没有统一配置；Python编译不等于生产部署。当前所有系统环境变更脚本只读审查，不在CI自动运行。

## 历史结论处理

研究笔记为过程记录，保留错误假设及纠正。准备大厅接入笔记中的“尚不发game_begin”等是当时状态；当前local_battle及后续场景/部署记录已继续推进。2026-11-01记录优先解释固定基地问题。相互冲突时明确引用日期、客户端版本、函数地址和运行证据；不能只取日期最旧或最乐观的结论。
