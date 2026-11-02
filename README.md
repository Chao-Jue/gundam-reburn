# Gundam Reburn

面向《机动战士敢达 Online》中国客户端的本地协议研究、服务端原型与资源数据匹配工程。开发快照日期：2026-11-01。

目前包含认证/休息室协议、机师创建和持久化、格纳库、GM关联实验、正式战预约与本地准备房间、初始场景及出击选择协议，以及DXG模型与Wiki数据人工匹配台。尚无完整战斗实体、伤害结算、多人战斗或生产部署能力。固定基地模型渲染、点选和真实出击仍待原版客户端验证。

## 从哪里开始

- [使用手册](docs/USER_GUIDE.md)：安装、启动、匹配、实验与排错。
- [开发手册](docs/DEVELOPMENT.md)：架构、代码作用、协议与开发步骤。
- [选角到大规模战准备房间](docs/HALL_TO_BATTLE_ROOM.md)：协议通路、初始化闸门、任务资源、房间凭据与关键包结构。
- [格纳库与机体系统](docs/HANGAR_AND_UNITS.md)：资产预加载、机型与模型、性能模板、武器盾牌、编队和换装持久化。
- [数据集说明](docs/DATASETS.md)：数据来源、版本、ID关系、资源规则与可信度。
- [当前实验机体关联](docs/CURRENT_UNIT_ASSOCIATION.md)：实例、机型、模型、武器的 ID 链。机器可读表在同目录 JSON。
- [代码索引](docs/CODE_INDEX.md)：逐文件作用、入口及导入依赖。
- [历史研究索引](docs/RESEARCH_INDEX.md)：全部本地研究记录，旧结论需按最新纠错复核。
- [Agent协作规范](docs/AGENT_WORKFLOW.md) / [AGENTS.md](AGENTS.md)：Issue、分支、提交、MR/PR、审查、交接的机器可读约定。
- [本次验证](docs/VERIFICATION.md) / [发布范围](docs/PUBLISHING.md)。

## 快速验证（无需启动游戏）

使用Python 3.10及以上版本；加密TCP验证还需PATH中存在支持Camellia的OpenSSL。

```powershell
python -m unittest discover -s server -p "test_*.py" -v
python tools/smoke_local_battle.py
```

模型匹配需Pillow及本地解码资源：

```powershell
python -m pip install Pillow
python tools/model_matcher/app.py --open
```

打开 http://127.0.0.1:8765 。客户端与解码资源不随仓库分发，应按手册放入本地指定位置。仓库里的历史CMD含作者本机Python路径，使用前须检查。

## 目录

`server/`为服务、协议、参考数据和历史研究；`tools/`为资源处理、调试和测试；`exports/gundam-model-matcher/`为独立工具导出快照（主工程开发入口是tools/model_matcher）；`start_game.py`为早期启动入口。

## 许可与来源

游戏客户端、资源、商标及Wiki内容的权利属于各自权利人。根项目尚未指定统一开源许可证，不推定第三方资源获得再分发许可。独立导出工具和vendor目录现有LICENSE仅按各自适用范围保留。默认以私有研究仓库保存源码和参考记录，不包含游戏安装包、图像资源、内存转储或个人存档。
