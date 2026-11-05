# 使用手册

基线为2026-11-01本地开发目录。先阅读README中的功能边界。

## 1. 环境与文件准备

推荐Windows x64、Python 3.10+、Git。普通服务主要使用标准库；fake_auth调用OpenSSL CLI执行Camellia-128-ECB。模型工具需Pillow，图标匹配需numpy；Wiki浏览器采集/界面冒烟需playwright及对应浏览器；原生解码测试需unicorn；反汇编工具通常还需capstone，运行时注入需frida。按使用模块安装，不必为只读代码安装所有调试依赖。依赖未统一锁版本，跨机复现仍需记录实际版本。

```powershell
python --version
openssl version
python -m pip install Pillow numpy unicorn capstone frida playwright
```

游戏客户端放在 `launcher/gundam/机动战士敢达Online/GundamOnline/`；解码参考资源放在 `GundamOnline_CHINA_已解密/decrypted/`。二者是不同数据版本，不能互相替代。离线原生测试读取 `server/img_dump/main_GundamOnline_CHINA.exe`，该文件为研究环境中的已加载映像，不是可任意替换的磁盘PE。缺少私有输入时应明确报告blocked，不要填假文件让测试通过。

启动CMD里的PY目前指向作者本机环境。跨机器使用前将其改为实际解释器路径；这些路径尚未参数化。先运行 `python tools/env_check.py` 阅读环境诊断；不要自动执行环境修改脚本。

## 2. 模型与Wiki匹配台

运行 `python tools/model_matcher/app.py --open`，默认监听127.0.0.1:8765；冲突时加 `--port 8767`。关闭控制台或Ctrl+C停止。

左侧搜索MSM编号，旋转、缩放检查模型；逐网格检查显隐、DDS与UV方向。右侧搜索Wiki机体，可多选同模型的数据变体，填写证据和备注后保存。切换前处理未保存提示。用已匹配/未匹配筛选追踪进度，顶部导出JSON。

正式结果为 `server/reference/model_matches.json`；试验时使用 `--save 临时路径.json`，避免污染正式标注。保存后刷新并重新打开确认恢复。匹配不会自动授予机体，贴图默认选择是启发式，必须人工复核。工具静态解析DXG 1.8，不还原动画与完整shader。Three.js和OrbitControls已本地随附。

Wiki补抓：`python tools/crawl_gundam_wiki.py --max-pages 5 --out scratch/wiki`。确认采集效果后再决定完整抓取输出；不要覆盖唯一完整缓存。修复脚本和图片链接采集脚本先查看 `--help`。图标候选用 `python tools/weapon_icon_match.py --unit 高达OL吉姆`，打开输出review.html，人工选择后导出；未导出的选择不会自动恢复。

武器特效匹配：`python tools/weapon_effect_match.py --port 8769 --open`（或双击 `tools/start_weapon_effect_match.cmd`）。左栏按标签浏览 `fx/` 下的特效库，中间每张卡片是「当前武器模型 + 该特效」的合成预览，右栏按槽位人工指派并导出。预览为离线近似（混合模式、粒子发射、轨迹都是近似），不是渲染验收；导出写在 `server/reference/weapon_effect_match/weapon_effect_assignments.json`，不会改服务端武器定义。

武器/机体复核：`python tools/weapon_review.py --port 8770 --open`。`--icons` 出图标候选、`--import-csv` 导入国服武器对照表、`--fill-icons` 按客户端号补图标、`--export` 导出扁平表；`python tools/unit_export.py` 生成机体级汇总（units.csv / units.json / unit_index.csv / completeness.json）。数据只写 `server/reference/` 下的 JSON，不改服务端武器定义。

日服 wiki 数值：`python tools/extract_gow_swiki.py --html <各種検証存档.html>`，产出装填/连射/弹速派生表（日服 2022 年实测，未验证与国服一致）。

## 3. 独立服务与协议验证

```powershell
python server/fake_http.py --host 127.0.0.1 --port 8080
python server/fake_auth.py --port 30000 --idle 7200
python tools/smoke_local_battle.py
```

HTTP静态清单来自server/fake_root/launcher/authsv.csv；认证端口必须与清单及客户端重定向一致。8080适合独立验证；现有一键启动流程使用80。fake_auth包含大量历史试探开关，实际参数以 `--help` 为准。GM模式额外使用 `--hangar-experiment gm`；普通模式不会自动开放实验战斗。

角色保存在server/saved_pilots.json，普通机库为saved_hangar.json，实验机库为saved_hangar.gm.json。修改/删除前备份，停止服务后操作；不要上传真实存档。准备房间、预约和OTP在内存中，重启即失效。

## 4. 原版客户端联调

当前使用 `tools/start_gm_experiment.cmd`，它设置PILOT_EXTRA并调用start_local.cmd。流程启动hosts守护、清理旧客户端/CPS、HTTP与认证监听、ODS日志、状态探针、auto_advance和run_hooked注入。脚本会结束旧进程和30000端口监听，应先确认这些是本项目进程。

此流程需要管理员权限并修改本机hosts/进程内存；auto_advance清除下载泵字段是临时绕过，不是下载问题已修复。可设置 `GUNDAM_AUTO_ADVANCE=0` 重现自然下载卡点。env_prepare_game.py会改BCD、快速启动及结束进程；env_restore.py用于恢复，两者涉及重启，不属于普通安装必要步骤，应先读server/环境改动记录.md及脚本。

进入游戏后按大规模战→单人参战→预约参战。GM模式创建本地单机师准备房间，重启服务和客户端重新登录才能加载新表；旧场景刷新不能验证新基地定义。预期链路为2EFF预约、FC4B轮询、B099通知、846A请求、5383凭据、新连接F24B、A5DA/BDD6/5913，然后准备状态与场景/出击列表。当前实体生成尚未实现，服务应明确拒绝真实出击，不能把倒计时或地图显示当作战斗完成。

## 5. 排错与退出

端口占用：先用Get-NetTCPConnection确认拥有者；不要盲目杀未知PID。无战区：核对HTTP监听、hosts及authsv.csv。认证断开：查fake_auth.log和首个异常，不靠扩大随机回包掩盖结构错。正在取得数据卡住：核对下载泵绕过与表解析。模型读取失败：按模型ID还原资源路径，检查实际运行客户端而非仅参考解码目录。

正常退出先关客户端与各自控制台；hosts_guard可能持续恢复hosts，恢复环境前先停该守护。记录停止了哪些进程、恢复哪些配置。日志保留本地，发布问题时脱敏账号、路径和凭据。
