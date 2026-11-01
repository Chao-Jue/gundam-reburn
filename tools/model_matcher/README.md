# 机体模型 / 数据匹配台

双击 `tools/start_model_matcher.cmd`，无需管理员权限。启动后打开 http://127.0.0.1:8765 。关闭工具控制台即可停止服务。若端口被占用，关闭旧工具或直接运行 `python tools/model_matcher/app.py --port 8767 --open`。

## 使用

1. 左侧搜索模型资源编号或浏览列表，默认打开吉姆101010101。拖动旋转、滚轮缩放、右键平移。
2. 默认尝试选择资源目录内的基础颜色贴图，并隐藏部分替换手型、贴花与光束。右侧可逐网格切换DDS贴图、勾选显隐；这些只是预览建议，需人工检查。支持翻转贴图V方向、线框与重置镜头。
3. 右侧搜索Wiki机体名称，勾选对应条目。可多选，用于共用模型的多个数据变体。展开查看原始性能和武器参考数据。
4. 填写备注并点击“保存匹配”。切换模型前会提示未保存修改。筛选“未匹配/已匹配”可管理进度。
5. 顶部可导出JSON。右侧顶部保存操作栏随滚动保持可见。机体选项显示Wiki头像，未找到或加载失败会明确提示。

## 数据与后续接入

结果：`server/reference/model_matches.json`，按资源相对路径索引，包含model_id、模型SHA256、人工选中的Wiki标题/修订/来源URL、每网格贴图、显隐、UV翻转、备注与更新时间。原子写入，新增匹配保留其他模型记录。删除匹配需界面确认。浏览器关闭或服务重启不丢失已保存数据。

不自动授予机体、不修改客户端、不修改Wiki原始数据、不自动编造机型ID。后续agent可读取结果，将确认后的Wiki条目关联到服务器机型定义；模型ID、机型ID、实例ID仍是不同层次。匹配的是参考解码资源版本，不能把所有条目自动认定为当前运行客户端都可用。

输入：`GundamOnline_CHINA_已解密/decrypted/chara`中的MSM资源，`server/reference/wiki/units.json`。当前识别659个规范命名模型，632个Wiki页面；三维解析扫描649成功、10失败。失败模型明确报错，不能假装是已支持预览。解析成功表示格式检查通过，不表示649个模型都已人工核对外观。

## 解析与限制

dxg.py实现DXG 1.8的静态网格流（0xFF01、0xFF02）：独立位置/法线/UV索引、三角形及多骨骼组。根据原始坐标显示静态姿态，不播放骨骼动画，不还原游戏shader、法线贴图、发光或所有隐藏部件规则。不能自动保证材质名与DDS的精确关系，因此提供每网格手动选择并保存。纹理由Pillow在本地解码成PNG。

开发工具与依赖：Python（Pillow）；浏览器WebGL；Three.js 0.170.0与OrbitControls已随工具本地保存，许可证在web/vendor/LICENSE。运行不依赖CDN。

## 验证

运行以下命令（项目使用的Python绝对路径见启动CMD）：

```powershell
python -m unittest discover -s tools/model_matcher -p test_matcher.py -v
python -m py_compile tools/model_matcher/app.py tools/model_matcher/dxg.py
python tools/model_matcher/smoke_ui.py
```

最后一项要求playwright及本机Chrome，使用临时保存路径，验证真实DXG加载、DDS贴图、选择条目、保存、刷新恢复、导出；不向正式匹配文件写测试条目。截图preview.png仅为测试截图，标注是测试数据。首次冒烟测试在导出检查处因测试脚本相对URL错误失败，改为绝对URL后通过。贴图V方向回归也先失败后修正为默认不翻转，通过后再次检查外观。

机体图片链接清单：`server/reference/wiki/unit_images.json`，当前565/632条目有图片；保留Wiki原图URL，浏览器按需加载，图片本身未下载到本地。使用 `python tools/model_matcher/fetch_unit_images.py` 可补抓缺失链接（需playwright）。

## 2026-10-31补抓

当前751条去重标题记录，包含107条仅分类性能记录（界面明确标识，武器未取得），原27个失败页面已补抓成功；696条记录有图片链接。初期型吉姆已有页面数据，吉姆指挥轻装型暂为分类性能记录。可用repair_wiki_data.py重试失败记录并补齐分类覆盖；不会把分类条目伪装成完整武器图鉴。资源命名新规则见docs/model-texture-rules.md（主工程为server/模型与贴图命名规则-用户确认-2026-10-31.md）。
