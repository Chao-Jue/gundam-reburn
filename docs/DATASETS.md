# 数据集与资源理解

本项目没有单一训练数据集，存在多层研究输入、衍生配置与人工标注。每层须保留来源和版本，不能混合当作原版服务端数据库。

| 层 | 位置 | 作用与边界 |
|---|---|---|
| 官方运行客户端 | launcher/（不发布） | 当前执行协议/读取器/资源加载的最终核验对象 |
| 解码参考资源 | GundamOnline_CHINA_已解密/decrypted/（不发布） | chara模型纹理、settings配置、world地图、interface布局；存在文件不等于运行客户端可用 |
| 研究表与解析结果 | server/ref_settings、xdt_decoded、hed_out等（本地） | 反推列号、枚举与资源关系；版本及完整度不统一 |
| 结构规格 | server/表规格.json、表解析器地址表.json、hangar_*_wire_map.json | 记录读取器/列/偏移；ncols_min仅为静态提取下界 |
| Wiki资料 | server/reference/wiki/units.json | 公开Wiki页面、修订、原始属性和武器字段；属于参考平衡数据 |
| 人工关联 | server/reference/model_matches.json | 模型SHA256、Wiki标题/修订/来源、逐网格贴图显隐、UV、备注与时间 |
| 本地实验定义 | gm_starter_weapons.json、odessa_home_bases.json等 | 明确选择的GM武器与基地锚点，不是完整原版配置 |
| 玩家资产 | server/saved_*.json（不发布） | 真实本地角色与机库状态，与资料集分离 |

## Wiki解释

来源记录在JSON的source_api和单条来源字段中，原始响应缓存raw/仅本地保留。旧README中的632页面、27失败是早期统计，补抓后为751条记录（包括107条仅分类性能记录），696条图片链接，旧失败已补抓。机器可读的当前顶层结构、数量与哈希见DATA_MANIFEST.json；统计日期和retrieved_at并不一定相同，不能将补抓前时间当作所有条目的最新修订时间。

属性里的空白、范围、公式、图片标记和旧手写表格保留原义，不强制转数字。gold_only支持true/false/null；null表示未知，不能视为银图纸。分类性能条目缺武器数据，图片URL存在也不保证当前可访问。模板武器和tables不是统一完整武器库，旧式表格仍需人工核对。

Wiki页ID、分类序号、模型ID、msma_id、武器item_id、资产uniqid互不等价。Wiki的client_unit_id未确认时保持null。模型与Wiki身份可能多对多；同目录多模型既可能是同机体状态，也可能不同机体，必须依据人工证据。

当前实验吉姆这五层 ID 的对照表在 [CURRENT_UNIT_ASSOCIATION.json](CURRENT_UNIT_ASSOCIATION.json)。日文攻略站的开发/强化规则译文在 [gow_develop_enhance_status.md](../server/reference/wiki/gow_develop_enhance_status.md)，只作外部参考，不是本客户端已还原的强化公式。

## 模型和贴图规则

MSM_0101_0101_01.dxg对应模型编号101010101；通用编码为(前两段合并)*1000000 + 中间四位*100 + 变体。基地BAM_0601_0303_01为601030301，错误的601010303会指向不存在资源。模型ID不能通过简单拼接目录数字取得。

默认贴图候选为同编号MST_*_01C.dds或MST_*_01.dds；C表示Color，_001等数字后缀为换色皮肤，Ca/Cb/Cc等字母后缀是扩展贴图。需逐材质/网格绑定，不能一张图覆盖全部。具体规则和用户反例见server/模型与贴图命名规则-用户确认-2026-10-31.md。

DXG解析成功只说明支持的静态流可读，不表示外观、骨骼、动画、shader均正确。模型目录扫描历史为659个规范模型，649解析成功、10失败；这不是人工验收通过数。

## 本地实验数据

GM msma_id=777001、model_id=101010101、uniqid=777000000001；基地msma_id=777201、model_id=601030301。保留这些ID层次，不能互换。GM显示值来自选定Wiki修订并经过当前UI换算，不是已恢复原版战斗参数；COST容量1200/电量100是本地实验设置。

odessa_home_bases.json包含4个独立双方pop锚点，原始坐标单位cm，game_begin使用pos_factor=100。来源任务资源30110130与当前30110100不同变体；不能宣称恢复完整A/B/C-X/Y/Z布局。旧14点诊断脚本写入选项不应套用新布局。

## 更新和审计

更新前复制正式标注/数据到独立备份，不覆盖唯一原件。抓取写独立输出→检查failures、条目类型与来源修订→人工复核关联→比较数量/哈希→以PR说明新增/删除/版本差异。原始数据、自动候选、人工确认、服务实验定义应各自保持身份，不把距离排名叫置信概率。发布仅保存选择后的结构资料和源码，不分发图像、客户端及转储。
