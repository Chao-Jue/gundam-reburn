# Agent工程约定

开始工作先读README.md、docs/DEVELOPMENT.md、docs/DATASETS.md、docs/AGENT_WORKFLOW.md及相关最新研究记录。

- Bug先写复现测试，运行确认因预期原因失败，再修复并复跑同一测试。
- 修改代码后必须Python编译或适用构建，并运行与风险相称的自动测试；检查可安全运行就不得省略。
- 区分source_inspection、compile_build、automated_tests、service_startup、database_migration、runtime_integration、native_client_e2e；未执行不称通过。
- 保护所有现有未提交文件。禁止未经明确指示执行stash、reset、clean、checkout --或覆盖/移动用户改动。
- 不上传客户端、解码资产、转储、日志、账号、凭据及saved_*存档。保持默认本地监听和普通/实验模式隔离。
- 不将Wiki ID、模型ID、机型ID、资产ID混用，不自动覆盖人工匹配。实验占位字段必须标明。
- MR与PR同义；遵循docs/AGENT_WORKFLOW.md，使用.github/pull_request_template.md和schemas/agent-result.schema.json提交可解析结果。
- 未完成真实客户端验证不得声称基地显示、实体出击或完整战斗已完成。报告失败尝试、阻塞原因和下一步。
