# 逐文件代码索引

自动从当前源文件的模块说明、主入口与import生成；无模块说明的历史脚本仅标注静态事实，运行前必须阅读源码。归类不表示已经验证可执行。

## server

### `server/_branch.py`

Disassemble the branch that decides to show the XGG error.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, find, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_build_spec.py`

从解包镜像里批量抽"表规格"：每张表的列号 → 类型（整数/字符串/枚举），

入口/对象：va2off, code, cstr, dis, imm_strings, is_enum_token, fields_of, main。 导入：capstone, capstone.x86, json, pefile, struct, sys。

### `server/_build_table_map.py`

生成"文件序号 → 表类 → Load → 行解析器"地图。需要提权（客户端是提权进程）。

入口/对象：va2off, s_dw, s_cstr, class_of, row_parser_of, find_pid, r_u32。 导入：ctypes, pefile。

### `server/_caller.py`

Find who calls the XGG error dialog, in memory and in the exe file.

入口/对象：WOW64_FLOATING_SAVE_AREA, WOW64_CONTEXT, MEMORY_BASIC_INFORMATION, readmem, main, dialog_tid。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_calls_in.py`

列出 [s,e) 范围内的所有 call 目标。用法: python server/_calls_in.py 0x544F60 0x545600

入口/对象：。 导入：capstone, pathlib, sys。

### `server/_callsites.py`

Find every relative call into the XGG error dialog function.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, find_sig, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_count_rec.py`

独立核算 0xA956F0（parse_pilot_record）的线上消费字节数。

入口/对象：。 导入：capstone, pathlib, re。

### `server/_crop.py`

抓一张客户端窗口图并按 Rect 裁剪放大保存（不需要 PIL）。

入口/对象：。 导入：argparse, pathlib, sys, win_shot。

### `server/_diff_snap.py`

整块内存差分：autoexec 请求时拍快照 A，msma 回复后 3 秒拍快照 B，diff 出变化的块。

入口/对象：MBI, log, find_pid, regions, rd, snap, main。 导入：ctypes, ctypes.wintypes, hashlib, os, subprocess, sys, time。

### `server/_dis_parser.py`

反汇编行解析器并在取字段处标注列号。用法: python server/_dis_parser.py 0x551BC0 [字数]

入口/对象：va2off, run。 导入：capstone, sys。

### `server/_disasm_xgg.py`

Disassemble the exe call sites that lead into the XGG error dialog.

入口/对象：main。 导入：capstone, pathlib, pefile。

### `server/_dpi_probe.py`

验证「DPI 缩放导致 GetSystemMetrics 与真实显示模式不一致」的假设。

入口/对象：DEVMODEW, metrics, device_caps, display_mode, system_dpi, logpixels, is_aware, main。 导入：__future__, ctypes, ctypes.wintypes, sys。

### `server/_dump_err.py`

Dump the decrypted error-message table and nearby error codes.

入口/对象：MODULEINFO, read, main。 导入：ctypes。

### `server/_dump_pending.py`

不挂调试器，直接读客户端里的"待下载表"（std::map），把每个节点的

入口/对象：log, find_pid, Mem, read_wstring, dump_map, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time。

### `server/_enum_dispatch.py`

枚举 CGVOProtoLounge::on_message (0xAA2D50) 的 opcode 分发表。

入口/对象：off。 导入：capstone, pathlib, sys。

### `server/_enum_dispatch2.py`

补全分发表：除 cmp eax,imm 外，编译器还会用 sub eax,imm / je 的形式（线性尾段）。

入口/对象：。 导入：capstone, json, pathlib。

### `server/_enum_dispatch3.py`

递归解析 CGVOProtoLounge::on_message 的二分查找树，输出 opcode -> handler。

入口/对象：dis1, walk。 导入：capstone, json, pathlib, sys。

### `server/_err_strings.py`

Launch the game and write the decrypted dialog strings plus owning module.

入口/对象：MEMORY_BASIC_INFORMATION, MODULEENTRY32W, titles, read, u16_strings, main。 导入：ctypes, pathlib, subprocess, time。

### `server/_extract_columns.py`

从行解析器里抽取列布局：push <列号>; call 0xB081E0(整数) / 0xB082E0(字符串)。纯静态。

入口/对象：va2off, code, fields_of。 导入：capstone, json。

### `server/_find_e13a.py`

在整个解包镜像里精确搜 0xE13A / 0xDFC2 作为立即数出现的所有位置。

入口/对象：。 导入：capstone, pathlib。

### `server/_find_node.py`

触发式内存扫描：等 fake_auth.log 里出现目标表请求 → 等 N 秒 → 扫全内存，

入口/对象：MBI, log, find_pid, rd, regions, scan_blocks, wide, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time。

### `server/_find_os_check.py`

Launch the game, then locate the code that creates the OS error dialog.

入口/对象：MEMORY_BASIC_INFORMATION, launch, window_titles, scan, main。 导入：ctypes, pathlib, subprocess, time。

### `server/_find_vcall78.py`

找 `mov r,[vt+0x78]` 之后 30 字节内出现 `ff d0`(call eax)/`ff d1`/`ff d2`/`ff d3` 的位置。

入口/对象：。 导入：pathlib。

### `server/_find_vt78.py`

搜 `call dword ptr [reg+0x78]`（ff 5x 78）的所有位置。

入口/对象：。 导入：pathlib。

### `server/_find_vt78b.py`

搜 `mov reg,[reg2+0x78]`（8b / 01 r r r / 78）与 `jmp [reg+0x78]`（ff 6x 78）。

入口/对象：。 导入：pathlib。

### `server/_find_vt78c.py`

只找 on_message 区域（0xAA0000-0xAE0000）里 `mov eax,[reg+0x78]` 的形态。

入口/对象：。 导入：pathlib。

### `server/_fn.py`

Disassemble the function that reports error 49235, from its prologue.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, find_mark, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_frames.py`

Walk the dialog's stack frames and disassemble the XGG return sites.

入口/对象：WOW64_FLOATING_SAVE_AREA, WOW64_CONTEXT, main, find_dialog, readmem。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_frida_probe.py`

探测 frida 能否从 64 位宿主注入 32 位 (WOW64) 进程。

入口/对象：main。 导入：__future__, ctypes, frida, sys, time。

### `server/_grid.py`

抓图 + 裁剪放大 + 画坐标网格（每 50 屏幕像素一条线，主网格 100 标红）。

入口/对象：load_png, save_rgb。 导入：argparse, pathlib, struct, sys, win_shot, zlib。

### `server/_hed_probe.py`

解析 data/settings.hed（FPMF 索引），并用已知明文校验 data/settings/0000.dat。

入口/对象：try_inflate, printable_ratio, main。 导入：__future__, pathlib, re, struct, zlib。

### `server/_imm.py`

Classify every instruction that materializes error 49235 or 49236.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, dialog。 导入：ctypes, pathlib, subprocess, time。

### `server/_jump.py`

Find the conditional jump that enters the 49235 and 49236 reports.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, find, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_known_plain.py`

已知明文攻击：用解密后的 settings 原文去撞 data/settings/0000.dat 容器。

入口/对象：read_head, xor, main。 导入：__future__, pathlib, sys。

### `server/_map_tables.py`

解析 0x544E3C 的文件序号跳转表，提取每个 case 用的表对象全局。

入口/对象：va2off, dw。 导入：struct。

### `server/_ods_import.py`

解析解包镜像的导入表，找 OutputDebugString 的 IAT 槽，再数代码里对它有多少次 call/jmp。

入口/对象：。 导入：pathlib, struct。

### `server/_ods_selftest.py`

自检：同进程内起监听线程 -> 自己发 ODS -> 看能否收到（不写任何文件）。

入口/对象：。 导入：ctypes, ods_listen, pathlib。

### `server/_peek_str.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：。 导入：pathlib。

### `server/_probe_dat.py`

探测 data/ 下分片 .dat 的封装：是不是 FPMF？能否用已知方法(xor0x43+raw-deflate)解开？

入口/对象：head_hex, try_inflate, try_xor_inflate, probe, main。 导入：__future__, pathlib, sys, zlib。

### `server/_ptr_os_check.py`

Find pointers to the decrypted OS-error string inside the running game.

入口/对象：MEMORY_BASIC_INFORMATION, main。 导入：ctypes。

### `server/_read_tbl_global.py`

读 0x544790 分派表里用到的表对象全局（0x1169a48 等），拿 vtable。

入口/对象：find_pid, rd, main。 导入：ctypes。

### `server/_read_tbl_global2.py`

常驻读取器：每 0.3s 读一次表对象全局，非零就落盘（提权运行）。

入口/对象：find_pid, rd, log, main。 导入：ctypes。

### `server/_refs_global.py`

列出所有引用某个绝对全局地址的指令位置（a1 xx / 8b 0d xx / ff 15 xx 等）。

入口/对象：。 导入：pathlib, sys。

### `server/_rtti_vt.py`

给一个 TypeDescriptor VA，解出 vtable（COL 引用点 +4）。

入口/对象：resolve。 导入：pathlib, struct。

### `server/_rtti_vtable.py`

在 dump 出来的镜像上静态解析 RTTI → vtable。

入口/对象：off2va, va2off, dword, find_all, resolve。 导入：pefile, re。

### `server/_scan_absref.py`

找出所有引用某个绝对地址（全局变量）的指令。

入口/对象：。 导入：capstone, pathlib, re, sys。

### `server/_scan_calldisp.py`

扫描 call/jmp dword ptr [reg+disp8] （指定 disp），打印上下文。

入口/对象：。 导入：capstone, pathlib, re, sys。

### `server/_scan_now.py`

一次性内存扫描：立刻扫，不等待。把所有输出（含异常）写进 server/scan_now.log。

入口/对象：log, MBI, find_pid, rd, regions, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time, traceback。

### `server/_scan_now2.py`

第二轮运行时取证（提权，一次性）。输出 server/scan_now2.log。

入口/对象：log, MBI, find_pid, rd, dw, wstr, find_sentinel, inorder, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time, traceback。

### `server/_scan_vt78.py`

扫描全镜像里 call/jmp dword ptr [reg+0x78] 的点，并对每个命中点做局部反汇编。

入口/对象：。 导入：capstone, pathlib, re, sys。

### `server/_scan_vt78b.py`

找 `mov reg,[reg+0x78]` 且后面紧跟 `call reg` 的点（vt+0x78 调用）。

入口/对象：。 导入：capstone, pathlib, sys。

### `server/_scan_vtcall.py`

找 `mov rA,[rB+disp]` 且后续同寄存器被 call 的点。

入口/对象：。 导入：capstone, pathlib, sys。

### `server/_scan_vtslot.py`

找 `mov rB,[rX+0x78]` 且 rB 刚由 `mov rB,[rY]` 载入（= 取 vtable 后再取槽）的点。

入口/对象：。 导入：capstone, pathlib, sys。

### `server/_sites.py`

Show the branch immediately before each 49235 and 49236 report.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_stack.py`

Walk the error-dialog thread back into the unpacked XGG code.

入口/对象：WOW64_FLOATING_SAVE_AREA, WOW64_CONTEXT, MEMORY_BASIC_INFORMATION, main, find_dialog, readmem, protect。 导入：ctypes, pathlib, subprocess, time。

### `server/_status.py`

Find the instruction that returns status 0xffff0002 inside the unpacked XGG image.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, locate, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_tmpl.py`

Dump the decrypted error-message templates and the code that points at them.

入口/对象：MEMORY_BASIC_INFORMATION, regions, read, u16_runs, main, titled。 导入：ctypes, pathlib, subprocess, time。

### `server/_trace_err.py`

Capture the live error dialog and locate its message template in memory.

入口/对象：MEMORY_BASIC_INFORMATION, main, windows, child_text。 导入：ctypes, pathlib, subprocess, time。

server\_unlock_launcher.py: 静态解析失败 'utf-8' codec can't decode byte 0xbe in position 236: invalid start byte

### `server/_ver.py`

Disassemble the version compare that rejects this operating system.

入口/对象：MEMORY_BASIC_INFORMATION, readmem, main, find, dialog。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_verify_frames.py`

按 `0xBD1610` 的反汇编字面，重写客户端的分帧解码器，然后回读服务端实际发出的字节。

入口/对象：decode_stream, main。 导入：__future__, fake_auth, pathlib, sys。

### `server/_watch_all.py`

不挂调试器：同时监视全部 68 个表对象，看哪个变了（= 回复被派发到哪张表）。

入口/对象：log, find_pid, rd, sig_of, main。 导入：ctypes。

### `server/_watch_tbl.py`

不挂调试器：轮询表对象，记录它有没有变化（判断 Load 到底跑没跑）。

入口/对象：log, find_pid, main。 导入：ctypes。

### `server/_which_proto.py`

取若干 vtable 的 +0x54 (on_message)，各自枚举 opcode 分发表，判断谁处理 0x5290。

入口/对象：dword, enum_table。 导入：capstone, json, pathlib。

### `server/_who.py`

Print stack returns inside the unpacked XGG image and the dialog function prologue.

入口/对象：WOW64_FLOATING_SAVE_AREA, WOW64_CONTEXT, MEMORY_BASIC_INFORMATION, readmem, main, locate, dialog_tid。 导入：capstone, ctypes, pathlib, subprocess, time。

### `server/_xref.py`

通用 xref：找所有指向 VA 的 call/jmp/jcc rel32 与 imm32。

入口/对象：。 导入：capstone, pathlib, re, sys。

### `server/_zip_ls.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：。 导入：zipfile。

### `server/_zip_settings.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：。 导入：zipfile。

### `server/battlefield_bases.py`

Explicit local stronghold definitions; not recovered original mission balance.

入口/对象：character_row, model_row。 导入：。

### `server/cn_port80.py`

Port 80 stand-in for the hostnames baked into the China client.

入口/对象：Handler, main。 导入：http.server。

### `server/cn_server.py`

Local endpoints for the 9you China Gundam Online client.

入口/对象：log, find_client, read_user_version, patch_ini, rewrite_utf16_url, point_client, restore_client, ng_packet, gate_reply, recv_exact, GateHandler, PatchHandler, main。 导入：__future__, argparse, datetime, http.server, pathlib, socket, socketserver, struct, sys, threading, urllib.parse。

### `server/decode_proto.py`

离线解码客户端收发帧（Camellia-128-ECB）。

入口/对象：camellia, visual, dump, main。 导入：argparse, json, subprocess, sys。

### `server/dump_client_table_list.py`

从镜像里解出**客户端自己的**表清单，并与解包 CSV 做差异对照。

入口/对象：main。 导入：__future__, pathlib, pefile, re, struct, sys。

### `server/fake_auth.py`

假认证服务器（30000）：分阶段脚本，用来逼出客户端的协议流程。

入口/对象：auth_block, login_ok_block, _zstr, load_local_zone, worldlist_get_r, lounge_ok_block, _align_message, _kind0, _settings_file, parse_datafile_name, parse_msg, op_block, body_70e9, pilot_entry, pilot_list_body, pilot_body, _load_pilot_form, pilot_form。 导入：argparse, hangar, hangar_experiment, json, local_battle, os, random, select, socket, struct, subprocess, sys, threading, time, xwar_entry。

### `server/fake_http.py`

假 HTTP 服务：接住客户端对 ms.patch1.9you.com 的请求（尤其 /launcher/authsv.csv）。

入口/对象：log, Handler, main。 导入：__future__, argparse, http.server, os, pathlib, socket, sys, threading, time。

### `server/gen_msma_weapon_set.py`

按规格生成 msma/msma_weapon_set.csv。

入口/对象：build, main。 导入：argparse, os, sys。

### `server/hangar.py`

Persistent owned units and the v5.0.0.33 hangar wire format.

入口/对象：weapon_wire, unit_wire, unit_add_body, HangarStore。 导入：copy, json, pathlib, struct, threading。

### `server/hangar_experiment.py`

Opt-in GM identity experiment. Assets use a separate experiment store; normal pilot/assets are untouched.

入口/对象：starter_definitions, performance_templates, csv_rows, weapon_tables, upgrade_unarmed_unit, csv_table, table_body, gm_unit。 导入：battlefield_bases, copy, csv, io, json, pathlib。

### `server/local_battle.py`

Local single-pilot preparation rooms and initial scene loading; no combat simulation.

入口/对象：deployment_points, deployment_post_body, deployment_post_states_body, countdown_body, prestart_body, mission_progress_body, auth_identity, authenticate_body, member_body, game_begin_body, spawn_unit_body, Reservation, LocalBattleBackend。 导入：battlefield_bases, dataclasses, functools, json, pathlib, secrets, struct, time, xwar_entry。

### `server/patch_server.py`

Local patch endpoint for the Gundam Online client.

入口/对象：FileEntry, FileList, repo_root, default_client, load_filelist, origin_for, rewrite_baseurl, point_client, restore_client, audit, PatchHandler, serve, main。 导入：__future__, argparse, csv, dataclasses, datetime, hashlib, http.server, io, pathlib, sys, threading, urllib.parse。

### `server/probe_all_cases.py`

一次读全部 67 个 case 的表对象：vtable + 槽 0..7 + 类名，输出 TSV。

入口/对象：log, find_pid, main。 导入：ctypes, pefile。

### `server/probe_purecall.py`

读 case 60..70 用到的表对象全局，打印 vtable / 槽0 / 槽1 / 类名。

入口/对象：log, find_pid, main。 导入：ctypes, pefile。

### `server/probe_queue_map.py`

读「下载队列」那个 map 的全部成员，验证第 65 张的名字到底在不在里面。

入口/对象：log, find_pid, main。 导入：ctypes。

### `server/probe_state.py`

手动触发的运行时状态采样器（需要管理员）。

入口/对象：filelog, say, MBI, find_pid, rd, dw, wstr, regions, read_all, find_nodes, count_rows, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time, traceback。

### `server/scan_case67.py`

卡住时扫内存：找 develop/mechanic_overcustom.csv 的 map 节点。

入口/对象：MBI, log, find_pid, main。 导入：ctypes。

### `server/test_hall_mission_init.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：HallMissionInitTest。 导入：fake_auth, unittest。

### `server/test_hangar.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：sample_unit, HangarTest。 导入：fake_auth, hangar, pathlib, struct, tempfile, unittest, unittest.mock。

### `server/test_hangar_experiment.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：IdentityExperimentTest。 导入：csv, fake_auth, hangar, hangar_experiment, io, pathlib, struct, tempfile, unittest, unittest.mock。

### `server/test_local_battle.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：pilot_record, LocalBattleTest, BattleTransportIntegrationTest。 导入：battlefield_bases, csv, fake_auth, local_battle, pathlib, socket, struct, threading, types, unittest, unittest.mock, xwar_entry。

### `server/test_xwar_entry.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：XwarEntryTest。 导入：csv, fake_auth, io, struct, unittest, unittest.mock, xwar_entry。

### `server/test_xwar_queue.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：FormalBattleQueueTest。 导入：fake_auth, struct, unittest, unittest.mock, xwar_entry。

### `server/world_sniff.py`

在本地监听游戏服端口，把客户端发来的字节原样记下来。

入口/对象：log, hexdump, handle, main。 导入：__future__, argparse, datetime, pathlib, socket, threading。

### `server/xwar_entry.py`

Opt-in diagnostic VS mission for the local entry UI, not a playable map.

入口/对象：BattleRoom, BookingQueue, mission_info_body, table_body。 导入：csv, dataclasses, io, struct, threading。

## tools

### `tools/attach_net.py`

挂客户端**模块内部**的收发路径（不是 Win32 API），抓明文/密文与调用链。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/attach_ws2.py`

对已经在跑的客户端做"热挂"：只装网络发包 hook，抓 16 字节登录包的调用栈。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, sys, time。

### `tools/attach_ws2b.py`

精确栈版网络 hook：抓 send/WSASend/connect 的**精确返回地址** + EBP 链 + 栈快照。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, sys, time。

### `tools/auto_advance.py`

自动推进器：等表阶段跑完，自动把下载器计数写成 0，让状态机进入「正在取得机师数据」。

入口/对象：MBI, log, find_pid, read_u32, write_u32, find_downloader, wait_for_round, advance_once, main。 导入：__future__, argparse, ctypes, os, re, subprocess, sys, time。

### `tools/auto_probe.py`

自动跟随客户端进程挂 probe_state 的钩子（客户端崩了重开也能自动跟上）。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, probe_state, subprocess, sys, time。

### `tools/capture_cps.py`

轮询截获保护模块的内核驱动（CPS.sys 之类）。

入口/对象：service_image_paths, Watcher, main。 导入：__future__, argparse, ctypes, os, pathlib, shutil, sys, threading, time, winreg。

### `tools/clean_cps.py`

清理保护模块在系统里留下的 `CPS` 服务键 / 驱动文件残留。

入口/对象：scm_exists, scm_delete, _delete_tree, inspect, clean, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, os, sys, winreg。

### `tools/click.py`

向屏幕绝对坐标发送一次鼠标左键点击（SendInput，对 DirectInput 游戏同样有效）。

入口/对象：MOUSEINPUT, INPUT, send, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, sys, time。

### `tools/cpuid_probe.py`

读 CPUID，证明这台机器对用户态暴露了 hypervisor。

入口/对象：make_cpuid, main。 导入：__future__, ctypes, struct, sys。

### `tools/crawl_gundam_wiki.py`

Cache Biligame unit references through its public MediaWiki API.

入口/对象：split_top, templates, parse_unit, reference_name, enrich_unit, complete_catalog, WikiClient, fetch_pages, main。 导入：argparse, datetime, hashlib, json, pathlib, re, time, unicodedata, urllib.parse, urllib.request。

### `tools/cropfind.py`

把窗口画面降采样成 ASCII 亮度图，用于定位深色 UI 面板。

入口/对象：main。 导入：__future__, argparse, ctypes, ctypes.wintypes, pathlib, shot, sys。

### `tools/decode_xdt.py`

Decode the XDt/ protection-module logs (obfuscated ASCII wide-char log).

入口/对象：decode, iter_logs, main。 导入：__future__, pathlib, sys。

### `tools/diagnose_deployment_markers.py`

One-shot diagnostic: run the client's existing marker initialization function.

入口/对象：。 导入：argparse, frida, json, pathlib, probe_pilot_state。

### `tools/dis_img.py`

在 dump 出来的客户端镜像上做静态反汇编（壳已解开，代码是真的）。

入口/对象：load, off, find_prologue, dis, callers, main。 导入：__future__, capstone, pathlib, re, sys。

### `tools/disasm_driver.py`

反汇编 CPS_extracted.sys（x64 内核驱动），定位 IOCTL 分发与 0x222055 的读写语义。

入口/对象：load, rva_to_off, off_to_rva, sec_name, scan, disasm, main。 导入：argparse, capstone, pathlib, pefile, struct, sys。

### `tools/disasm_region.py`

按 RVA 反汇编 GundamOnline_CHINA.exe 的任意区间。

入口/对象：load_raw, rva_to_off, section_of, fmt_bytes, main。 导入：__future__, argparse, capstone, pathlib, pefile, sys。

### `tools/dl_attach.py`

attach 到正在运行的客户端，加载 dl_probe.js，把事件写进 dl_probe.log。

入口/对象：find_pid, log, main。 导入：frida。

### `tools/dl_state_probe.py`

只读探针：读「数据表下载器」的三/四个整数，判定它到底处于哪个状态。

入口/对象：PROCESSENTRY32W, find_pid, walk_wstring_map, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, sys。

### `tools/drv_info.py`

对保护模块的内核驱动做静态分析（PE 结构 / 导入 / 签名 / IOCTL 分发）。

入口/对象：main。 导入：__future__, capstone, datetime, hashlib, pathlib, pefile, re, struct, sys。

### `tools/drv_load_probe.py`

只测「CPS.sys 这个内核驱动能不能加载」——把驱动问题从游戏里彻底剥离出来。

入口/对象：SERVICE_STATUS_PROCESS, _SHELLEXECUTEINFOW, is_admin, relaunch_elevated, err_text, run_probe, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, hashlib, os, pathlib, sys。

### `tools/dump_code.py`

只读地 dump 一段壳内代码（**不装任何 hook**）。

入口/对象：find_pid, main。 导入：__future__, argparse, frida, json, pathlib, subprocess, sys, time。

### `tools/elevate_run.py`

用 UAC 提权跑一条命令，并把输出落到文件。

入口/对象：_SEI, is_admin, run_elevated, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, pathlib, subprocess, sys。

### `tools/elevated_watcher.py`

常驻提权执行器：UAC 只点一次，之后可以反复跑需要管理员权限的命令。

入口/对象：wlog, is_admin, elevate_self, run_batch, check_command, run_job, watch, submit, main。 导入：__future__, argparse, ctypes, os, pathlib, shlex, subprocess, sys, time, traceback。

### `tools/emulate_wire_reader.py`

Run an existing client wire reader offline, without touching a live process.

入口/对象：decode, main。 导入：argparse, json, pathlib, struct, unicorn, unicorn.x86_const。

### `tools/env_check.py`

环境自检：一眼看出「hypervisor 关掉了没」以及「到底重启了没」。

入口/对象：uptime, read_boot_options, read_hiberboot, hypervisor_services, main。 导入：__future__, cpuid_probe, ctypes, datetime, os, sys, winreg。

### `tools/env_prepare_game.py`

开工脚本（需要管理员）：关掉 hypervisor，为跑客户端做准备。

入口/对象：run, list_procs, kill, stop_lab, disable_hypervisor, disable_fast_startup, main。 导入：__future__, os, subprocess, sys。

### `tools/env_restore.py`

收工脚本（必须在管理员下运行）：停掉实验进程 + 恢复虚拟化环境。

入口/对象：run, list_procs, kill, stop_lab, restore_hypervisor, main。 导入：__future__, os, subprocess, sys。

### `tools/find_index_array.py`

find_index_array.py —— 用"文件序号等差序列"定位 74 项下载表。

入口/对象：MBI, log, read, regions, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, numpy, struct, time。

### `tools/fpmf_info.py`

Read the clear FPMF header on Gundam Online .hed indexes.

入口/对象：read_header, iter_hed, main。 导入：__future__, argparse, pathlib, struct, sys。

### `tools/hed_extract.py`

尝试解开 FPMF(.hed) 的 body —— 判断它到底是不是 zlib/简单异或。

入口/对象：try_inflate, try_xor_inflate, encodings, scan, main。 导入：__future__, argparse, pathlib, sys, zlib。

### `tools/hook_datadl.py`

数据表下载探针：定位「0x5290 回了却不往下要第三张表」到底断在哪一步。

入口/对象：find_pid, attach_and_hold, main。 导入：__future__, argparse, frida, json, pathlib, subprocess, sys, time。

### `tools/hook_msgid.py`

极简探针：只 hook 收包分发器 0x7d5009，把 32 位消息 ID 打出来。

入口/对象：find_pid, attach_and_hold, main。 导入：__future__, argparse, frida, json, pathlib, subprocess, sys, time。

### `tools/hook_net2.py`

挂客户端**模块内部**的收发路径 + 验证 hook 是否真的写入内存。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/hosts_guard.py`

hosts 守护：每 5 秒检查一次，缺 `127.0.0.1 ms.patch1.9you.com` 就补回去。

入口/对象：missing, patch, main。 导入：__future__, argparse, os, pathlib, sys, time。

### `tools/hosts_up.py`

确保 hosts 里有 gundam-reburn 需要的两条映射（需要管理员权限）。

入口/对象：is_admin, main。 导入：__future__, ctypes, os, pathlib, socket, sys。

### `tools/inspect_scene.py`

One-shot read-only scene/task inspection of the running client.

入口/对象：main。 导入：argparse, json, pathlib, probe_pilot_state。

### `tools/killstale.py`

清理上一轮实验残留的【提权】进程（必须在管理员下运行）。

入口/对象：list_procs, pid_alive, kill, main。 导入：__future__, os, pathlib, subprocess, sys。

### `tools/model_matcher/app.py`

Local-only model / Wiki matching workstation. Run with Python, no elevation.

入口/对象：catalog, read_matches, save_match, model_data, Handler, main。 导入：PIL, argparse, datetime, dxg, functools, hashlib, http.server, io, json, pathlib, re, threading, urllib.parse, webbrowser。

### `tools/model_matcher/dxg.py`

Bounded reader for DXG 1.8 static mesh streams; no skeleton animation.

入口/对象：parse。 导入：math, struct。

### `tools/model_matcher/fetch_unit_images.py`

Resolve unit portraits from the Wiki's actual basic-stat template naming rule.

入口/对象：image_name, main。 导入：json, pathlib, playwright.sync_api, urllib.parse。

### `tools/model_matcher/smoke_ui.py`

Chrome smoke test on an isolated save file, never creates real matches.

入口/对象：。 导入：json, pathlib, playwright.sync_api, subprocess, sys, tempfile, time, urllib.request。

### `tools/model_matcher/test_matcher.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：MatcherTest。 导入：app, dxg, json, pathlib, tempfile, unittest, unittest.mock。

### `tools/ods_listen.py`

ods_listen.py —— 进程外旁听 OutputDebugString（DBWIN_BUFFER 协议）。

入口/对象：PROCESSENTRY32W, find_pid_by_name, pid_alive, probe_foreign_listener, OdsListener, _err, _printer, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, datetime, os, queue, struct, sys, threading, time。

### `tools/page_prot_test.py`

方案 B：页保护存在性测试（只改页表，不改字节）

入口/对象：MBI64, ts, log, is_admin, find_pid, open_target, module_list, dep_policy, query_page, describe, set_protect, exit_code, tail_fa, last_table_no, _probe_default, test_page, selftest, main。 导入：__future__, argparse, ctypes, os, subprocess, sys, time。

### `tools/patch_force_advance.py`

强制推进：把 0x5448F4 的 `jne 0x544E07`（处理失败就返回）改成无条件 jmp 0x544DD7

入口/对象：p, find_pid, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time。

### `tools/patch_skip_load.py`

把 0x5448FA（switch 表序号 / 调各表 Load 的地方）改成直接跳到 0x544DD7（公共尾部：

入口/对象：_Tee, find_pid, main。 导入：ctypes, ctypes.wintypes, os, struct, subprocess, sys, time。

### `tools/peek.py`

在**运行中**的客户端里按 RVA 读字节并反汇编（壳内的真实代码，静态文件里是密文）。

入口/对象：find_pid, main。 导入：__future__, argparse, capstone, frida, json, subprocess, sys, time。

### `tools/pilot_call.py`

手工完成一次 0xE13A 成功回调 —— 绕开帧层，直接把机师数据喂给客户端。

入口/对象：find_pid, main。 导入：__future__, argparse, frida, sys。

### `tools/plain_launch.py`

纯净启动客户端：不注入 frida、不打任何 hook，只观察它自己会怎样。

入口/对象：SHELLEXECUTEINFOW, launch_elevated, wait_elevated, find_exe, collect_window_texts, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, pathlib, subprocess, sys, time。

### `tools/probe_deployment_state.py`

Read-only snapshot of deployment posts and minimap configuration in the current client.

入口/对象：snapshot。 导入：argparse, json, pathlib, probe_pilot_state, struct。

### `tools/probe_hs.py`

定位"16 字节登录包"的产出者。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/probe_light.py`

轻量探针：只挂已被验证安全的点，状态靠"轮询内存"而不是"给代码下断点"。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/probe_pilot_state.py`

只读探针：机师阶段的关键状态。

入口/对象：PROCESSENTRY32, find_pid, Reader, snapshot, _q, _hx, fmt, change_key, main。 导入：__future__, argparse, ctypes, os, struct, sys, time。

### `tools/probe_setsession.py`

追问"那 16 字节是谁写进 RSA 上下文的"。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/probe_state.py`

实时追踪 Socket 握手状态机 [Socket+0x280] 的每一步。

入口/对象：find_pid, main。 导入：argparse, frida, json, os, subprocess, sys, time。

### `tools/queue_patch.py`

queue_patch.py —— 不附加调试器，直接找到"数据表下载队列"并清空它。

入口/对象：MBI, log, open_proc, regions, read, write_u32, scan_for, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, pathlib, struct, sys, time。

### `tools/queue_patch2.py`

queue_patch2.py —— 找下载队列节点（多假设版），先 dump 结构再决定是否清空。

入口/对象：MBI, log, read, write_u32, regions, hexdump, plausible, name_at, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, struct, sys, time。

### `tools/read_va.py`

从**正在运行**的进程里读内存，验证 dump 是否与当前进程一致。

入口/对象：find_pid, main。 导入：argparse, capstone, frida, os, subprocess, sys。

### `tools/repair_wiki_data.py`

Retry failed Wiki pages and retain category-only references. Never drop good records.

入口/对象：main。 导入：argparse, crawl_gundam_wiki, datetime, hashlib, json, pathlib, playwright.sync_api, urllib.parse。

### `tools/run_hooked.py`

用 frida 在 Win32 API 边界上"骗过"保护模块的驱动加载检查。

入口/对象：find_exe, is_admin, _run_elevated_and_wait, elevate_self, parse_fake, parse_ioctl_out, parse_redirect, build_string_patterns, build_cfg, Logger, query_exit_code, collect_window_texts, kill_existing_game, _proc_table, kill_stale_runners, main。 导入：__future__, argparse, clean_cps, ctypes, frida, json, os, pathlib, subprocess, sys, threading, time。

### `tools/scan_ref.py`

在整个主模块里搜某个 4 字节值的引用（只读 Memory.scan，不装 hook）。

入口/对象：le_hex, find_pid, main。 导入：__future__, argparse, frida, json, pathlib, subprocess, sys, time。

### `tools/sendinput.py`

用 SendInput 往目标窗口发文字/点击/回车（D3D 游戏只认真实输入）。

入口/对象：MOUSEINPUT, KEYBDINPUT, INPUT, _send, click, text, key, main。 导入：argparse, ctypes, ctypes.wintypes, pathlib, sys, time, win_shot。

### `tools/shot.py`

截取某个窗口（或全屏）并存成 PNG。纯 ctypes + zlib，不依赖 PIL。

入口/对象：BITMAPINFOHEADER, BITMAPINFO, window_text, find_window, write_png, capture, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, os, struct, zlib。

### `tools/show_rtti.py`

把 server/hook_runs/rtti_scan.json 里的 RTTI 侦察结果排版出来。

入口/对象：main。 导入：__future__, json, pathlib, sys。

### `tools/smoke_local_battle.py`

Launch an isolated real service and exercise auth -> lounge -> battle over TCP.

入口/对象：Client, main。 导入：collections, fake_auth, hangar, json, local_battle, pathlib, socket, struct, subprocess, sys, tempfile, threading, time。

### `tools/start_local_admin.py`

以管理员身份跑 `tools/start_local.cmd`（UAC 只点一次）。

入口/对象：is_admin, SHELLEXECUTEINFOW, run_as_admin, _clean_stale, main。 导入：__future__, ctypes, pathlib, subprocess, sys, time。

### `tools/tables_probe.py`

只读探针：把「表下载器」对象的真实状态读出来（不写任何字节）。

入口/对象：find_pid, Reader, scan_vtable, main。 导入：__future__, argparse, ctypes, subprocess, sys, time。

### `tools/test_battle_room_native.py`

Current battle decoder execution, excluding UI callbacks and resource loading.

入口/对象：BattleRoomNativeTest。 导入：csv, local_battle, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest, xwar_entry。

### `tools/test_crawl_gundam_wiki.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：WikiParserTest。 导入：crawl_gundam_wiki, unittest。

### `tools/test_hangar_action_resources_native.py`

Exercise real weapon state resource selection, stopping before asset loading.

入口/对象：ActionResourceNativeTest。 导入：csv, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_hangar_native_reader.py`

Offline execution of actual client code, not a second Python decoder.

入口/对象：NativeReaderTest。 导入：emulate_wire_reader, hangar, pathlib, struct, sys, unittest。

### `tools/test_hangar_payload_native.py`

Execute the actual client payload-column assignment block offline.

入口/对象：NativePayloadTest。 导入：csv, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_hangar_readiness_native.py`

Current client initialization contract for deck budget and unit energy.

入口/对象：ReadinessNativeTest。 导入：csv, emulate_wire_reader, fake_auth, hangar_experiment, io, pathlib, struct, sys, unittest, unittest.mock。

### `tools/test_hangar_shield_native.py`

Real shield UI renderer with the static item lookup and widgets substituted.

入口/对象：ShieldNativeTest。 导入：csv, emulate_wire_reader, hangar, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_hangar_sort_native.py`

Regression for the empty sorted list behind the 2026-10-29 crash.

入口/对象：native_sort_lookup, NativeSortTest。 导入：fake_auth, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest, unittest.mock。

### `tools/test_hangar_weapon_detail_native.py`

Regression of 0x7A68BB with native enum and ticket tree lookup.

入口/对象：native_ticket_key, WeaponDetailNativeTest。 导入：csv, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_hangar_weapon_icons_native.py`

Execute the real weapon icon dispatcher; substitute the texture loader only.

入口/对象：WeaponIconsNativeTest。 导入：csv, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_hangar_weapon_stats_native.py`

CSV scalar parser plus actual x87 panel conversions (no live client).

入口/对象：WeaponStatsNativeTest。 导入：csv, hangar_experiment, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest。

### `tools/test_probe_pilot_state.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：FakeReader, SceneProbeTest。 导入：probe_pilot_state, unittest。

### `tools/test_start_local_format.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：LauncherFormatTest。 导入：pathlib, unittest。

### `tools/test_weapon_icon_match.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：IconMatchTest。 导入：PIL, numpy, unittest, weapon_icon_match。

### `tools/test_xwar_booking_native.py`

Execute the current client's field readers, excluding transport and UI callbacks.

入口/对象：BookingNativeTest。 导入：pathlib, struct, sys, unicorn, unicorn.x86_const, unittest, xwar_entry。

### `tools/test_xwar_entry_native.py`

Native description dereference regression; mission lookup is substituted.

入口/对象：XwarDescriptionNativeTest。 导入：csv, io, pathlib, struct, sys, unicorn, unicorn.x86_const, unittest, xwar_entry。

### `tools/vt_probe.py`

在 ivce/协议类的 vtable 槽上做「数据补丁」观测，看客户端真正收到的每条报文。

入口/对象：find_pid, snapshot_pids, run_session, main。 导入：__future__, argparse, frida, json, pathlib, sys, time。

### `tools/weapon_icon_match.py`

Download Wiki weapon icons and generate reviewable, non-authoritative candidates.

入口/对象：references, normalize, descriptor, main。 导入：PIL, argparse, collections, hashlib, html, io, json, numpy, pathlib, playwright.sync_api, urllib.parse。

### `tools/win_shot.py`

按 PID / 窗口类名截取**指定窗口**内容（不依赖前台）。

入口/对象：BITMAPINFOHEADER, BITMAPINFO, find_window, grab, save_png, force_foreground, main。 导入：__future__, argparse, ctypes, ctypes.wintypes, pathlib, struct, sys, time, zlib。

### `tools/winlist.py`

枚举顶层窗口（含对话框），用于判断客户端是不是被模态框挡住了。

入口/对象：text, cls, owner_pid, rect, main。 导入：__future__, argparse, ctypes, ctypes.wintypes。

### `tools/xref.py`

在解包镜像里找所有 call/jmp 到指定 VA 的位置（E8/E9 rel32）。

入口/对象：regions, main。 导入：argparse, glob, os。

## exports/gundam-model-matcher

### `exports/gundam-model-matcher/app.py`

Local-only model / Wiki matching workstation. Run with Python, no elevation.

入口/对象：catalog, read_matches, save_match, model_data, Handler, main。 导入：PIL, argparse, datetime, dxg, functools, hashlib, http.server, io, json, os, pathlib, re, threading, urllib.parse, webbrowser。

### `exports/gundam-model-matcher/crawl_gundam_wiki.py`

Cache Biligame unit references through its public MediaWiki API.

入口/对象：split_top, templates, parse_unit, reference_name, enrich_unit, complete_catalog, WikiClient, fetch_pages, main。 导入：argparse, datetime, hashlib, json, pathlib, re, time, unicodedata, urllib.parse, urllib.request。

### `exports/gundam-model-matcher/dxg.py`

Bounded reader for DXG 1.8 static mesh streams; no skeleton animation.

入口/对象：parse。 导入：math, struct。

### `exports/gundam-model-matcher/fetch_unit_images.py`

Resolve unit portraits from the Wiki's actual basic-stat template naming rule.

入口/对象：image_name, main。 导入：json, pathlib, playwright.sync_api, urllib.parse。

### `exports/gundam-model-matcher/repair_wiki_data.py`

Retry failed Wiki pages and retain category-only references. Never drop good records.

入口/对象：main。 导入：argparse, crawl_gundam_wiki, datetime, hashlib, json, pathlib, playwright.sync_api, urllib.parse。

### `exports/gundam-model-matcher/test_crawl_gundam_wiki.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：WikiParserTest。 导入：crawl_gundam_wiki, unittest。

### `exports/gundam-model-matcher/test_matcher.py`

无模块说明；历史辅助/实验脚本，按源代码确认用途。

入口/对象：MatcherTest。 导入：app, dxg, json, pathlib, tempfile, unittest, unittest.mock。
