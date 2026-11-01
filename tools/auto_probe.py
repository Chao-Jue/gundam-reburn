"""自动跟随客户端进程挂 probe_state 的钩子（客户端崩了重开也能自动跟上）。

客户端冷启动存活率不高（已知随机 AV 0xc0000005），每次崩了启动器会重开新 pid，
手动重挂很麻烦。这个脚本每 2 秒查一次 GundamOnline_CHINA.exe，pid 变了就重挂。

用法：python tools/auto_probe.py --seconds 3600
日志：server/probe_state.log（与 probe_state.py 同一个文件）
"""
import argparse
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from probe_state import JS, STATE_SETTERS, LOG, MOD  # noqa: E402


def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ' + MOD, '/FO', 'CSV', '/NH'],
                         capture_output=True)
    txt = out.stdout.decode('mbcs', 'replace')
    for line in txt.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seconds', type=int, default=3600)
    a = ap.parse_args()

    f = open(LOG, 'a', encoding='utf-8')

    def on_msg(msg, data):
        if msg.get('type') == 'error':
            line = '[JS-ERR] ' + str(msg.get('description'))
        else:
            p = msg.get('payload')
            if isinstance(p, dict):
                p.pop('q', None)
                line = json.dumps(p, ensure_ascii=False)
            else:
                line = str(p)
        f.write(time.strftime('%H:%M:%S ') + line + '\n')
        f.flush()

    js = JS.replace('__SETTERS__', json.dumps({str(k): v for k, v in STATE_SETTERS.items()}))
    cur_pid = None
    sess = None
    t0 = time.time()
    try:
        while time.time() - t0 < a.seconds:
            pid = find_pid()
            if pid != cur_pid:
                if sess:
                    try:
                        sess.detach()
                    except Exception:
                        pass
                    sess = None
                cur_pid = pid
                if pid:
                    f.write('\n===== auto_probe pid=%d %s =====\n' % (pid, time.strftime('%H:%M:%S')))
                    f.flush()
                    try:
                        sess = frida.attach(pid)
                        sc = sess.create_script(js)
                        sc.on('message', on_msg)
                        sc.load()
                        print('[+] attached pid=%d' % pid, flush=True)
                    except Exception as e:
                        print('[!] attach %s failed: %r' % (pid, e), flush=True)
                        cur_pid = None
                else:
                    print('[-] client gone, waiting', flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        if sess:
            try:
                sess.detach()
            except Exception:
                pass
        f.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
