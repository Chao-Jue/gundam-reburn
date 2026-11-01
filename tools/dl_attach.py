# -*- coding: utf-8 -*-
"""attach 到正在运行的客户端，加载 dl_probe.js，把事件写进 dl_probe.log。

只记录、不改代码，比下断点温和；但 frida 用 inline hook，
保护层有极小概率检测到并让客户端退出。
"""
import frida, sys, time, os, subprocess, json

HERE = os.path.dirname(os.path.abspath(__file__))
JS = os.path.join(HERE, 'dl_probe.js')
OUT = os.path.join(os.path.dirname(HERE), 'server', 'dl_probe.log')
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 600


def find_pid():
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True).stdout.decode('mbcs', 'ignore')
    for line in out.splitlines():
        if 'GundamOnline_CHINA' in line:
            p = [x.strip('"') for x in line.split('","')]
            if len(p) >= 2 and p[1].isdigit():
                return int(p[1])
    return None


def log(s):
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(s + '\n')
    print(s, flush=True)


def main():
    open(OUT, 'w', encoding='utf-8').close()
    pid = find_pid()
    if not pid:
        log('没有找到 GundamOnline_CHINA.exe')
        return 1
    log('# attach pid=%d' % pid)
    session = frida.attach(pid)
    script = session.create_script(open(JS, encoding='utf-8').read())

    def on_message(msg, data):
        if msg.get('type') == 'send':
            p = msg['payload']
            t = p.get('t')
            if t == 'enter':
                log('ENTER %-7s this=%s a0=%s a1=%s a2=%s'
                    % (p['tag'], p['thisp'], p['a0'], p['a1'], p['a2']))
            elif t == 'leave':
                log('LEAVE %-7s ret=%s (%sms)' % (p['tag'], p['ret'], p['ms']))
            elif t == 'armed':
                log('ARMED %-7s @ %s' % (p['tag'], p['addr']))
            elif t == 'ready':
                log('# ready')
            elif t == 'error':
                log('ERROR %-7s %s' % (p['tag'], p['err']))
            else:
                log(str(p))
        else:
            log('MSG %s' % json.dumps(msg, ensure_ascii=False)[:300])

    script.on('message', on_message)
    script.load()
    log('# loaded, 等待 %ds' % SECONDS)
    end = time.time() + SECONDS
    while time.time() < end:
        time.sleep(1)
        if find_pid() != pid:
            log('# 客户端已退出（pid 变了或没了）')
            break
    try:
        session.detach()
    except Exception:
        pass
    log('# done')
    return 0


if __name__ == '__main__':
    sys.exit(main())
