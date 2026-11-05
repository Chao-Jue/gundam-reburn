"""从日服 GOW wiki「各種検証」存档 HTML 提取可复算的数值表。

存档来自 gow.swiki.jp 的 2022-01-27 快照（Internet Archive）。这里只做两件事：
1. 把每个章节的表格抽成 JSON，保留原始行列，不做解释；
2. 从原文给出的公式/映射生成两份派生表：装填性能→秒、连射速度→发/秒。

**这些是日服 2022 年的实测值**，与国服 5.0.0.33 是否一致未验证；
派生表只用于给 weapon_settings 的数值列提供参考，不能当客户端权威数据。
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / 'server/reference/gow_swiki'


def clean(fragment):
    fragment = re.sub(r'<br\s*/?>', ' ', fragment)
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', fragment)).strip()


def cells(row):
    return [clean(c) for c in re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', row, re.S)]


def sections(html):
    """按 h2..h4 切段，返回 [(标题, 正文)]；标题和正文都保留原始片段。"""
    parts = re.split(r'(<h[2-4][^>]*>.*?</h[2-4]>)', html, flags=re.S)
    out = []
    for i in range(1, len(parts), 2):
        out.append((clean(parts[i]), parts[i + 1] if i + 1 < len(parts) else ''))
    return out


def parse_tables(html):
    """抽出所有非空表格：{section, rows}。rows 是纯文本二维数组。"""
    result = []
    for title, body in sections(html):
        for table in re.findall(r'<table.*?</table>', body, re.S):
            rows = [cells(r) for r in re.findall(r'<tr.*?</tr>', table, re.S)]
            rows = [r for r in rows if any(x for x in r)]
            if rows:
                result.append({'section': title, 'rows': rows})
    return result


def reload_seconds(stat):
    """（1000 − 装填性能）/ 100 = 秒。原文：1000 对应 0s，0 对应 10s，每 100 差 1 秒。"""
    return round((1000 - float(stat)) / 100.0, 2)


def shots_per_second(frames):
    """连射速度表里的「1発撃つフレーム」→ 发/秒（60FPS）。"""
    return round(60.0 / float(frames), 2) if frames else None


def reload_curve(tables):
    for table in tables:
        if table['section'] == 'リロード時間' and table['rows'][0][:2] == ['リロード値', 'リロード時間']:
            curve = []
            for row in table['rows'][1:]:
                try:
                    stat = int(row[0])
                    seconds = float(re.sub(r'[^0-9.]', '', row[1]))
                except (ValueError, IndexError):
                    continue
                curve.append({'reload_stat': stat, 'seconds': seconds,
                              'formula_seconds': reload_seconds(stat)})
            return curve
    return []


def rate_of_fire_curve(tables):
    for table in tables:
        header = table['rows'][0] if table['rows'] else []
        if table['section'] == '連射速度' and header[:2] == ['連射速度', '1発撃つフレーム']:
            curve = []
            for row in table['rows'][1:]:
                try:
                    span = re.findall(r'\d+', row[0])
                    frames = int(re.findall(r'\d+', row[1])[0])
                except (ValueError, IndexError):
                    continue
                if not span:
                    continue
                curve.append({'reload_stat_min': int(span[0]),
                              'reload_stat_max': int(span[-1]),
                              'frames_per_shot': frames,
                              'shots_per_second': shots_per_second(frames)})
            return curve
    return []


def bullet_speeds(tables):
    """各種武装弾速：日服具体武器的实测弹速（m/s），按武器名保留原文。"""
    out = []
    for table in tables:
        header = table['rows'][0] if table['rows'] else []
        if not header or '弾速[m/s]' not in header[2:3]:
            continue
        for row in table['rows'][1:]:
            if len(row) < 3:
                continue
            try:
                speed = float(re.sub(r'[^0-9.]', '', row[2]))
            except ValueError:
                continue
            out.append({'weapon': row[0], 'frames_to_impact': row[1], 'speed_mps': speed})
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--html', type=Path, required=True, help='存档的各種検証 HTML')
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    html = args.html.read_text('utf-8', errors='replace')
    tables = parse_tables(html)
    payload = {
        'source': 'https://web.archive.org/web/20220127142918/https://gow.swiki.jp/'
                  'index.php?%E5%90%84%E7%A8%AE%E6%A4%9C%E8%A8%BC',
        'snapshot_utc': '2022-01-27T14:29:18Z',
        'server': '日服（PS4/PC）；与国服 5.0.0.33 是否一致未验证',
        'note': '实测值，不是客户端权威数据；只作 weapon_settings 数值列参考。',
        'tables': tables,
        'derived': {
            'reload_curve': reload_curve(tables),
            'rate_of_fire_curve': rate_of_fire_curve(tables),
            'bullet_speeds_mps': bullet_speeds(tables),
        },
    }
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / 'various_tests_2022-01-27.json'
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), 'utf8')

    derived = payload['derived']
    print('表格 %d 个，章节 %d 个' % (len(tables), len({t['section'] for t in tables})))
    print('装填曲线 %d 点，连射曲线 %d 段，弹速 %d 条'
          % (len(derived['reload_curve']), len(derived['rate_of_fire_curve']),
             len(derived['bullet_speeds_mps'])))
    print('写出', target)


if __name__ == '__main__':
    main()
