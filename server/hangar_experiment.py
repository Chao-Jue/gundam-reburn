"""Opt-in GM identity experiment. Assets use a separate experiment store; normal pilot/assets are untouched.

The resource group 01/01/0101 is user-confirmed GM. 777001 is our test
msma_id, intentionally different from candidate model ID 101010101.
Unmapped parameters below are placeholders, not recovered original stats.
"""
import copy
import json
import battlefield_bases
from pathlib import Path

MSMA_ID = 777001
MODEL_ID = 101010101
UNIQID = 777000000001
DECK_COST_CAPACITY = 1200  # local experiment budget, not recovered rank progression
ENERGY_CAPACITY = 100
SHIELD_ITEM_ID = 777104
SHIELD_HP = 990  # same cached GM Wiki revision103423 as the other reference stats



def _reference(name):
    return json.loads((Path(__file__).parent / 'reference' / name).read_text(encoding='utf-8'))['weapons']


def starter_definitions():
    """默认授予的三把武器：只有它们会写进新建机体的 weapons 列表。"""
    return _reference('gm_starter_weapons.json')


def test_definitions():
    """追加的测试武器：只进下载表，必须显式解锁。

    资源号均已在 decrypted 资源树里核对 icon 与 vra 同时存在；
    类别/动作只用原生枚举里已验证过的 SHOTGUN / WRESTLE / HAND_THROW。
    """
    return _reference('gm_test_weapons.json')


def all_definitions():
    return starter_definitions() + test_definitions()


def unlock_weapon(store, account, pilot_id, uniqid, item_id):
    """把一把已定义但未持有的武器写进机体记录并落盘。

    幂等：已持有返回 False。db_index 取该武器在 all_definitions 里的下标，
    与 msma_weapon_set 的下发顺序一致。
    """
    index = {w['item_id']: i for i, w in enumerate(all_definitions())}
    if item_id not in index:
        raise ValueError('weapon %d 不是已定义的测试武器' % item_id)
    return store.add_weapon(account, pilot_id, uniqid, item_id, index[item_id])


def lock_weapon(store, account, pilot_id, uniqid, item_id):
    """把武器退回未解锁状态（从持有列表移除，并清掉装备槽）。幂等。"""
    return store.remove_weapon(account, pilot_id, uniqid, item_id)


def store_equipset(store, account, pilot_id, uniqid, blob, slot=None):
    """「装备记忆」：保存 121B 装备组块，返回 (实际存档字节, 解出的可读条目)。"""
    return store.store_equipset(account, pilot_id, uniqid, blob, slot)


def delete_equipset(store, account, pilot_id, uniqid, slot):
    """「删除装备组合」。"""
    return store.remove_equipset(account, pilot_id, uniqid, slot)


def apply_equipset(store, account, pilot_id, uniqid, slot):
    """「换装」：把装备组套回机体。"""
    return store.apply_equipset(account, pilot_id, uniqid, slot)


def store_msset(store, account, pilot_id, blob):
    """「机体组」保存：一个 95B 机体组块。"""
    return store.store_msset(account, pilot_id, blob)


def msset_list(store, account, pilot_id):
    return store.mssets(account, pilot_id)


def category_of(weapon):
    """线上类别枚举；原生枚举没有 BEAM_SPRAYGUN，喷枪落到 SHOTGUN。"""
    return weapon.get('category') or ('SHOTGUN' if weapon['kind'] == 'BEAM_SPRAYGUN'
                                      else weapon['kind'])


ACTION_OF = {'BEAM_SPRAYGUN': 'GUN_SINGLE', 'WRESTLE': 'WRESTLE', 'HAND_THROW': 'HAND_THROW'}


def action_of(weapon):
    return weapon.get('action') or ACTION_OF[weapon['kind']]


def performance_templates(weapon):
    """Verified v5 panel conversions; Wiki values are reference balance."""
    a = weapon['attributes']
    result = [('POWER', 74, [int(a['威力']) // 10])]
    if '射程距离' in a:
        result.append(('RANGE', 77, [float(a['射程距离']) / 10]))
    if '装填性能' in a:
        result.append(('RELOAD', 88, [10 - float(a['装填性能']) / 100]))
    if '集弹性能' in a:
        # 55A650 reverses col2/3, both x100; UI (500-value)*2.
        spread = (1000 - float(a['集弹性能'])) / 200
        result.append(('STABILITY', 81, [spread, spread]))
    if '锁定' in a:
        # 55A6B0 x0.01, UI 7A3601 x1000.
        result.append(('LOCKON_CAM', 90, [float(a['锁定']) / 10]))
    return result


def csv_rows(rows):
    import csv
    import io
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\r\n')
    writer.writerows([['# GM experiment; incomplete native combat parameters'], ['#']])
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def weapon_tables(name):
    definitions = all_definitions()
    if name == 'develop/mechanic_weapon.csv':
        # Detail preview 0x7A6810 unconditionally reads ticket key2 bounds.
        # 0x548820 reads 20 alternating min/max columns, each multiplied by10.
        # 0x548CE0 -> 0x548AD0 parses col0 as a NAME; numeric "2" maps to0.
        # 1169A00 is CMechanicWeaponTable (DF89FC), download enum19.
        # mechanic_ticket.csv is enum21 MECHANIC_SUCCESS, a different table.
        # Conservative zero bounds until real ticket success/buildup rules exist.
        return csv_rows([['BUILDUP_GREATEST'] + [0] * 20])
    if name == 'develop/buildup_weapon.csv':
        # 0x53F080 col1 -> row+4; 0x7A2810 maps that byte to POWER UI bit.
        rows = []
        for w in definitions:
            row = [w['item_id']] + [0] * 20
            for col, attribute in ((1, '威力'), (2, '集弹性能'), (4, '装填性能'),
                                   (5, '锁定'), (6, '射程距离'), (10, '效果范围')):
                row[col] = int(attribute in w['attributes'])
            rows.append(row)
        return csv_rows(rows)
    if name == 'item/bullet.csv':
        # 53F1F0 reads through col31. UI metadata only: physical flight,
        # collision and effect resources remain unrecovered, not battle ready.
        rows = []
        for w in definitions:
            if '弹数' not in w['attributes']:
                continue
            row = [0] * 32
            row[0] = w['item_id']
            # 7A39D1: raw radius /1200 *10000 -> displayed effect range.
            row[11] = float(w['attributes'].get('效果范围', 0)) * 0.12
            # col24 optional special projectile enum: empty -> ordinary(0).
            row[24] = ''
            rows.append(row)
        return csv_rows(rows)
    if name == 'item/weapon_battle_detail.csv':
        # CMSMAWeaponBattleDetailTables: type, template name, integer power.
        # vt0xDF9194 -> 0x55A610 reads col2; 0x55E1C0 binds to +0x74C.
        rows = []
        for w in definitions:
            for kind, column, values in performance_templates(w):
                rows.append([kind, 'GM_WEAPON_%d_%s' % (w['item_id'], kind), *values])
        rows.append(['SHIELD', 'GM_SHIELD_HP', SHIELD_HP, 0])
        return csv_rows(rows)
    if name == 'item/item.csv':
        # Native 0x558560: id, number, name, description, category, u16, int, u16.
        return csv_rows([[w['item_id'], 0, w['name'], w['name'], 'WEAPON', 0, 0, 0]
                         for w in definitions] +
                        [[SHIELD_ITEM_ID, 0, '吉姆盾牌', '吉姆盾牌（参考耐久990）', 'WEAPON', 0, 0, 0]])
    if name == 'item/weapon_settings.csv':
        rows = []
        for w in definitions:
            # Native 0x55C3E0 reads through col 0x85. Empty strings are intentional:
            # resource, attack and balance templates are not yet recovered.
            row = [''] * 134
            row[0] = w['item_id']
            # 0x55C45D: col2 -> weapon+4. 0x558110 WEAPON branch
            # passes weapon+4 to 0xA317F0/0xA318F0 (d/s%08d.dds).
            # 资源号按本地 icon+vra 双存在核对过，属实验引用。
            row[2] = int(w['resource'])
            # 4E2570 selects weapon+4/+8/+C for state-dependent VRA loading.
            # Reuse the verified existing base model in alternate states until
            # distinct drawn/stowed variants are recovered. Not original poses.
            row[3] = row[4] = row[2]
            # Native enum55B240 has SHOTGUN, not BEAM_SPRAYGUN.
            row[21] = category_of(w)
            row[30] = action_of(w)
            if '弹数' in w['attributes']:
                row[101], row[102] = map(int, w['attributes']['弹数'].split('/'))
                row[68] = w['item_id']  # bullet table -> weapon+970, bound55E1C0
            # Native 0x55D36x: col 0x6D -> row+0x7C4 (WEIGHT).
            row[109] = int(w['attributes']['重量'])
            for kind, column, values in performance_templates(w):
                row[column] = 'GM_WEAPON_%d_%s' % (w['item_id'], kind)
            row[64] = w['item_id']  # buildup/visible-attribute group, +0x720
            rows.append(row)
        shield = [''] * 134
        shield[0] = SHIELD_ITEM_ID
        shield[2] = shield[3] = shield[4] = 12010101
        shield[21] = shield[30] = 'SHIELD'
        shield[97] = 'GM_SHIELD_HP'
        shield[109] = 0  # separate shield equipment, no invented weapon weight
        rows.append(shield)
        return csv_rows(rows)
    if name == 'msma/msma_weapon_set.csv':
        rows = []
        for w in definitions:
            # 0x551BC0 groups by col0, row+4=col2 item ID; row+0x14=col6 default.
            row = [0] * 29
            row[0], row[2] = MSMA_ID, w['item_id']
            row[4], row[5], row[6], row[28] = 'MAIN', category_of(w), 1, 'CHINA'
            rows.append(row)
        return csv_rows(rows)
    return None


def upgrade_unarmed_unit(unit):
    """Only migrate the previous untouched GM seed, preserving existing loadouts."""
    unit = copy.deepcopy(unit)
    if (unit.get('msma_id') == MSMA_ID and unit.get('uniqid') == UNIQID
            and not unit.get('gm_shield_revision')):
        if not unit.get('shield'):
            unit['shield'] = SHIELD_ITEM_ID
        unit['gm_shield_revision'] = 1
    if (unit.get('msma_id') == MSMA_ID and unit.get('uniqid') == UNIQID
            and not unit.get('weapons') and unit.get('equipped_weapons') == [0, 0, 0]):
        definitions = starter_definitions()
        unit['weapons'] = [{'item_id': w['item_id'], 'db_index': i}
                           for i, w in enumerate(definitions)]
        unit['equipped_weapons'] = [w['item_id'] for w in definitions]
    return unit


def csv_table(row):
    return ('# identity experiment; not original balance data\r\n#\r\n'
            + ','.join(str(value) for value in row) + '\r\n').encode('utf-8')


def table_body(name):
    name = name.replace('\\', '/').lstrip('/')
    if name in ('autoexec.cfg', 'autoexec_sv.cfg'):
        # Older reference config lacks the current client's ARGB UI keys (9EF860).
        # Explicit local experiment colors, not recovered official palette values.
        source = Path(__file__).resolve().parents[1] / 'GundamOnline_CHINA_已解密/decrypted/settings/autoexec.cfg'
        data = source.read_bytes()
        keys = {line.split(b',', 1)[0].strip() for line in data.splitlines()}
        # 9EF6A0 prefixes the registered UI keys with "wnd_" before lookup.
        for key, values in ((b'wnd_eff_ui_color', b'255,51,170,255'),
                            (b'wnd_zeon_ui_color', b'255,255,68,68')):
            if key not in keys:
                data += b'\r\n' + key + b',' + values + b',# local battle experiment\r\n'
        return data
    if name == 'msma/msma_settings.csv':
        # Current parser 0x54EF50: column 0 -> row+0, column 1 -> row+4.
        # 0x5DEB20 looks up msma_id, then copies row+4 to owned-unit+0xC.
        row = ['0'] * 92
        row[0], row[1] = MSMA_ID, MODEL_ID
        row[4], row[5], row[6] = 'RANK1', '吉姆（关联实验）', 'GM identity experiment'
        row[7], row[8] = 'ASSAULT_A', 'GM'
        # Native terrain UI 0x786Axx/0x7939xx reads +0x78/+0x80 together.
        row[9], row[10], row[11] = 1, 0, 1  # GM ground/space; no aquatic affinity
        # Native 0x54E2F0 resolves these names in CMSMABattleDetailTables.
        # Wiki reference balance, not recovered balance for this client.
        for column, key in ((56, 'RESPAWN_TIME'), (58, 'WARP_TIME'),
                            (60, 'COST'), (62, 'MAX_HP'), (64, 'ENERGY'),
                            (67, 'MOVE'), (73, 'BOOST_SPEED'),
                            (69, 'BOOST_GAUGEMAX'), (71, 'BOOST_GAUGEHEAL')):
            row[column] = 'GM_REF_' + key
        row[38] = MSMA_ID  # links the three default weapon-set entries
        # 54F3E1/54F3E9: col44 -> model definition+16C; 786D9B and
        # 792FB0 use this ID to resolve shield support and displayed durability.
        row[44] = SHIELD_ITEM_ID
        # 0x54EF50 col52 -> row+0xE8; 0x5DF940 names this field PAYLOAD.
        row[52] = 1450  # cached Wiki GM carrying capacity
        return csv_table(row) + (','.join(str(v) for v in battlefield_bases.character_row(row)) + '\r\n').encode('utf-8')
    if name == 'msma/msma_battle_detail.csv':
        # 0x9B1B30 -> 0x9AC5F0 dispatches col0; col1 is the key.
        # 0x55A610 reads scalar col2; 0x549780 reads eleven time values.
        rows = [('RESPAWN_TIME', *([50] * 11)), ('WARP_TIME', 10),
                ('COST', 200), ('MAX_HP', 3425),
                # 5497B0 parses two ints; first -> msma+A8 -> owned+14 capacity.
                # Second scalar's economic semantics are not yet recovered.
                ('ENERGY', ENERGY_CAPACITY, 0),
                # 0x54D130: MOVE * max(boost[0], boost[4]). UI 0x78CC79
                # scales by (1/1680)*200*10. Neutral ratios calibrate Wiki1004;
                # other acceleration parameters remain diagnostic zero values.
                ('MOVE', 1004 * 1680 / 2000),
                ('BOOST_SPEED', 1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
                ('BOOST_GAUGEMAX', 1000), ('BOOST_GAUGEHEAL', 200)]
        return (b'# Wiki reference subset; not original client balance\r\n#\r\n'
                + b''.join((','.join(map(str, (kind, 'GM_REF_' + kind, *values)))
                            + '\r\n').encode() for kind, *values in rows))
    if name == 'msma/msma_model.csv':
        # Model-parameter row 0x53FA30; unit scales are diagnostic placeholders.
        row = ['1'] * 32
        row[0] = MODEL_ID
        for index in (6, 12, 13, 14): row[index] = 0
        # 53FA30 column15 -> model+34 -> 47C370 -> A23120. A nonzero
        # value is a camera-distance override in deci-units, not a unit scale.
        # Zero uses the client's native default (550 for the default option).
        row[15] = 0
        base_model = battlefield_bases.model_row(row)
        # 477950 uses model+4 as the focus height; its no-parameter fallback
        # is 160. Use that native fallback for GM, not the diagnostic 1.
        # This is an experimental view parameter, not recovered balance data.
        row[1] = 160
        # Column14 -> model+32 -> 474670: owned actors require this flag
        # to enter the native visibility refresh rather than stay camera-hidden.
        row[14] = 1
        return csv_table(row) + (','.join(str(v) for v in base_model) + '\r\n').encode('utf-8')
    return weapon_tables(name)


def gm_unit():
    return upgrade_unarmed_unit({'uniqid': UNIQID, 'msma_id': MSMA_ID, 'nickname': '吉姆关联实验',
            'cost': 200, 'energy': 100, 'blueprint_grade': 'silver',
            # Controlled follow-up: seed slot 0 in both decks instead of two
            # empty decks. This tests the minimum-deck hypothesis, not a fix
            # for the still-unimplemented deck-change request.
            'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0], 'weapons': []})
