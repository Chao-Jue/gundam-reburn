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
GM_RETURN_SECONDS = 10  # archived2022 return table: base GM performance682 ->10s; no upgrade mapping claim



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
    if name == 'item/wrestle.csv':
        rows = []
        for w in definitions:
            for field in ('melee_presentation', 'melee_dash_presentation'):
                presentation = w.get(field)
                if not presentation:
                    continue
                # 53DEB0: col8 -> row+14 (*0.001), read as seconds by 4D8E50;
                # col27 -> row+64 -> move+67C -> class*1000 + base motion.
                # Physical values below are a local collision candidate, not
                # recovered GM balance or animation timing.
                row = [0] * 31
                row[0] = presentation['attack_id']
                row[7] = row[17] = row[28] = row[29] = ''
                row[8] = presentation['duration_ms']
                row[27] = presentation['base_motion']
                # CSV17 -> atk+38 -> 4791E0 mode3 resolves the active weapon.
                # 47F580 consumes atk+40..48 as box half-extents, +4C..54
                # as local offset. 53DEB0 halves CSV18..20. Zero extents
                # cannot intersect the target in 6338D0's box sweep.
                row[17] = 'ACTIVE_WEAPON'
                # PP_02_001_01/saber_body -> PM_02_001_01 extends along
                # local +X, not +Z. Apply hilt s_shot01 (Y16.589, X/Z
                # scale1.048612) and effect Z=-10: blade X reaches140.65.
                # Center69/16.6/-10.5 with half83/15/15 covers the blade
                # rotation envelope plus a small experimental margin.
                row[18:21] = [166, 30, 30]
                row[21:24] = [69, 16.6, -10.5]
                row[24] = 1  # center on the offset; avoid extra axis extension
                # 53DEB0 CSV25 *100 -> atk+5C; 4D8E50 divides this
                # distance by duration -> controller+A80 forward speed.
                # Short 4m local dash candidate, not recovered GM balance
                # or a proven deceleration curve. Normal swings stay still.
                row[25] = 4 if field == 'melee_dash_presentation' else 0
                # A38FD0 event3 reads atk+24/+28 (CSV12/13) as the
                # collision window; 4BC743 skips 6338D0 for a zero window.
                # User-requested full action window, in CSV milliseconds.
                # The weapon-following box covers the reference blade core;
                # server swing-scoped dedup still limits each target to one hit.
                row[12] = 0
                row[13] = presentation['duration_ms']
                row[30] = 1  # event3's atk+A0 window-control value
                rows.append(row)
        return csv_rows(rows)
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
        # 53F1F0 reads through col31. Presentation speed below is an explicit
        # local prototype; collision/damage parameters remain unrecovered.
        rows = []
        for w in definitions:
            if '弹数' not in w['attributes']:
                continue
            row = [0] * 32
            row[0] = w['item_id']
            if action_of(w) == 'HAND_THROW':
                # Local lob-speed tuning (world units/second), not recovered
                # GM balance. 53F1F0 CSV5 -> bullet+0C -> 505BD0 velocity.
                # 8000 hid native980 gravity curvature;1800 preserves the
                # native upward bias/gravity and makes the arc observable.
                row[5] = 1800
            if w.get('projectile_presentation'):
                # 53F239..53F27E parses the literal ON into bullet+4.
                # 4EC9D0 requires it before 4EBB70 reports an actor hit;
                # numeric 1 is also false. Enable only the experimental guns.
                row[3] = 'ON'
                # col5 -> bullet+0C: native53F110 divides distance by speed.
                row[5] = w['projectile_presentation']['speed']
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
            # 55C3E0 col11 -> definition+20 -> 4E1F00. Zero selects a
            # non-rendering base object (CB5ECC); a socket selects CB5E54.
            # GM DXG contains S_wpn_01 under T_R_Hand. Experimental mount,
            # not a recovered original drawn/stowed weapon configuration.
            row[11] = 1
            # CSV13 -> 55AF70 -> definition+28 -> 50A900 joint route.
            # Empty selects route0 (head/spine), even while 3101 holds the gun.
            # GM ONEHAND route2 includes right upper arm/spine. This is separate
            # from CSV15's animation group and only activates in aiming states.
            row[13] = w.get('aim_category', '')
            # 55B060: blank -> FFFFFFFF, then 48E710 uses class*1000+motion.
            # Explicit experimental pose candidates may select native ranged
            # groups with existing GM aim clips (3101/8101). Preserve COMMON
            # for throwables; class selection does not restore attack timing.
            row[15] = w.get('motion_class') or ('WRESTLE' if w['kind'] == 'WRESTLE' else 'COMMON')
            # Native enum55B240 has SHOTGUN, not BEAM_SPRAYGUN.
            row[21] = category_of(w)
            row[30] = action_of(w)
            if row[30] == 'HAND_THROW':
                # 49B180 uses CSV7/8 to select the throw-origin mount. With
                # no s_shot sockets in the grenade it falls back to the body's
                # S_wpn_NN. Search the same right-hand mount as the held model.
                row[7], row[8] = row[11], 0
                # Experimental one-grenade release. 4D74AC reads +7B0:
                # zero skips both local creation and the 7C0C request loop.
                # This only opens release; fuse/physics/replies remain separate.
                row[103], row[104] = 1, 1
                # Experimental model/trail candidate verified in live fx.hed,
                # including its geometry/texture dependencies. The decrypted
                # tree's _31 variant is absent from this client's archive and
                # enters its failed-path cache, aborting 4ED990 initialization.
                # Availability is not original GM attribution or render proof.
                row[46], row[47] = '01/PP_01_011_01.vra', 1
                # 4F2520 normal impact consumes CSV48/49 (+23C/+290).
                # Generic explosion and image dependencies are in live fx.hed.
                # Experimental presentation, no original fuse or damage claim.
                row[48], row[49] = '03/PP_03_001_01.vra', 1
            if w.get('projectile_presentation'):
                presentation = w['projectile_presentation']
                # CSV33/34 -> definition+814 bits1/2. Native505850
                # skips 4EC9A0 actor-hit dispatch when bit2 is absent.
                row[33], row[34] = 1, 1
                # CSV7/8 -> +18/+1C: 49B180 searches S_wpn_NN for
                # the weapon's shot sockets. Zero searches S_wpn_00 and
                # falls back to the actor root. End0 means start only.
                row[7], row[8] = row[11], 0
                # Native4F0F10 muzzle FX +134 / scale+188; 4ED190 uses
                # the moving projectile FX +1E4 / scale+238.
                row[42], row[43] = presentation['muzzle_effect'], presentation['scale']
                row[46], row[47] = presentation['projectile_effect'], presentation['scale']
                # col103 -> +7AC ammo cost; col104 -> protected +7B0.
                # Native4F33F0 skips the entire spawn loop when count is0.
                row[103], row[104] = 1, presentation['count']
            if w.get('attached_effect'):
                # 55C3E0 col60/62 -> wide-string arrays +528/+624;
                # 4E2A40 selects these two states then 4E20A0 loads the FX.
                # 5440D0 prepends fx/ after CSV path normalization: the token
                # must be relative to fx/, or it resolves to fx/fx/... .
                # The chosen saber FX targets the hilt's existing s_shot01.
                row[60] = row[62] = w['attached_effect']
            if w.get('melee_presentation'):
                # CSV39/40 -> impact path/scale (+D8/+F4), selected by
                # 4A5BC0 bit1. CSV39 goes through5440D0, so use a token
                # relative to fx/. CSV37/38 belong to the bit0 shield path.
                # Slashing candidate, not original GM attribution.
                row[39], row[40] = '03/PP_03_004_01.vra', 1
                # 4BC8A0 selects +734 normally and +738 for boost predicates.
                # 55C3E0 maps col69/70 and one-segment counts col113/114.
                row[69] = w['melee_presentation']['attack_id']
                row[113] = 1
                row[70] = w['melee_dash_presentation']['attack_id']
                row[114] = 1
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
        # Existing GM S_wpn_04 socket (T_L_Hand); experimental shield mount.
        shield[11] = 4
        # 55C51A adds1 to col14: use overlay2, separate from weapon1.
        # Experimental SHIELD2=31 candidate: 31101 references only existing
        # GM left-arm/spine/head bones; old30101 includes absent UpperArm2z.
        # This is a candidate for the prior sideways pose. Attack blending
        # and recovery still require client validation; keep socket4 fixed.
        shield[14] = 1
        shield[15] = 'SHIELD2'
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
                            (b'wnd_zeon_ui_color', b'255,255,68,68'),
                            # 9F4540 building_rate -> move defaults+90;
                            # 49112E/49A647 ->50D040 physics+68. Missing
                            # key retains0.1: 50D100 scales gravity/impulse
                            # displacement to one tenth. Explicit experiment
                            # neutral1; not recovered official balance.
                            (b'move_building_rate', b'1.0')):
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
        row[79] = 'GM_EXP_JUMP'  # independent current-native JUMP profile, not BOOST_SPEED
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
        rows = [('RESPAWN_TIME', *([50] * 11)), ('WARP_TIME', GM_RETURN_SECONDS),
                ('COST', 200), ('MAX_HP', 3425),
                # 5497B0 parses two ints; first -> msma+A8 -> owned+14 capacity.
                # Second scalar's economic semantics are not yet recovered.
                ('ENERGY', ENERGY_CAPACITY, 0),
                # 0x54D130: MOVE * max(boost[0], boost[4]). UI 0x78CC79
                # scales by (1/1680)*200*10. Neutral ratios calibrate Wiki1004;
                # other acceleration parameters remain diagnostic zero values.
                ('MOVE', 1004 * 1680 / 2000),
                # 54E2F0 values[7:9] -> +110/+114; 4DE520 uses these
                # as directional speed multipliers. Zero suppresses side/rear
                # boost. Neutral 1 is experimental, not original GM balance.
                # Values[2]/[5] -> +FC/+108, integer costs consumed by
                # 4E3500/4E3540. 100 is a local experiment cost, not
                # recovered original GM balance or a proven duration.
                ('BOOST_SPEED', 1, 0, 100, 0, 1, 100, 0, 1, 1, 0),
                ('BOOST_GAUGEMAX', 1000), ('BOOST_GAUGEHEAL', 200),
                # 5498A0 has12 mixed fields, 54E2F0 -> +11C..14C.
                # Explicit ground-jump experiment, not recovered GM balance:
                # ascent time2s; takeoff preparation~.133s; combined-boost
                # ascent ratio1; two phase durations.15s; initial/ongoing
                # costs100; upward speed600cm/s; post-ascent descent50cm/s;
                # hover cost100; landing wait.15s; ordinary gravity mode0.
                # Missing profile had velocity0 and expired on first tick.
                ('JUMP', 2, 0.133333333, 1, 0.15, 100, 0.15, 600, 100, 50, 100, 0.15, 0)]
        return (b'# Wiki reference subset; not original client balance\r\n#\r\n'
                + b''.join((','.join(map(str, (kind, ('GM_EXP_' if kind == 'JUMP' else 'GM_REF_') + kind, *values)))
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
        # 53FA30 interleaves CSV16..23/24..31 into model+38..74.
        # 484B20 chooses these per S_vnr socket and requests fx category3.
        # The old placeholder1 has no category3 row. Local blue-small
        # candidates: sustained/ignition, and their underwater variants;
        # not a recovered original GM effect-size or special-mode mapping.
        thrusters = [201, 208, 214, 220, 201, 208, 214, 220]
        row[16:32] = thrusters + thrusters
        # 477950 uses model+4 as camera focus height, scaled by the render
        # model. Raise the experimental GM view from160 to220 so its body
        # obstructs less of the forward view. This is user-requested framing.
        row[1] = 220
        # 53FA30 CSV2 -> model+8; 47EAE0 uses it for the target center
        # (47EB90 fallback). The diagnostic 1 puts it at ankle height.
        # Use the native missing-row fallback 80, not recovered GM balance.
        row[2] = 80
        # 53FA30 CSV5 -> model+18. 4958A0 uses this for visual stair
        # compensation; placeholder1 drains its offset at only5cm/s,
        # leaving the rendered body floating above the collision floor.
        # Zero takes the native no-compensation branch. Preserve collision
        # and free-fall physics rather than invent an original stair height.
        row[5] = 0
        # CSV11 -> model+2C -> physics mass (4910E1/50CEC0).
        # 4DE430 hands off cm/s as impulse *100; 50D100 integrates it
        # with fixed1/60 then divides by mass. Preserve velocity in m/s:
        # mass =100 (handoff) *100 (cm/m) /60. Placeholder1 launched
        # a short600cm/s jump at1000m/s. This is a neutral experimental
        # conversion mass, not recovered GM weight; gravity still cancels mass.
        row[11] = 10000 / 60
        # Column14 -> model+32 -> 474670: owned actors require this flag
        # to enter the native visibility refresh rather than stay camera-hidden.
        row[14] = 1
        # 53FA30 col45 -> model+10C; 48CC30 mode2 selects the native
        # non-looping start2 then half-steps3/4. Missing col45 parsed as0
        # loops only3, whose end does not join its own start. Keep bases
        # on their existing row and let the client advance its own gait.
        row.extend(['0'] * (49 - len(row)))
        # 53FD3E CSV44 bool -> model+108; 4CDC60 requires it before
        # return entry4C5AB0 can request the native ground crouch posture.
        row[44] = 1
        row[45] = 2
        # 53FD96..53FDB8 CSV48 -> model+115. 633CAA requires it to
        # collect this target's render collision shapes for melee overlap.
        row[48] = 1
        return csv_table(row) + (','.join(str(v) for v in base_model) + '\r\n').encode('utf-8')
    return weapon_tables(name)


def gm_unit():
    return upgrade_unarmed_unit({'uniqid': UNIQID, 'msma_id': MSMA_ID, 'nickname': '吉姆关联实验',
            'cost': 200, 'energy': 100, 'blueprint_grade': 'silver',
            # Controlled follow-up: seed slot 0 in both decks instead of two
            # empty decks. This tests the minimum-deck hypothesis, not a fix
            # for the still-unimplemented deck-change request.
            'deckslots': [0, 0], 'equipped_weapons': [0, 0, 0], 'weapons': []})
