"""Persistent owned units and the v5.0.0.33 hangar wire format.

Client unit/item IDs must come from verified downloaded definitions. Wiki IDs
are reference identifiers only. No starter unit is silently granted here.
"""
import copy
import json
from pathlib import Path
import struct
import threading

MSMA_WIRE_SIZE = 299  # offline execution of client reader 0xA96070
WEAPON_WIRE_SIZE = 30  # reader 0xA964D0
EQUIPSET_WIRE_SIZE = 121  # reader 0xA96750 / writer 0xA948C0

# 装备组（装备记忆）线上布局 —— 相对 121 字节块起点。
# 两个函数逐条对照得到：writer 0xA948C0 与 reader 0xA96750 的字段宽度完全一致。
EQUIPSET_FIELDS = (
    ('a', 0x00, 'u32'),        # 语义未定（实测像未初始化值），原样回存
    ('b', 0x04, 'u32'),
    ('slot', 0x08, 'u16'),     # 槽位；单击「装备记忆」实测为 0，待第二次采样确认
    ('weapons', 0x0A, '3u32'),  # 三个武器槽
    ('shield', 0x16, 'u32'),
    ('d', 0x1A, 'u32'),
    ('tail10', 0x1E, '10u32'),
    ('e', 0x46, 'u32'),
    ('f', 0x4A, 'u32'),
    ('name', 0x4E, 'char43'),
)
EQUIPSET_NAME_SIZE = 43
EQUIPSET_NAME_OFFSET = 0x4E
EQUIPSET_SLOT_OFFSET = 0x08


def equipset_count_limit():
    # 装备界面 4 格 × 2 页
    return 8


def decode_equipset(blob):
    """把 121 字节装备组块解成可读字典（保留原始字节）。"""
    if len(blob) != EQUIPSET_WIRE_SIZE:
        raise ValueError('equipset block must be %d bytes' % EQUIPSET_WIRE_SIZE)
    name = blob[EQUIPSET_NAME_OFFSET:EQUIPSET_NAME_OFFSET + EQUIPSET_NAME_SIZE]
    name = name.split(b'\x00', 1)[0].decode('utf-8', 'ignore')
    return {
        'slot': struct.unpack_from('<H', blob, EQUIPSET_SLOT_OFFSET)[0],
        'name': name,
        'weapons': list(struct.unpack_from('<3I', blob, 0x0A)),
        'shield': struct.unpack_from('<I', blob, 0x16)[0],
        'raw': blob.hex(),
    }


def encode_equipset(entry):
    """把存档里的装备组条目还原成 121 字节。优先用 raw。"""
    raw = entry.get('raw')
    if raw:
        blob = bytes.fromhex(raw)
        if len(blob) != EQUIPSET_WIRE_SIZE:
            raise ValueError('stored equipset raw is not %d bytes' % EQUIPSET_WIRE_SIZE)
        return blob
    blob = bytearray(EQUIPSET_WIRE_SIZE)
    struct.pack_into('<H', blob, EQUIPSET_SLOT_OFFSET, int(entry.get('slot', 0)))
    struct.pack_into('<3I', blob, 0x0A, *[int(x) for x in entry.get('weapons', [0, 0, 0])][:3])
    struct.pack_into('<I', blob, 0x16, int(entry.get('shield', 0)))
    name = entry.get('name', '').encode('utf-8')[:EQUIPSET_NAME_SIZE]
    blob[EQUIPSET_NAME_OFFSET:EQUIPSET_NAME_OFFSET + len(name)] = name
    return bytes(blob)


def weapon_wire(weapon):
    values = weapon.get('buildup_values', [0] * 10)
    if len(values) != 10:
        raise ValueError('weapon needs ten buildup values')
    return struct.pack('<IHH10HBB', weapon['item_id'], weapon.get('db_index', 0),
                       weapon.get('buildup_count', 0), *values,
                       weapon.get('ticket_success', 0), weapon.get('ticket_greatest', 0))


def unit_wire(unit):
    data = bytearray(MSMA_WIRE_SIZE)
    struct.pack_into('<QIII', data, 0, unit['uniqid'], unit['msma_id'],
                     unit.get('tm_sec', 0), unit.get('tm_usec', 0))
    nickname = unit.get('nickname', '').encode('utf-8')[:60].decode('utf-8', 'ignore').encode('utf-8')
    data[20:20 + len(nickname)] = nickname
    struct.pack_into('<IIB', data, 81, unit.get('energy', 100), unit.get('decal', 0), unit.get('color', 0))
    data[90:92] = bytes(unit.get('deckslots', [255, 255]))
    struct.pack_into('<II3I', data, 94, unit.get('cost', 0), unit.get('mission_cost', 0),
                     *unit.get('equipped_weapons', [0, 0, 0]))
    struct.pack_into('<II', data, 114, unit.get('shield', 0), unit.get('special', 0))
    struct.pack_into('<H', data, 190, unit.get('buildup_count', 0))
    struct.pack_into('<7H', data, 192, *unit.get('up_params', [0] * 7))
    struct.pack_into('<7H', data, 206, *unit.get('develop_params', [0] * 7))
    struct.pack_into('<HI', data, 290, unit.get('msbits', 0), unit.get('unlocked_colors', 1))
    data[298] = int(unit.get('favorite', False))
    return bytes(data)


def unit_add_body(unit):
    weapons = unit.get('weapons', [])
    if len(weapons) > 30:
        raise ValueError('current client accepts at most 30 weapon records per unit')
    equipsets = unit.get('equipsets', [])
    if len(equipsets) > equipset_count_limit():
        raise ValueError('too many equipsets for one unit')
    # 0xAC0304: unit record, weapon_count + weapon records,
    #            equipset_count + equipset records (each 121B, reader 0xA96750).
    return (unit_wire(unit) + struct.pack('<I', len(weapons))
            + b''.join(weapon_wire(w) for w in weapons)
            + struct.pack('<I', len(equipsets))
            + b''.join(encode_equipset(e) for e in equipsets))


class HangarStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()

    @staticmethod
    def key(account, pilot_id):
        return json.dumps([str(account), int(pilot_id)], ensure_ascii=False, separators=(',', ':'))

    def _read(self):
        if not self.path.exists():
            return {'schema_version': 1, 'pilots': {}}
        data = json.loads(self.path.read_text(encoding='utf-8'))
        if data.get('schema_version') != 1:
            raise ValueError('unsupported hangar schema')
        return data

    def units(self, account, pilot_id):
        with self.lock:
            return copy.deepcopy(self._read()['pilots'].get(self.key(account, pilot_id), []))

    def replace_units(self, account, pilot_id, units):
        # Validate wire ranges/array lengths before touching the persisted state.
        ids = set()
        for unit in units:
            if unit['uniqid'] in ids or unit['uniqid'] <= 0 or unit['msma_id'] <= 0:
                raise ValueError('unit IDs must be positive and instance IDs unique')
            ids.add(unit['uniqid'])
            if unit.get('blueprint_grade') not in (None, 'gold', 'silver', 'rental'):
                raise ValueError('invalid blueprint grade')
            if len(unit.get('equipped_weapons', [])) != 3:
                raise ValueError('unit must have three weapon slots')
            allowed = {w['item_id'] for w in unit.get('weapons', [])} | {0}
            if not set(unit['equipped_weapons']) <= allowed:
                raise ValueError('equipped weapon is not owned by this unit')
            unit_add_body(unit)
        with self.lock:
            data = self._read()
            data['pilots'][self.key(account, pilot_id)] = copy.deepcopy(units)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + '.tmp')
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            temporary.replace(self.path)

    def add_weapon(self, account, pilot_id, uniqid, item_id, db_index=0):
        """解锁一把武器：写进机体 weapons 列表并落盘。

        幂等 —— 已持有直接返回 False，不产生写入。
        只做存储层校验；"这把武器在不在本机型的可装备集合里" 由调用方判定。
        """
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None:
                raise ValueError('unit does not exist')
            if any(w['item_id'] == item_id for w in unit.get('weapons', [])):
                return False
            if len(unit.get('weapons', [])) >= 30:
                # 0xAC0304 / unit_add_body: current client accepts at most 30.
                raise ValueError('unit weapon list is full')
            unit.setdefault('weapons', []).append(
                {'item_id': int(item_id), 'db_index': int(db_index)})
            self.replace_units(account, pilot_id, units)
        return True

    def remove_weapon(self, account, pilot_id, uniqid, item_id):
        """退回未解锁：从机体 weapons 列表移除，并清掉引用它的装备槽。

        幂等 —— 本来就没有直接返回 False。装备槽必须一起清，否则
        replace_units 会因为 equipped 不在 owned 里而拒绝写入。
        """
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None:
                raise ValueError('unit does not exist')
            weapons = unit.get('weapons', [])
            if not any(w['item_id'] == item_id for w in weapons):
                return False
            unit['weapons'] = [w for w in weapons if w['item_id'] != item_id]
            unit['equipped_weapons'] = [0 if slot == item_id else slot
                                        for slot in unit.get('equipped_weapons', [0, 0, 0])]
            self.replace_units(account, pilot_id, units)
        return True

    def change_weapon(self, account, pilot_id, request):
        # Current sender 0xADFC00 reserves 18 bytes incl opcode, writes:
        # uniqid u64, slot u16, item_id u32. Actual body is 14 bytes.
        if len(request) != 14:
            raise ValueError('weapon change requires 14 body bytes')
        uniqid, slot, item_id = struct.unpack('<QHI', request)
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None or slot >= 3:
                raise ValueError('unit or weapon slot does not exist')
            if item_id and item_id not in {w['item_id'] for w in unit.get('weapons', [])}:
                raise ValueError('weapon is not owned by this unit')
            unit['equipped_weapons'][slot] = item_id
            self.replace_units(account, pilot_id, units)
        # 0xACCE4F: result i32, uniqid u64, slot u16, item_id u32.
        return struct.pack('<iQHI', 0, uniqid, slot, item_id)

    def store_equipset(self, account, pilot_id, uniqid, blob, slot=None):
        """「装备记忆」：把 121 字节装备组块存进机体的 equipsets 并落盘。

        槽位取 blob 里的 u16(+0x08)；调用方可以显式覆盖。
        同槽位覆盖写。返回实际保存的 121 字节（回包要原样回给客户端）。
        """
        if len(blob) != EQUIPSET_WIRE_SIZE:
            raise ValueError('equipset block must be %d bytes' % EQUIPSET_WIRE_SIZE)
        entry = decode_equipset(blob)
        index = entry['slot'] if slot is None else int(slot)
        if not 0 <= index < equipset_count_limit():
            raise ValueError('equipset slot out of range')
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None:
                raise ValueError('unit does not exist')
            entry['slot'] = index
            stored = bytearray(blob)
            struct.pack_into('<H', stored, EQUIPSET_SLOT_OFFSET, index)
            entry['raw'] = bytes(stored).hex()
            sets = [e for e in unit.get('equipsets', []) if e.get('slot') != index]
            sets.append(entry)
            sets.sort(key=lambda e: e.get('slot', 0))
            unit['equipsets'] = sets
            self.replace_units(account, pilot_id, units)
        return bytes(stored), entry

    def remove_equipset(self, account, pilot_id, uniqid, slot):
        """删除一个装备组；不存在时返回 False。"""
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None:
                raise ValueError('unit does not exist')
            sets = unit.get('equipsets', [])
            kept = [e for e in sets if e.get('slot') != int(slot)]
            if len(kept) == len(sets):
                return False
            unit['equipsets'] = kept
            self.replace_units(account, pilot_id, units)
        return True

    def apply_equipset(self, account, pilot_id, uniqid, slot):
        """「换装」：把某个装备组套到机体当前装备上。"""
        with self.lock:
            units = self.units(account, pilot_id)
            unit = next((u for u in units if u['uniqid'] == uniqid), None)
            if unit is None:
                raise ValueError('unit does not exist')
            entry = next((e for e in unit.get('equipsets', [])
                          if e.get('slot') == int(slot)), None)
            if entry is None:
                raise ValueError('equipset does not exist')
            owned = {w['item_id'] for w in unit.get('weapons', [])}
            weapons = list(entry.get('weapons', []))[:3]
            if len(weapons) != 3:
                raise ValueError('equipset must carry three weapon slots')
            if not set(weapons) <= (owned | {0}):
                raise ValueError('equipset references a weapon this unit does not own')
            unit['equipped_weapons'] = weapons
            if entry.get('shield') is not None:
                unit['shield'] = entry['shield']
            self.replace_units(account, pilot_id, units)
        return entry

