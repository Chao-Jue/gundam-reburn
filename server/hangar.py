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
    # 0xAC0304: unit record, weapon_count + weapon records, equipset_count.
    return unit_wire(unit) + struct.pack('<I', len(weapons)) + b''.join(
        weapon_wire(w) for w in weapons) + struct.pack('<I', 0)


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
