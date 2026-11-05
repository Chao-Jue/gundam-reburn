"""Local single-pilot preparation rooms and initial scene loading; no combat simulation.

Uses the formal xwar booking path and the current native battle protocol.
The caller supplies the existing encrypted transport and validated pilot records.
"""
from dataclasses import dataclass, field
import secrets
import struct
import time
import json
from pathlib import Path
from functools import lru_cache

import xwar_entry
import battlefield_bases
import battle_entities
import training_target

MISSION_ID = xwar_entry.PREPARATION_MISSION_ID
MAP_ID = 100102
ROOM_NAME = 'Local preparation room'
DEPLOYMENT_SECONDS = 60
BASE_ENTITY_START = 100  # Server-owned fixed-base IDs, separate from native local-only IDs.


@lru_cache(maxsize=1)
def experimental_weapon_kinds():
    from hangar_experiment import all_definitions
    return {w['item_id']: w['kind'] for w in all_definitions()}


@lru_cache(maxsize=1)
def experimental_melee_presentations():
    from hangar_experiment import all_definitions
    result = {}
    for w in all_definitions():
        normal = w.get('melee_presentation')
        if normal:
            actions = {0: normal, normal['attack_id']: normal}
            dash = w.get('melee_dash_presentation')
            if dash:
                actions[dash['attack_id']] = dash
            result[w['item_id']] = actions
    return result


@lru_cache(maxsize=1)
def deployment_points():
    data = json.loads((Path(__file__).parent / 'reference/odessa_home_bases.json').read_text(encoding='utf-8'))
    return tuple(sorted(((p['team'], tuple(p['position_cm'])) for p in data['points']), key=lambda p: p[0]))


def deployment_post_body(index, team, position):
    # A5EE80: type/team/troops/name[13]/gauge/chara/position[3]/direction/cmdr/group.
    # Map resources use cm; game_begin advertises pos_factor=100.
    xyz = [round(value / 100) for value in position]
    ordinal = sum(t == team for t, _ in deployment_points()[:index])
    name = chr(ord('A' if team == 0 else 'X') + ordinal).encode().ljust(13, b'\0')
    # Network 717D creates the actual base with letter/permission and map attachment.
    # A nonzero local-only character here would create an extra incomplete actor.
    return struct.pack('<IHH13sII3hHB I', 0, team, team, name, 10000,
                       0, *xyz, 0, 0, 0)


def deployment_post_states_body():
    """D1B3/A5EF90: positional states for the posts defined by game_begin."""
    points = deployment_points()
    return (struct.pack('<I', len(points))
            + b''.join(struct.pack('<HHIIBBBBB', team, team,
                                   10000 if team == 0 else 0,
                                   10000 if team == 1 else 0,
                                   1, 0, 1, 0, 0)  # visible, unlocked; type 2 requires keep (42D350)
                       for team, _ in points))


def countdown_body(seconds):
    """6A8D/A73151: seconds u32 -> game+24FDC float (42FC00)."""
    if not isinstance(seconds, int) or not 0 <= seconds <= 3600:
        raise ValueError('preparation countdown must be 0..3600 seconds')
    return struct.pack('<I', seconds)


def prestart_body(seconds, ms_index=None, post=0xffff, base_entity=0xffff):
    # 640D arrays describe member spawn locations: 0 none / 1 post / 2 stronghold.
    # The first array is NOT a mech index (4407E0 counts these spawn kinds).
    if ms_index is None:
        return countdown_body(seconds) + bytes(16)
    kind = 2 if base_entity != 0xffff else (1 if post != 0xffff else 0)
    return (countdown_body(seconds) + struct.pack('<IB', 1, kind)
            + struct.pack('<IH', 1, post) + struct.pack('<IH', 1, 0xffff)
            + struct.pack('<IH', 1, base_entity))


def mission_progress_body(prestart=True):
    offset = 8 + len(ROOM_NAME) + 1 + struct.calcsize('<4IBI4B') + 34
    progress = bytearray(authenticate_body()[offset:offset + 46])
    progress[21] = int(prestart)
    return bytes(progress)


def auth_identity(body):
    # Native A85A50: four u32, NUL ticket (<=40B), one comeback byte.
    if not 18 <= len(body) <= 58 or body[-2] != 0 or body[-1] not in (0, 1):
        return None
    ticket = body[16:-2]
    if not ticket or b'\0' in ticket:
        return None
    try:
        return (*struct.unpack_from('<4I', body), ticket.decode('ascii'), body[-1])
    except UnicodeError:
        return None


def authenticate_body(room_id=0, *, result=0, team=0):
    # Current A7A8B1..A7ABFF: no reference-version is_rankerbattle u32.
    # Config A5EC90 = 34B, progress A5ED60 = 46B, extra A5F560 = 514B.
    config = struct.pack('<HIIHIIIHII', 0, 10000, 0, 1, 10000, 0, 0, 0, 1, 1)
    progress = struct.pack('<4I2H2B6I', 1200000, 0, 10000, 10000, 100, 100,
                           0, 1, 0, 0, 0, 0, 0, 0)
    return (struct.pack('<II', result & 0xffffffff, room_id) + ROOM_NAME.encode('ascii') + b'\0'
            + struct.pack('<4IBI4B', MISSION_ID, 0, 0xffffffff, MAP_ID, 0, 0, 0, 0, team, 0)
            + config + progress + struct.pack('<HBB', 0, 0, 0) + bytes(514))


def member_body(record, world_id, *, team=0, stat=0, member_index=0):
    if len(record) != 157:
        raise ValueError('battle pilot record must be exactly 157 bytes')
    return (struct.pack('<BBI', team, record[29], world_id) + record
            + struct.pack('<I4BII', stat, 0, 0, member_index, 0, 0, 0))


def game_begin_body():
    """Current A6684E..A66CA6 scene initialization and static deployment posts."""
    auth = authenticate_body()
    offset = 8 + len(ROOM_NAME) + 1 + struct.calcsize('<4IBI4B')
    config_progress = auth[offset:offset + 80]
    return (struct.pack('<6I2B5I', 100, 100, 100, MAP_ID, 0, 1200000,
                        0, 0, MISSION_ID, 0, 0, 0, 0)
            + config_progress + struct.pack('<I', len(deployment_points()))
            + b''.join(deployment_post_body(i, team, xyz)
                       for i, (team, xyz) in enumerate(deployment_points()))
            + bytes(4)  # map gimmicks are not implemented
            + bytes(14) + bytes(4))  # one BGM description, zero mission units


def spawn_unit_body(unit, deck_index):
    """A5E300 battle spawn record, distinct from the 299B hangar record."""
    weapons = unit.get('equipped_weapons', [0, 0, 0])
    if len(weapons) != 3:
        raise ValueError('spawn unit requires three weapon slots')
    return (struct.pack('<QIII2BIBIHHI7H', unit['uniqid'], unit['msma_id'],
                        unit.get('crew_msma_id', 0), unit.get('decal', 0),
                        unit.get('color', 0), deck_index, unit.get('cost', 0), 0,
                        unit.get('energy', 100), 0, 0, unit.get('special', 0), *([0] * 7))
            + struct.pack('<5I', *weapons, unit.get('shield', 0), unit.get('special', 0))
            + bytes(42) + bytes(48) + struct.pack('<2BI2H2B', 0, 0, 0, 0, 0, 0, 0))


def base_entity_replies(reservation):
    replies = []
    for i, (team, position) in enumerate(deployment_points()):
        ordinal = sum(t == team for t, _ in deployment_points()[:i])
        base = {'uniqid': 900000000 + i, 'msma_id': battlefield_bases.MSMA_ID}
        replies.append((0x717D, battle_entities.appear_body(spawn_unit_body(base, 255),
                        BASE_ENTITY_START + i, position, team=team, troops=team,
                        # 44E120 resolves world=0 to a vacant member slot. Bases are
                        # unowned world actors, never extra entities owned by the human.
                        world_id=0, pilot_id=0, letter=ordinal)))
    return replies


@dataclass
class Reservation:
    account: str
    pilot_id: int
    user_id: int
    world_id: int
    record: bytes
    room: xwar_entry.BattleRoom
    expires_at: float
    connected: bool = False
    stat: int = 0
    started: bool = False
    start_at: float | None = None
    deployment_at: float | None = None
    round_active: bool = False
    selected_index: int | None = None
    selected_post: int | None = None
    selected_entity: int = 0xffff
    deployment_available: bool = False
    entities_ready: bool = False
    bases_sent: bool = False
    spawned_weapon_ids: tuple = ()
    active_weapon_index: int = 0
    next_grenade_id: int = 1
    # Presentation only: issued item and expiry, not authoritative hit state.
    pending_grenades: dict = field(default_factory=dict)
    training_target: object | None = None


class LocalBattleBackend:
    def __init__(self, queue, host, port, world_id=1, user_id_for_account=None, clock=time.monotonic,
                 countdown_seconds=None):
        self.queue = queue
        self.host = host
        self.port = port
        self.world_id = world_id
        self.user_id_for_account = user_id_for_account or (lambda account: 1)
        self.clock = clock
        self.reservations = {}
        self.next_room_id = 10000
        if countdown_seconds is not None:
            countdown_body(countdown_seconds)
        self.countdown_seconds = countdown_seconds
        self.units_for_pilot = lambda account, pilot: []
        self.training_targets_enabled = False

    def reserve(self, account, pilot_id, record):
        if len(record) != 157 or struct.unpack_from('<I', record)[0] != pilot_id or record[29] not in (0, 1):
            return None
        key = (str(account), int(pilot_id))
        with self.queue.lock:
            pending = self.queue.pending.get(key)
            if pending is None or pending[0] != 0:
                return None  # Only the observed normal solo matching type is implemented.
            previous = self.reservations.get(key)
            if previous and self.valid(previous):
                return previous
            self.next_room_id += 1
            room = xwar_entry.BattleRoom(0, self.next_room_id, MISSION_ID, self.host,
                                        self.port, secrets.token_hex(20), 0)
            reservation = Reservation(str(account), pilot_id, self.user_id_for_account(account),
                                      self.world_id, bytes(record), room, self.clock() + 300)
            self.reservations[key] = reservation
            if not self.queue.assign_room(account, pilot_id, room):
                del self.reservations[key]
                return None
            self.queue.set_status(0, active=True)
            return reservation

    def valid(self, reservation):
        with self.queue.lock:
            key = (reservation.account, reservation.pilot_id)
            return (self.reservations.get(key) is reservation
                    and self.queue.rooms.get(key) == reservation.room
                    and (reservation.connected or self.clock() <= reservation.expires_at))

    def authenticate(self, body):
        identity = auth_identity(body)
        if identity is None:
            return None, [(0xA5DA, authenticate_body(result=-1))]
        user_id, world_id, pilot_id, room_id, ticket, comeback = identity
        with self.queue.lock:
            for reservation in self.reservations.values():
                if ((reservation.user_id, reservation.world_id, reservation.pilot_id, reservation.room.room_id)
                        == (user_id, world_id, pilot_id, room_id)
                        and secrets.compare_digest(reservation.room.otp, ticket)
                        and self.valid(reservation) and not reservation.connected):
                    reservation.connected = True
                    if self.countdown_seconds is not None:
                        reservation.start_at = self.clock() + self.countdown_seconds
                    replies = [(0xA5DA, authenticate_body(room_id)),
                               (0xBDD6, member_body(reservation.record, world_id)),
                               (0x5913, struct.pack('<II', world_id, pilot_id))]
                    if self.countdown_seconds is not None:
                        replies.append((0x6A8D, countdown_body(self.countdown_seconds)))
                    return reservation, replies
        return None, [(0xA5DA, authenticate_body(result=-1))]

    def disconnect(self, reservation):
        if reservation is not None:
            with self.queue.lock:
                # An abandoned connection cannot leave reusable credentials behind.
                key = (reservation.account, reservation.pilot_id)
                if self.reservations.get(key) is reservation:
                    self.queue.cancel(*key, struct.pack('<I', reservation.room.matching))
                    del self.reservations[key]

    def replies(self, reservation, opcode, body):
        if not self.valid(reservation):
            return []
        if opcode == 0x770D:
            if not reservation.round_active or not reservation.entities_ready or reservation.training_target is None:
                return []
            return reservation.training_target.hit(training_target.parse_hit(body),
                    owned_items=reservation.spawned_weapon_ids,
                    kinds=experimental_weapon_kinds(), now=self.clock())
        if opcode == 0x7C0C:
            # A8B570: 30B hand_throw, distinct from the bound variant.
            # Release/impact presentation only; no authoritative hits/damage.
            if (len(body) != 30 or not reservation.round_active
                    or not reservation.entities_ready or len(reservation.spawned_weapon_ids) != 3):
                return []
            fields = struct.unpack('<I8HBBIBHB', body)
            _, lx, ly, lz, tx, ty, tz, target, msec, impact, fx, impact_id, charge, ai, salvo = fields
            if (impact not in (0, 1) or fx or charge or ai or salvo not in (0, 255)
                    or target not in (0, 0xffff) or msec > 10000):
                return []
            now = self.clock()
            reservation.pending_grenades = {
                gid: entry for gid, entry in reservation.pending_grenades.items()
                if entry[1] > now}
            if impact:
                issued = reservation.pending_grenades.get(impact_id)
                if issued is None:
                    return []
                item, _ = reservation.pending_grenades.pop(impact_id)
                # Keep the issued item even if the pilot has since switched.
                # Client callback A55620 selects 4F2520 when impact=1.
                return [(0x1A13, struct.pack('<HII8H3B', 1, item, impact_id,
                         lx, ly, lz, tx, ty, tz, target, msec, 1, 0, 0))]
            item = reservation.spawned_weapon_ids[reservation.active_weapon_index]
            if (experimental_weapon_kinds().get(item) != 'HAND_THROW' or impact_id
                    or len(reservation.pending_grenades) >= 64):
                return []
            grenade_id = reservation.next_grenade_id
            if grenade_id > 0xffffffff:
                return []
            reservation.next_grenade_id += 1
            reservation.pending_grenades[grenade_id] = (item, now + 30)
            # Explicit 1.5s local presentation fallback for observed msec=0;
            # not an original fuse or authoritative trajectory/hit calculation.
            return [(0x1A13, struct.pack('<HII8H3B', 1, item, grenade_id,
                     lx, ly, lz, tx, ty, tz, target, msec or 1500, 0, 0, 0))]
        if opcode == 0x2ADC:
            # Experimental presentation and one-target melee hit allowance.
            if (len(body) != 17 or not reservation.round_active
                    or not reservation.entities_ready or len(reservation.spawned_weapon_ids) != 3):
                return []
            _, dir_h, dir_v, msec, wrestle_id, charge, ai = struct.unpack('<I3HIBH', body)
            item = reservation.spawned_weapon_ids[reservation.active_weapon_index]
            presentation = experimental_melee_presentations().get(item, {}).get(wrestle_id)
            if (ai != 0 or charge != 0 or not presentation
                    or experimental_weapon_kinds().get(item) != 'WRESTLE'):
                return []
            if (reservation.training_target is not None
                    and not reservation.training_target.begin_melee(
                        item, now=self.clock(), duration=presentation['duration_ms']/1000,
                        dash=presentation is not experimental_melee_presentations()[item][0])):
                return []
            # D725 has no result/hit fields: entity, item, directions, duration,
            # configured local presentation ID and charge. No hit acceptance.
            # Current client sends0 for basic clicks even with the configured
            # attack base. Map only this observed case to the selected saber;
            # never resolve another item's or an arbitrary nonzero action ID.
            return [(0xD725, struct.pack('<HI3HIB', 1, item, dir_h, dir_v,
                                        presentation['duration_ms'], presentation['attack_id'], charge))]
        if opcode == 0xEA5A:
            # Current sender: frame_count u32, equip_index u8, AI entity u16.
            # Only the local human (AI=0) is implemented. Use the spawned
            # loadout, not a subsequently edited persistent hangar record.
            if (len(body) != 7 or not reservation.round_active
                    or not reservation.entities_ready or len(reservation.spawned_weapon_ids) != 3):
                return []
            _, index, ai_entity = struct.unpack('<IBH', body)
            if ai_entity != 0:
                return []
            accepted = index < 3 and reservation.spawned_weapon_ids[index] != 0
            if accepted:
                reservation.active_weapon_index = index
            current = reservation.active_weapon_index
            # B334 current reader: ent u16, result i32, index u8, item u32,
            # force u8. A nonnegative result invokes the native switch path.
            return [(0xB334, struct.pack('<HiBIB', 1, 0 if accepted else -1,
                     current, reservation.spawned_weapon_ids[current], 0))]
        if opcode == 0xCB97 and reservation.round_active:
            # A87750: is_initial u32, script_thread u8, NUL source <=64.
            # 8297 has an empty body and invokes the native game-resume callback.
            if (6 <= len(body) <= 70 and body[4] in (0, 1) and body[-1] == 0
                    and b'\0' not in body[5:-1]):
                return [(0x8297, b'')]
            return []
        if opcode == 0xE650 and len(body) == 16:
            # A87E.. current sender: three u32, two u8 flags, entity u16.
            index, post, spot, ship_ride, msma_ride, entity = struct.unpack('<IIIBBH', body)
            units = sorted((u for u in self.units_for_pilot(reservation.account, reservation.pilot_id)
                            if 0 <= u.get('deckslots', [255])[0] < 4), key=lambda u: u['deckslots'][0])
            if (reservation.deployment_available and not reservation.round_active
                    and index < len(units) and not ship_ride and not msma_ride):
                # Selection acceptance during prestart; not a spawned entity.
                if post == 0xffffffff and entity == 0xffff:
                    reservation.selected_index = index
                    prefix = []
                    if not reservation.bases_sent:
                        prefix = base_entity_replies(reservation)
                        reservation.bases_sent = True
                    remaining = (DEPLOYMENT_SECONDS if reservation.deployment_at is None else
                                 max(0, int(reservation.deployment_at - self.clock() + 0.999)))
                    return prefix + [(0x640D, prestart_body(remaining, index,
                              reservation.selected_post if reservation.selected_entity == 0xffff
                              and reservation.selected_post is not None else 0xffff,
                              reservation.selected_entity))]
                if entity != 0xffff:
                    base_index = entity - BASE_ENTITY_START
                    if (post != 0xffffffff or not 0 <= base_index < len(deployment_points())
                            or deployment_points()[base_index][0] != 0):
                        return [(0x86B2, struct.pack('<iIIIH', -1, index, post, spot, entity) + b'\0')]
                    post = base_index
                if post >= len(deployment_points()) or deployment_points()[post][0] != 0:
                    return [(0x86B2, struct.pack('<iIIIH', -1, index, post, spot, 0xffff) + b'\0')]
                reservation.selected_index = index
                reservation.selected_post = post
                reservation.selected_entity = entity
                prefix = []
                if not reservation.bases_sent:
                    prefix = base_entity_replies(reservation)
                    reservation.bases_sent = True
                if reservation.deployment_at is None:
                    reservation.deployment_at = self.clock() + DEPLOYMENT_SECONDS
                remaining = max(0, int(reservation.deployment_at - self.clock() + 0.999))
                # 86B2 success advances the native respawn step; it is not a selection receipt.
                return prefix + [(0x640D, prestart_body(remaining, index,
                          post if entity == 0xffff else 0xffff, entity))]
            return [(0x86B2, struct.pack('<iIIIH', -1, index, post, spot, 0xffff) + b'\0')]
        if opcode == 0x0372 and not body:
            return [(0x3E23, mission_progress_body(not reservation.round_active))]
        if opcode == 0xE041 and not body:
            units = self.units_for_pilot(reservation.account, reservation.pilot_id)
            equipped = sorted((u for u in units if 0 <= u.get('deckslots', [255])[0] < 4),
                              key=lambda u: u['deckslots'][0])
            replies = ([(0x9951, struct.pack('<II', 0, 1))]
                    + [(0x1E2F, struct.pack('<I', i) + spawn_unit_body(unit, unit['deckslots'][0]))
                       for i, unit in enumerate(equipped)] + [(0xAB6F, b'')])
            if reservation.started and not reservation.round_active:
                reservation.deployment_available = bool(deployment_points())
                remaining = (DEPLOYMENT_SECONDS if reservation.deployment_at is None else
                             max(0, int(reservation.deployment_at - self.clock() + 0.999)))
                # Static coordinates alone do not supply visibility or ownership.
                replies.append((0xD1B3, deployment_post_states_body()))
                replies.append((0x640D, prestart_body(remaining)))
            return replies
        if opcode == 0x2761 and len(body) == 4:
            stat = struct.unpack('<I', body)[0]
            # Native 6D08B8 also sends state 2 while entering the room.
            if stat in (0, 1, 2):
                reservation.stat = stat
                replies = [(0x339C, struct.pack('<4I', 0, reservation.world_id, reservation.pilot_id, stat))]
                return replies
        if opcode == 0xF741 and not body:
            # Formal xwar is server scheduled; a client request cannot skip its timer.
            return []
        if opcode == 0xD97D and not body:
            self.disconnect(reservation)
            # Current A66712 checks EOF immediately: no result field.
            return [(0x14C5, b'')]
        if opcode == 0x9B19 and len(body) == 4:
            index = struct.unpack('<I', body)[0]
            if index < 51:
                return [(0x0B3E, struct.pack('<IIIB', 0, reservation.world_id, reservation.pilot_id, index))]
        # Deployment and gameplay requests still require their own implementation.
        return []

    def tick(self, reservation):
        with self.queue.lock:
            if (self.valid(reservation) and reservation.connected and reservation.round_active
                    and reservation.training_target is not None):
                return reservation.training_target.tick(now=self.clock())
            if (self.valid(reservation) and reservation.connected and reservation.started
                    and not reservation.round_active and reservation.deployment_at is not None
                    and self.clock() >= reservation.deployment_at):
                # A progress flag is not a substitute for the missing entity stream.
                if not reservation.entities_ready:
                    if reservation.selected_index is None or reservation.selected_post is None:
                        return []
                    units = sorted((u for u in self.units_for_pilot(reservation.account, reservation.pilot_id)
                                    if 0 <= u.get('deckslots', [255])[0] < 4), key=lambda u: u['deckslots'][0])
                    if reservation.selected_index >= len(units):
                        return []
                    unit = units[reservation.selected_index]
                    reservation.spawned_weapon_ids = tuple(unit.get('equipped_weapons', [0, 0, 0]))
                    reservation.active_weapon_index = 0
                    own = battle_entities.appear_self_body(spawn_unit_body(unit, unit['deckslots'][0]),
                            1, deployment_points()[reservation.selected_post][1], team=0,
                            troops=reservation.record[29], hp=unit.get('hp', 3425),
                            shield_hp=990 if unit.get('shield') else 0)
                    reservation.entities_ready = True
                    reservation.round_active = True
                    replies = [(0x7621, own), (0x86B2, struct.pack('<iIIIH', 0,
                            reservation.selected_index,
                            reservation.selected_post if reservation.selected_entity == 0xffff else 0xffffffff,
                            0xffffffff, reservation.selected_entity) + b'\0'),
                            (0x640D, prestart_body(0)), (0x3E23, mission_progress_body(False))]
                    position = training_target.spawn_position(reservation.selected_post) if self.training_targets_enabled else None
                    if position is not None:
                        reservation.training_target = training_target.Target(position)
                        replies.append((0x717D, battle_entities.appear_body(
                            spawn_unit_body(training_target.UNIT, 255), training_target.ENTITY,
                            position, team=1, troops=1, world_id=0, pilot_id=0, letter=255,
                            snapshots=True)))
                        replies.append((0xE4DB, training_target.hp_display_body()))
                    return replies
                reservation.round_active = True
                return [(0x640D, prestart_body(0)), (0x3E23, mission_progress_body(False))]
            if (not self.valid(reservation) or not reservation.connected or reservation.started
                    or reservation.start_at is None or self.clock() < reservation.start_at):
                return []
            reservation.started = True
            return [(0x7206, struct.pack('<5I', 0, 0, 1200, 0, 0)),
                    (0x1365, game_begin_body())]
