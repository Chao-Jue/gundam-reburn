"""Opt-in stationary practice target; experimental damage, no original AI balance."""
from dataclasses import dataclass, field
import math
import struct
import json
from pathlib import Path
import down_points

ENTITY = 200
HP = 3425
UNIT = {'uniqid': 777000000002, 'msma_id': 777001,
        'equipped_weapons': [0, 0, 0], 'shield': 0}


def spawn_position(post_index):
    data = json.loads((Path(__file__).parent / 'reference/training_target_positions.json').read_text())
    return next((tuple(p['position_cm']) for p in data['points'] if p['post_index'] == post_index), None)


def hp_display_body():
    # E4DB: entity u16[count32], maxHP u32[count32], gauge_max u32.
    # A54860 ->44AE90 installs the HP display list separately from appearance.
    return struct.pack('<IHI2I', 1, ENTITY, 1, HP, 10000)


def parse_hit(body):
    # A8EB90 /770D: phash64,frame,item,fire; seven counted u16 arrays;
    # charge8,AI16,instate16,create_frame32,down_range8.
    if not 58 <= len(body) <= 282:
        return None
    phash, frame, item, fire = struct.unpack_from('<QIII', body)
    offset, arrays = 20, []
    for _ in range(7):
        if offset+4 > len(body):
            return None
        count = struct.unpack_from('<I', body, offset)[0]
        offset += 4
        if count > 16 or offset+count*2 > len(body):
            return None
        arrays.append(struct.unpack_from('<'+'H'*count, body, offset))
        offset += count*2
    if offset+10 != len(body):
        return None
    charge, ai, instate, created, down = struct.unpack_from('<BHHIB', body, offset)
    if charge or ai or instate or down not in (0, 1) or any(len(a) != 1 for a in arrays):
        return None
    values = [a[0] for a in arrays]
    signed = lambda n: n-65536 if n >= 32768 else n
    # Observed local frame counters can remain zero; preserve the native
    # projectile hash for identity, without treating it as authentication.
    return {'item': item, 'identity': (phash, frame, item, fire, created),
            # 4EC0C0..4EC0CD subtracts victim position before 6330A0
            # quantizes. These are victim-relative offsets, not world points.
            'entity': values[0], 'position': tuple(signed(n)*100 for n in values[1:4]),
            'encoded_position': tuple(values[1:4]), 'direction': values[4],
            'region': values[6]}


@dataclass
class Target:
    position: tuple
    hp: int = HP
    seen: set = field(default_factory=set)
    last_hit: float | None = None
    melee_sequence: int = 0
    melee_item: int | None = None
    melee_busy_until: float = float('-inf')
    melee_report_until: float = float('-inf')
    melee_dash: bool = False
    dp: down_points.Gauge = field(default_factory=down_points.Gauge)
    recovery_at: float | None = None
    snapshot_frame: int = 0
    tumble_sync_at: float | None = None

    def tick(self, *, now):
        if self.recovery_at is None or self.hp <= 0:
            return []
        if now < self.recovery_at:
            if self.tumble_sync_at is None or now < self.tumble_sync_at:
                return []
            self.tumble_sync_at = now+.1
            self.snapshot_frame += 1
            # Grounded stationary target: active tumble bit10, no airborne
            # bit20. 4BF4D0 refreshes ground contact; 4BE430 retains the
            # current tumble until the final clear instead of forcing getup.
            return [(0x5eea, recovery_delta(self.snapshot_frame, state_bits=0x10))]
        self.recovery_at = None
        self.tumble_sync_at = None
        self.dp.advance(now)
        self.snapshot_frame += 1
        return [(0x5eea, recovery_delta(self.snapshot_frame))]

    def begin_melee(self, item, *, now, duration, dash=False):
        if now < self.melee_busy_until:
            return False
        self.melee_sequence += 1
        self.melee_item = item
        self.melee_dash = dash
        self.melee_busy_until = now + duration
        self.melee_report_until = self.melee_busy_until + .25
        return True

    def hit(self, report, *, owned_items, kinds, now):
        if (report is None or report['entity'] != ENTITY or self.hp <= 0
                or report['item'] not in owned_items):
            return []
        kind = kinds.get(report['item'])
        # Native melee hashes repeat across distinct swings while frame/fire
        # counters stay zero. Scope one target hit to an accepted 2ADC instead.
        # With no unique native swing ID this is a bounded prototype gate,
        # not proof that a late report belongs to the current swing.
        identity = report['identity']
        if kind == 'WRESTLE':
            if self.melee_item != report['item'] or now > self.melee_report_until:
                return []
            identity = ('melee', self.melee_sequence)
        if identity in self.seen:
            return []
        # Only single-shot gun and saber initially. Grenade area damage needs
        # its own issued-projectile association, rather than trusting fire_id.
        damage = {'SHOTGUN': 100, 'BEAM_SPRAYGUN': 100, 'WRESTLE': 250}.get(kind)
        if (damage is None or math.dist(report['position'], (0, 0, 0)) > 400
                or self.last_hit is not None and now-self.last_hit < .2):
            return []
        if len(self.seen) >= 4096:
            return []  # bounded room-lifetime deduplication
        self.seen.add(identity)
        self.last_hit = now
        damage = min(damage, self.hp)
        self.hp -= damage
        x, y, z = report['encoded_position']
        # DDF7 weapon_hit_to_r: impact feedback. 49C6 weapon_hit_from:
        # victim,attacker,item,charge,hp_now,max,damage,spbits,xyz,dir,region,
        # optbits,shield_now. No invented death/respawn message.
        # 4A5BC0 bit1 selects impact +D8/+F4. Bit0 also creates
        # shield-defense camera UI (PP_09_400_04); keep it off here.
        hit_effect_flags = 2 if kind == 'WRESTLE' else 0
        replies = [(0xddf7, struct.pack('<I5H', report['item'], ENTITY, hit_effect_flags, x, y, z)),
                (0x49c6, struct.pack('<HHIB4I6HI', ENTITY, 1, report['item'], 0,
                 self.hp, HP, damage, 0, x, y, z, report['direction'], report['region'], 0, 0))]
        # Rejected/replayed hits never reach the DP accumulator. No reaction
        # on a lethal hit; target death lifecycle remains a separate task.
        if self.hp > 0:
            reaction = self.dp.hit(down_points.weapon_points().get(report['item']), now=now,
                                   force_tumble=kind == 'WRESTLE' and self.melee_dash)
            if reaction:
                self.recovery_at = self.dp.disabled_until
                self.tumble_sync_at = now+.1 if reaction == 'tumble' else None
                replies.append(down_points.reaction_packet(reaction, ENTITY, report['direction']))
        return replies


def recovery_delta(frame, *, state_bits=0):
    # Current A63B90/5EEA has 31 separately counted columns. 9FFB00
    # writes dirty20 into snapshot+2A and clears low special bits at+24.
    # Preserve position, HP, equipment and all other cached fields.
    columns = {0: struct.pack('<H', ENTITY), 1: struct.pack('<H', 0x20),
               15: struct.pack('<B', state_bits)}
    return struct.pack('<II', frame, 100)+b''.join(
        struct.pack('<I', 1)+columns[i] if i in columns else bytes(4) for i in range(31))
