"""Server-owned DP accumulator; late GM thresholds with explicit experiment timing."""
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import struct


@lru_cache(maxsize=1)
def settings():
    return json.loads((Path(__file__).parent/'reference/training_dp.json').read_text(encoding='utf-8'))


@lru_cache(maxsize=1)
def weapon_points():
    from hangar_experiment import all_definitions
    result = {}
    for weapon in all_definitions():
        value = weapon.get('attributes', {}).get('倒地值')
        if isinstance(value, str) and value.isdecimal():
            result[weapon['item_id']] = int(value)
    result.update({int(k): v for k, v in settings()['weapon_overrides'].items()})
    return result


@dataclass
class Gauge:
    consumed: float = 0
    flinched: bool = False
    last_hit: float | None = None
    updated_at: float | None = None
    disabled_until: float = float('-inf')
    reset_at: float | None = None

    def advance(self, now):
        if self.updated_at is not None and now < self.updated_at:
            raise ValueError('DP requires monotonic time')
        config = settings()
        if self.reset_at is not None and now >= self.reset_at:
            self.consumed = 0
            self.flinched = False
            self.reset_at = None
        elif self.last_hit is not None and self.reset_at is None:
            start = max(self.updated_at, self.last_hit+config['recovery_delay_seconds'])
            self.consumed = max(0, self.consumed-max(0, now-start)*config['recovery_per_second'])
            if self.consumed == 0:
                self.flinched = False
        self.updated_at = now

    def hit(self, points, *, now, force_tumble=False, airborne=False):
        self.advance(now)
        if points is None or points <= 0 or now < self.disabled_until:
            return None
        config = settings()
        self.last_hit = now
        self.consumed = min(config['gauge']['break'], self.consumed+points)
        reaction = None
        if force_tumble and config['dash_melee_forces_tumble']:
            reaction = 'tumble'
        elif self.consumed >= config['gauge']['break']:
            reaction = 'tumble' if airborne else 'kneel'
        elif not self.flinched and self.consumed >= config['gauge']['flinch']:
            reaction = 'flinch'
            self.flinched = True
        if reaction:
            self.disabled_until = now+config['reactions'][reaction]['msec']/1000
            if reaction != 'flinch':
                self.reset_at = self.disabled_until
        return reaction


def reaction_packet(reaction, entity, direction):
    row = settings()['reactions'][reaction]
    # Native A63B90: ent16, dir16, spbits32, optbits16, power16, msec16.
    # Power is impulse, NOT accumulated DP. Keep geometry and DP independent.
    return row['opcode'], struct.pack('<HHIHHH', entity, direction, 0, 0, row['power'], row['msec'])
