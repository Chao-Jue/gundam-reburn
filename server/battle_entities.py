"""Current-client entity wire records for the isolated local battle prototype."""
import struct

SNAPSHOT_FORMAT = '<4H7H2BH3B2HIH'


def snapshot_body(entity, position_cm, *, hp_percent=100, shield_percent=0, state_bits=0):
    if not 0 < entity < 0xffff:
        raise ValueError('entity ID must be a non-sentinel u16')
    xyz = tuple(round(x / 100) for x in position_cm)
    if any(not -32768 <= x <= 32767 for x in xyz):
        raise ValueError('entity position exceeds pos_factor=100 encoding')
    # A5EA80: wire has no padding; native record is 44B, wire is 39B.
    return struct.pack(SNAPSHOT_FORMAT, entity, *(x & 0xffff for x in xyz),
                       0, 0, 0, 0, 0, 0, 0, hp_percent, shield_percent, 0,
                       0, 255, 0, 0xffff, 0xffff, state_bits, 0)


def appear_body(descriptor, entity, position_cm, *, team, troops, world_id, pilot_id, letter, snapshots=False, state_bits=0):
    # 717D / A74089: team, troops/world/pilot, A5E300, A5EA80, A5F5C0,
    # unattended/weapon u16, target/is_respawn/is_using_ss/stronghold_number/xweapon u8.
    return (struct.pack('<BIII', team, troops, world_id, pilot_id) + descriptor
            + snapshot_body(entity, position_cm, state_bits=state_bits) + bytes(10)
            + struct.pack('<HH5B', 0, 0, 0, 1, int(snapshots), letter, 0))


def appear_self_body(descriptor, entity, position_cm, *, team, troops, hp, shield_hp):
    # 7621 / A75966: full owned descriptor + initial transform + explicit HP.
    return (struct.pack('<BB', team, troops) + descriptor
            + snapshot_body(entity, position_cm, shield_percent=100 if shield_hp else 0)
            + bytes(10) + struct.pack('<4IH', hp, hp, shield_hp, shield_hp, 0))
