"""Opt-in diagnostic VS mission for the local entry UI, not a playable map.

Enabled alongside the existing GM experiment. Original decoded files are untouched.
"""
import csv
import io
import struct
import threading
from dataclasses import dataclass
MISSION_ID = 900001
PREPARATION_MISSION_ID = 30110100


@dataclass(frozen=True)
class BattleRoom:
    """A room already prepared by a battle backend, including its auth ticket."""
    matching: int
    room_id: int
    mission_id: int
    host: str
    port: int
    otp: str
    wait_seconds: int = 0

    def __post_init__(self):
        for value in (self.matching, self.room_id, self.mission_id, self.wait_seconds):
            if not isinstance(value, int) or not 0 <= value <= 0xffffffff:
                raise ValueError('room fields must be u32')
        if not self.room_id or not self.mission_id or self.mission_id == MISSION_ID:
            raise ValueError('room needs a declared mission, not the diagnostic entry')
        if not 1 <= self.port <= 65535:
            raise ValueError('invalid battle port')
        for value, limit in ((self.host, 128), (self.otp, 40)):
            if not value or '\0' in value or len(value.encode('ascii')) > limit:
                raise ValueError('invalid battle host or ticket')

    def created_body(self):
        return struct.pack('<4I', self.matching, self.room_id, self.wait_seconds, self.mission_id)

    def enter_body(self):
        return (struct.pack('<II', 0, self.matching) + self.host.encode('ascii') + b'\0'
                + struct.pack('<II', self.port, self.room_id) + self.otp.encode('ascii') + b'\0')


class BookingQueue:
    """Hall-side booking state. A backend must explicitly publish ready rooms."""
    def __init__(self):
        self.lock = threading.RLock()
        self.pending = {}
        self.factions = {}
        self.rooms = {}
        self.notified = set()
        self.status = {}

    def register(self, account, pilot_id, body, troops=None):
        if len(body) != 28:
            return struct.pack('<IIBIIIBHB', 0xffffffff, 0, 0, 0, 0, 0, 0, 0, 0)
        fields = struct.unpack('<7I', body)
        matching, request, rules, extra = fields[:4]
        with self.lock:
            key = (str(account), int(pilot_id))
            if self.pending.get(key) != fields:
                self.rooms.pop(key, None)
                self.notified.discard(key)
            self.pending[key] = fields
            self.factions[key] = troops if troops in (0, 1) else None
        # Native ACA320..ACA75B: five u32, three u8 and one u16.
        # Additional tail fields have not been named; use zero defaults.
        return struct.pack('<IIBIIIBHB', 0, matching, 0, request, rules, extra, 0, 0, 0)

    def cancel(self, account, pilot_id, body):
        if len(body) != 4:
            return None
        matching = struct.unpack('<I', body)[0]
        with self.lock:
            key = (str(account), int(pilot_id))
            current = self.pending.get(key)
            if current is not None and current[0] == matching:
                del self.pending[key]
                self.factions.pop(key, None)
                self.rooms.pop(key, None)
                self.notified.discard(key)
        # Current native AB6A60 allocates 8 bytes and reads exactly two u32.
        return struct.pack('<II', 0, matching)

    def set_status(self, matching, *, active, remaining_count=0, remaining_seconds=0):
        """Accept an estimate from the matchmaker; zero means no estimate supplied."""
        for value in (matching, remaining_count, remaining_seconds):
            if not isinstance(value, int) or not 0 <= value <= 0xffffffff:
                raise ValueError('queue status must be u32')
        with self.lock:
            self.status[matching] = (int(bool(active)), remaining_count, remaining_seconds)

    def assign_room(self, account, pilot_id, room):
        """Called only once the backend has created the room and accepted the OTP."""
        if not isinstance(room, BattleRoom):
            raise TypeError('expected a prepared BattleRoom')
        key = (str(account), int(pilot_id))
        with self.lock:
            current = self.pending.get(key)
            if current is None or current[0] != room.matching:
                return False
            if self.rooms.get(key) != room:
                self.notified.discard(key)
            self.rooms[key] = room
        return True

    def info_replies(self, account, pilot_id, body):
        if len(body) != 4:
            return []
        matching = struct.unpack('<I', body)[0]
        key = (str(account), int(pilot_id))
        with self.lock:
            active, remaining, seconds = self.status.get(matching, (0, 0, 0))
            counts = [0, 0]
            for owner, fields in self.pending.items():
                faction = self.factions.get(owner)
                if fields[0] == matching and faction in (0, 1) and owner not in self.rooms:
                    counts[faction] += 1
            room_count = len({room.room_id for room in self.rooms.values() if room.matching == matching})
            replies = [(0xEA2C, struct.pack('<7I', matching, active, room_count, *counts, remaining, seconds))]
            room = self.rooms.get(key)
            if room is not None and room.matching == matching and key not in self.notified:
                replies.append((0xB099, room.created_body()))
                self.notified.add(key)
            return replies

    def enter(self, account, pilot_id, body):
        if len(body) != 8:
            return None
        matching, room_id = struct.unpack('<II', body)
        with self.lock:
            room = self.rooms.get((str(account), int(pilot_id)))
            if room is not None and (room.matching, room.room_id) == (matching, room_id):
                return room.enter_body()
        # The native handler still parses all six fields on failure.
        return struct.pack('<II', 0xffffffff, matching) + b'\0' + bytes(8) + b'\0'


BOOKINGS = BookingQueue()


def mission_info_body():
    # Native B080 at AC1563: two u32-counted arrays (<=128 each), three u8 flags.
    return struct.pack('<4I3B',1,MISSION_ID,1,MISSION_ID,0,0,0)


def table_body(name):
    if name.replace('\\','/').lstrip('/') != 'mission/mission_vs.csv':
        return None
    # Native row parser 5628A0 reads through column63. This supplies an entry
    # description object only; map/resources/rules remain unset until recovered.
    row=[0]*64
    row[0]=MISSION_ID
    row[3]='本地对战入口测试'
    row[4]='仅验证入口任务描述；尚未提供战斗地图和战斗服务器'
    out=io.StringIO(newline='')
    writer=csv.writer(out,lineterminator='\r\n')
    # A separate local preparation task; combat scripting is intentionally absent.
    preparation = row.copy()
    preparation[0] = PREPARATION_MISSION_ID
    preparation[1] = 100101  # mission/image/%05d.dds (not world_map ID)
    preparation[3] = '本地准备大厅'
    preparation[4] = '正式战预约链路的本地单人准备房间；尚不支持开始战斗'
    preparation[5] = 100102
    preparation[13] = 1  # ground environment
    preparation[16] = 'VS_TEAM_DEATHMATCH'
    preparation[17] = 'RPOST_DIFF'
    preparation[18] = 'ALL'
    preparation[23] = 0  # native mission vt+0x0C requires !row+0x50 for countdown UI
    preparation[38:42] = [1, 52, 20, 200]  # min, per-team maximum, minutes, cost
    writer.writerows([['# local entry and preparation tasks; combat not implemented'],['#'],row,preparation])
    return out.getvalue().encode('utf-8')
