"""Launch an isolated real service and exercise auth -> lounge -> battle over TCP.

This is a synthetic protocol client, not a native game/UI end-to-end test.
Pilot and hangar stores are temporary; the running port 30000 is untouched.
"""
from pathlib import Path
from collections import deque
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import fake_auth
import local_battle
import training_target


class Client:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.socket.sendall(bytes(16))
        self.key = self.exact(32)
        self.up = self.down = 0
        self.send(0x34A9, bytes(12))
        assert self.receive()[0][0] == 0xDE24

    def exact(self, count):
        data = b''
        while len(data) < count:
            part = self.socket.recv(count - len(data))
            if not part:
                raise RuntimeError('service closed connection before complete frame')
            data += part
        return data

    def send(self, opcode, body):
        plain = bytearray.fromhex(fake_auth.op_block(opcode, body))
        for i in range(0,len(plain),16):
            fake_auth.apply_ct_mask(plain,i,self.key[16:],self.up+i//16)
        cipher = fake_auth.camellia_ecb(self.key[16:],bytes(plain))
        self.up += len(plain) // 16
        self.socket.sendall(struct.pack('<I', len(plain)) + cipher)

    def receive(self):
        length = struct.unpack('<I', self.exact(4))[0]
        if not 0 < length <= 65535:
            raise RuntimeError(f'invalid downlink length {length}')
        # ECB accepts all blocks in one invocation. Preserve the game's
        # per-block counter mask while avoiding one Windows process per block.
        encrypted=self.exact((length+15)&~15)
        result=subprocess.run(['openssl','enc','-d','-camellia-128-ecb','-K',
            self.key[:16].hex(),'-nopad'],input=encrypted,capture_output=True,check=True)
        plain=bytearray(result.stdout)
        for i in range(0,len(plain),16):
            fake_auth.apply_ct_mask(plain,i,self.key[:16],self.down+i//16)
        self.down+=len(plain)//16
        return [(opcode, body) for opcode, body in fake_auth.iter_type0(plain[:length]) if opcode != 0xFFFF]

    def expect(self, opcode, *, entity=None):
        deadline=time.monotonic()+15
        while True:
            assert time.monotonic()<deadline, ('timed out waiting for opcode',hex(opcode),entity)
            replies = self.receive()
            assert len(replies) == 1, replies
            op, body = replies[0]
            if op == 0x5eea and struct.unpack_from('<H',body,12)[0] == 201:
                if opcode == op and entity == 201:
                    return body
                continue  # asynchronous aerial patrol, not a request response
            assert op == opcode, (opcode, op)
            return body

    def close(self):
        self.socket.close()


def main():
    with tempfile.TemporaryDirectory(prefix='gundam-battle-smoke-') as temporary:
        directory = Path(temporary)
        record = bytearray(157)
        struct.pack_into('<I', record, 0, 1)
        record[4:10] = b'SMOKE\0'
        record[30] = 1
        store = directory / 'pilots.json'
        store.write_text(json.dumps({'battle-smoke': {'slots': {'0:0': record.hex()}}}), encoding='utf-8')
        from hangar import HangarStore
        spawn_unit = {'uniqid': 123, 'msma_id': 777001, 'deckslots': [0, 0],
                      'equipped_weapons': [777108, 777106, 777103],
                      'weapons': [{'item_id': item, 'db_index': index} for index, item in
                                  enumerate((777108, 777106, 777103))], 'cost': 200}
        HangarStore(directory / 'hangar.gm.json').replace_units('battle-smoke', 1, [spawn_unit])
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        bootstrap = ("import sys, fake_auth, local_battle; local_battle.DEPLOYMENT_SECONDS=1; fake_auth.PILOT_STORE=sys.argv[1]; "
                     "fake_auth.log=lambda message: print(message,flush=True); "
                     "sys.argv=['fake_auth.py',*sys.argv[2:]]; "
                     "raise SystemExit(fake_auth.main())")
        process = subprocess.Popen(
            [sys.executable, '-u', '-c', bootstrap, str(store), '--port', str(port),
             '--sweep', '--hangar-experiment', 'gm', '--battle-countdown', '2',
             '--hangar-store', str(directory / 'hangar.json')],
            cwd=ROOT / 'server', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace')
        # Drain continuously: Windows pipe buffers can fill while the codec logs frames.
        output = deque(maxlen=1000)
        reader = threading.Thread(target=lambda: output.extend(process.stdout), daemon=True)
        reader.start()
        clients = []
        try:
            for attempt in range(50):
                if process.poll() is not None:
                    raise RuntimeError('service exited during startup')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('service did not start')

            auth = Client(port)
            clients.append(auth)
            auth.send(0xF24B, b'battle-smoke\0'.ljust(92, b'\0'))
            assert struct.unpack('<i', auth.expect(0xA5DA))[0] == 0
            auth.send(0xA380, struct.pack('<I', 1))
            auth.expect(0x1146)
            auth.close()

            lounge = Client(port)
            clients.append(lounge)
            lounge.send(0xF24B, struct.pack('<I', 1) + b'local\0')
            assert struct.unpack_from('<i', lounge.expect(0xA5DA))[0] == 0
            lounge.send(0x2EFF, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
            assert struct.unpack_from('<i', lounge.expect(0xD52A))[0] == 0
            lounge.send(0xFC4B, bytes(4))
            lounge.expect(0xEA2C)
            matching, room_id, wait, mission = struct.unpack('<4I', lounge.expect(0xB099))
            assert mission == local_battle.MISSION_ID
            lounge.send(0x846A, struct.pack('<II', matching, room_id))
            handoff = lounge.expect(0x5383)
            assert struct.unpack_from('<i', handoff)[0] == 0
            host, tail = handoff[8:].split(b'\0', 1)
            battle_port, assigned_room = struct.unpack_from('<II', tail)
            ticket = tail[8:].split(b'\0', 1)[0]
            assert host == b'127.0.0.1' and battle_port == port and assigned_room == room_id
            lounge.close()

            battle = Client(battle_port)
            clients.append(battle)
            battle.send(0xF24B, struct.pack('<4I', 1, 1, 1, room_id) + ticket + b'\0\0')
            assert battle.expect(0xA5DA) == local_battle.authenticate_body(room_id)
            assert battle.expect(0xBDD6)[6:163] == bytes(record)
            assert battle.expect(0x5913) == struct.pack('<II', 1, 1)
            assert battle.expect(0x6A8D) == struct.pack('<I', 2)
            battle.send(0x2761, struct.pack('<I', 2))
            assert battle.expect(0x339C) == struct.pack('<4I', 0, 1, 1, 2)
            # Do not click/change the ready or deck state: server timer drives loading.
            assert battle.expect(0x7206) == struct.pack('<5I', 0, 0, 1200, 0, 0)
            assert battle.expect(0x1365) == local_battle.game_begin_body()
            battle.send(0xE041, b'')
            assert battle.expect(0x9951) == struct.pack('<II', 0, 1)
            assert battle.expect(0x1E2F) == bytes(4) + local_battle.spawn_unit_body(spawn_unit, 0)
            assert battle.expect(0xAB6F) == b''
            assert battle.expect(0xD1B3) == local_battle.deployment_post_states_body()
            assert battle.expect(0x640D) == local_battle.prestart_body(1)
            battle.send(0xE650, struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 0xffff))
            for i, (team, _) in enumerate(local_battle.deployment_points()):
                packet = battle.expect(0x717D)
                assert packet[0] == team
                assert struct.unpack_from('<H', packet, 13 + 175)[0] == local_battle.BASE_ENTITY_START + i
            assert struct.unpack('<iIIIHB', battle.expect(0x86B2)) == (1, 0, 0xffffffff, 0xffffffff, 0xffff, 0)
            assert battle.expect(0x640D) == local_battle.prestart_body(1, 0)
            # Captured native prestart flow uses E650 for both default home
            # post selection and changing bases, not the live warp request.
            battle.send(0xE650, struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff))
            assert struct.unpack('<iIIIHB', battle.expect(0x86B2)) == (1, 0, 0, 0xffffffff, 0xffff, 0)
            assert battle.expect(0x640D) == local_battle.prestart_body(1, 0, 0, 100)
            battle.send(0xE650, struct.pack('<IIIBBH', 0, 0xffffffff, 0xffffffff, 0, 0, 101))
            assert struct.unpack('<iIIIHB', battle.expect(0x86B2)) == (1, 0, 0xffffffff, 0xffffffff, 101, 0)
            assert battle.expect(0x640D) == local_battle.prestart_body(1, 0, 0xffff, 101)
            assert battle.expect(0x640D) == local_battle.prestart_body(0, 0, 0xffff, 101)
            # Do not manufacture another E650: the native client did not send
            # one in the failed runtime experiment. Timer must finish on its own.
            assert struct.unpack('<iIIIHB', battle.expect(0x86B2)) == (0, 0, 0xffffffff, 0xffffffff, 101, 0)
            own = battle.expect(0x7621)
            assert struct.unpack_from('<H', own, 2 + 175)[0] == 1
            spawn_xyz = tuple(round(v / 100) & 0xffff for v in local_battle.deployment_points()[1][1])
            assert struct.unpack_from('<3H', own, 2 + 175 + 2) == spawn_xyz
            assert battle.expect(0x640D) == local_battle.prestart_body(0)
            assert battle.expect(0x3E23)[21] == 0
            target_packet = battle.expect(0x717D)
            assert target_packet[0] == 1
            assert struct.unpack_from('<H', target_packet, 13+175)[0] == training_target.ENTITY
            air_packet = battle.expect(0x717D)
            assert struct.unpack_from('<H',air_packet,13+175)[0] == 201
            assert struct.unpack_from('<I',air_packet,13+175+33)[0] == 0x20
            assert battle.expect(0xE4DB) == training_target.hp_display_body((200,201))
            print('CHECK: both target appearances received',flush=True)
            battle.send(0xCB97, struct.pack('<IB', 1, 0) + b'\0')
            assert battle.expect(0x8297) == b''
            battle.send(0xEA5A, struct.pack('<IBH', 0, 1, 0))
            assert battle.expect(0xB334) == struct.pack('<HiBIB', 1, 0, 1,
                                                       spawn_unit['equipped_weapons'][1], 0)
            battle.send(0x2ADC, struct.pack('<I3HIBH', 0, 238, 1, 0, 0, 0, 0))
            assert battle.expect(0xD725) == struct.pack('<HI3HIB', 1, 777106, 238, 1, 500, 880002, 0)
            time.sleep(.55)  # finish normal swing before issuing dash
            battle.send(0x2ADC, struct.pack('<I3HIBH', 0, 238, 1, 0, 880012, 0, 0))
            assert battle.expect(0xD725) == struct.pack('<HI3HIB', 1, 777106, 238, 1, 366, 880012, 0)
            battle.send(0xEA5A, struct.pack('<IBH', 0, 2, 0))
            assert battle.expect(0xB334) == struct.pack('<HiBIB', 1, 0, 2, 777103, 0)
            battle.send(0x7C0C, struct.pack('<I8HBBIBHB', 0, 124, 65521, 147,
                        93, 65527, 165, 0, 0, 0, 0, 0, 0, 0, 255))
            assert battle.expect(0x1A13) == struct.pack('<HII8H3B', 1, 777103, 1,
                        124, 65521, 147, 93, 65527, 165, 0, 1500, 0, 0, 0)
            battle.send(0x7C0C, struct.pack('<I8HBBIBHB', 0, 105, 65520, 160,
                        105, 65520, 160, 0, 0, 1, 0, 1, 0, 0, 255))
            assert battle.expect(0x1A13) == struct.pack('<HII8H3B', 1, 777103, 1,
                        105, 65520, 160, 105, 65520, 160, 0, 0, 1, 0, 0)
            target_xyz = (0, 1, 0)  # victim-relative impact, not appearance world coords
            hit = (struct.pack('<QIII', 0, 1, 777108, 1)
                   + b''.join(struct.pack('<IH', 1, value)
                     for value in (200, *target_xyz, 0, 10, 0))
                   + struct.pack('<BHHIB', 0, 0, 0, 1, 1))
            battle.send(0x770D, hit)
            assert battle.expect(0xDDF7) == struct.pack('<I5H', 777108, 200, 0, *target_xyz)
            hp = battle.expect(0x49C6)
            assert struct.unpack_from('<3I', hp, 9) == (3325, 3425, 100)
            battle.expect(0x45fc)
            print('CHECK: gun DP flinch received',flush=True)
            battle.expect(0x5eea)
            time.sleep(3.1)  # recover DP from the new gun flinch before saber tests
            battle.send(0xEA5A, struct.pack('<IBH', 0, 1, 0))
            assert battle.expect(0xB334) == struct.pack('<HiBIB', 1, 0, 1, 777106, 0)
            melee_hit = (struct.pack('<QIII', 123, 0, 777106, 0)
                         + b''.join(struct.pack('<IH', 1, value)
                                    for value in (200, 0, 1, 0, 0, 10, 0))
                         + struct.pack('<BHHIB', 0, 0, 0, 0, 1))
            for expected_hp, reaction in ((3075, 0x45fc), (2825, 0xe332)):
                print('CHECK: ground saber',expected_hp,flush=True)
                time.sleep(.6)
                battle.send(0x2ADC, struct.pack('<I3HIBH', 0, 0, 0, 0, 0, 0, 0))
                battle.send(0x770D, melee_hit)
                assert len(battle.expect(0xD725)) == 17
                assert battle.expect(0xDDF7) == struct.pack('<I5H', 777106, 200, 2, 0, 1, 0)
                assert struct.unpack_from('<3I', battle.expect(0x49C6), 9) == (expected_hp, 3425, 250)
                assert struct.unpack('<HHIHHH', battle.expect(reaction)) == (
                    200, 0, 0, 0, 0, 300 if reaction == 0x45fc else 1000)
                recovery = battle.expect(0x5eea)
                assert len(recovery) == 137 and struct.unpack_from('<I', recovery, 8)[0] == 1
                assert struct.unpack_from('<H', recovery, 12)[0] == 200
            time.sleep(1.1)  # target finishes kneeling; DP is rearmed
            battle.send(0x2ADC, struct.pack('<I3HIBH', 0, 0, 0, 0, 880012, 0, 0))
            battle.send(0x770D, melee_hit)
            assert len(battle.expect(0xD725)) == 17
            assert battle.expect(0xDDF7) == struct.pack('<I5H', 777106, 200, 2, 0, 1, 0)
            assert struct.unpack_from('<3I', battle.expect(0x49C6), 9) == (2575, 3425, 250)
            assert struct.unpack('<HHIHHH', battle.expect(0xa8f2)) == (200, 0, 0, 0, 100, 1500)
            for _ in range(30):
                state = battle.expect(0x5eea)
                assert len(state) == 137 and state[76] in (0,0x10)
                if state[76] == 0: break
            else: raise AssertionError('tumble never received final recovery state')
            battle.send(0xEA5A, struct.pack('<IBH', 0, 0, 0))
            print('CHECK: ground tumble finished',flush=True)
            battle.expect(0xB334)
            for frame, hp, reaction in ((4,3325,0x45fc),(5,3225,0xa8f2)):
                air_hit = (struct.pack('<QIII',frame,frame,777108,frame)
                    + b''.join(struct.pack('<IH',1,value) for value in (201,0,1,0,0,10,0))
                    + struct.pack('<BHHIB',0,0,0,frame,1))
                battle.send(0x770D,air_hit)
                assert struct.unpack_from('<H',battle.expect(0xDDF7),4)[0] == 201
                assert struct.unpack_from('<I',battle.expect(0x49C6),9)[0] == hp
                assert struct.unpack_from('<H',battle.expect(reaction))[0] == 201
                print('CHECK: aerial gun reaction',hex(reaction),flush=True)
                if frame == 4: time.sleep(.5)
            states=[]
            for _ in range(70):
                body=battle.expect(0x5eea,entity=201)
                cursor=8; fields={}
                for i in range(31):
                    count=struct.unpack_from('<I',body,cursor)[0]; cursor+=4
                    width=2 if i in (0,1,2,3,4) else 1
                    fields[i]=body[cursor:cursor+count*width];cursor+=count*width
                bits=fields[15][0]; states.append(bits)
                if bits == 0: break
            assert 0x30 in states and 0x10 in states and states[-1] == 0, states
            battle.send(0x7B52,struct.pack('<I',0))
            assert struct.unpack('<iIHI',battle.expect(0xFEBB)) == (0,0,1,10000)
            battle.send(0x7B52,struct.pack('<I',1))
            assert struct.unpack('<iIHI',battle.expect(0xFEBB)) == (0,1,1,0)
            battle.send(0x7B52,struct.pack('<I',0))
            assert struct.unpack('<iIHI',battle.expect(0xFEBB)) == (0,0,1,10000)
            battle.socket.settimeout(15)  # a valid10s return may have no intervening world traffic
            assert battle.expect(0xE5FC) == struct.pack('<H',1)
            assert battle.expect(0x130A) == struct.pack('<H',1)
            battle.socket.settimeout(5)
            # Captured native return UI keeps the selected machine and sends
            #800A directly. Do not manufacture E041/E650 to conceal a gap.
            battle.send(0x800A,struct.pack('<IIBH',0xffffffff,0xffffffff,0,101))
            battle.expect(0x640D);battle.expect(0x640D)
            assert struct.unpack_from('<i',battle.expect(0x86B2))[0] == 0
            own=battle.expect(0x7621)
            assert struct.unpack_from('<3H',own,2+175+2) == spawn_xyz
            assert battle.expect(0x0120) == struct.pack('<H',1)
            battle.expect(0x640D);battle.expect(0x3E23)
            battle.send(0xCB97,struct.pack('<IB',1,0)+b'\0')
            battle.expect(0x8297)
            print('PASS: emergency return start/cancel/10s completion; direct800A B redeployment and self show without duplicate targets',flush=True)
            battle.send(0xD97D, b'')
            assert battle.expect(0x14C5) == b''
            battle.close()
            print('PASS: isolated service startup; encrypted formal handoff; bases/player/target spawn; weapon switch; grenade release/impact; target hit/HP; repeated saber hash; DP flinch/kneel/dash tumble packets; exit')
            print('PASS: aerial target spawn; gun DP flinch then air tumble; falling, landing and recovery sync')
            print('Native game UI and map resource loading were not exercised.')
        except Exception:
            # Keep failures diagnosable without exposing the generated OTP.
            for line in list(output):
                if '[battle]' in line or 'error:' in line:
                    print(line.rstrip(), file=sys.stderr)
            raise
        finally:
            for client in clients:
                client.close()
            process.terminate()
            process.wait(timeout=5)
            reader.join(timeout=2)
            process.stdout.close()


if __name__ == '__main__':
    main()
