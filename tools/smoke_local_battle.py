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
        plain = bytes.fromhex(fake_auth.op_block(opcode, body))
        cipher = b''.join(fake_auth.camellia_block(self.key[16:], plain[i:i + 16], self.up + i // 16)
                          for i in range(0, len(plain), 16))
        self.up += len(plain) // 16
        self.socket.sendall(struct.pack('<I', len(plain)) + cipher)

    def receive(self):
        length = struct.unpack('<I', self.exact(4))[0]
        if not 0 < length <= 65535:
            raise RuntimeError(f'invalid downlink length {length}')
        plain, self.down = fake_auth.decrypt_uplink(self.key[16:] + self.key[:16],
                                                    self.exact((length + 15) & ~15), self.down)
        return [(opcode, body) for opcode, body in fake_auth.iter_type0(plain[:length]) if opcode != 0xFFFF]

    def expect(self, opcode):
        replies = self.receive()
        assert len(replies) == 1 and replies[0][0] == opcode, (opcode, [op for op, _ in replies])
        return replies[0][1]

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
                      'equipped_weapons': [0, 0, 0], 'weapons': [], 'cost': 200}
        HangarStore(directory / 'hangar.gm.json').replace_units('battle-smoke', 1, [spawn_unit])
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        bootstrap = ("import sys, fake_auth; fake_auth.PILOT_STORE=sys.argv[1]; "
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
            assert battle.expect(0x640D) == local_battle.prestart_body(60)
            battle.send(0xE650, struct.pack('<IIIBBH', 0, 0, 0xffffffff, 0, 0, 0xffff))
            assert battle.expect(0x640D) == local_battle.prestart_body(60, 0, 0)
            battle.send(0xD97D, b'')
            assert battle.expect(0x14C5) == b''
            battle.close()
            print('PASS: isolated service startup; encrypted auth/lounge; formal booking and handoff; battle auth/member/ready/exit')
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
