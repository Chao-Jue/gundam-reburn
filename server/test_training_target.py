import struct
import unittest
import training_target as target
import local_battle
import xwar_entry


def report(*, item=777108, frame=1, entity=target.ENTITY, xyz=(0, 1, 0)):
    arrays = [entity, *xyz, 0, 10, 0]
    return (struct.pack('<QIII', 0, frame, item, frame)
            + b''.join(struct.pack('<IH', 1, value) for value in arrays)
            + struct.pack('<BHHIB', 0, 0, 0, frame, 0))


class TrainingTargetTest(unittest.TestCase):
    def test_both_local_spawn_points_clear_every_fixed_base_after_wire_rounding(self):
        for post in (0, 1):
            position = target.spawn_position(post)
            self.assertIsNotNone(position)
            wire = tuple(round(v/100)*100 for v in position)
            for _, base in local_battle.deployment_points():
                self.assertTrue(abs(wire[0]-base[0]) >= 1000 or abs(wire[2]-base[2]) >= 1500)
            self.assertLessEqual(abs(wire[1]-position[1]), 50)
        self.assertIsNone(target.spawn_position(99))

    def test_target_spawn_is_opt_in_once_and_backend_routes_hits(self):
        queue = xwar_entry.BookingQueue()
        queue.register('test', 77, struct.pack('<7I', 0, 4, 0, 0, 0, 0, 0))
        backend = local_battle.LocalBattleBackend(queue, '127.0.0.1', 30000)
        backend.training_targets_enabled = True
        clock = [100.]
        backend.clock = lambda: clock[0]
        unit = {'uniqid': 123, 'msma_id': 777001, 'deckslots': [0, 0],
                'equipped_weapons': [777108, 777106, 777103]}
        backend.units_for_pilot = lambda a, p: [unit]
        room = backend.reserve('test', 77, struct.pack('<I', 77)+bytes(153))
        room.connected = room.started = True
        room.selected_index = room.selected_post = 0
        room.deployment_at = backend.clock()-1
        room.deployment_release_at = backend.clock()-1  # target-only fixture after selection grace
        replies = backend.tick(room)
        appearance = next(body for op, body in replies if op == 0x717d)
        self.assertEqual(appearance[0], 1)  # enemy team
        base = local_battle.deployment_points()[0][1]
        # BAM_0601_0303_01 static bounds: X±680,Z±1130. Keep a
        # full extra GM body length outside the base, including wire rounding.
        delta = [room.training_target.position[i]-base[i] for i in (0, 2)]
        with self.subTest(check='base_clearance'):
            self.assertTrue(abs(delta[0]) >= 1000 or abs(delta[1]) >= 1500,
                            'training target is inside the base model bounds')
        with self.subTest(check='hp_visibility'):
            self.assertIn((0xe4db, target.hp_display_body((200, 201))), replies,
                          'enemy target has no explicit HP display initialization')
        self.assertEqual(backend.tick(room), [])
        xyz = (0, 1, 0)  # native victim-relative offset
        self.assertTrue(backend.replies(room, 0x770d, report(xyz=xyz)))
        self.assertEqual(room.air_training_target.hp, target.HP)
        self.assertTrue(backend.replies(room, 0x770d, report(entity=201)))
        self.assertEqual(room.air_training_target.hp, target.HP-100)
        self.assertEqual(room.training_target.hp, target.HP-100)
        clock[0] += .5
        packets = backend.tick(room)
        frames = [struct.unpack_from('<I', body)[0] for op,body in packets if op == 0x5eea]
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames, sorted(set(frames)))
        clock[0] += .5
        self.assertGreater(struct.unpack_from('<I',backend.tick(room)[0][1])[0],frames[-1])
        room.round_active = False
        self.assertEqual(backend.replies(room, 0x770d, report(frame=2, xyz=xyz)), [])

    def test_native_hit_shape_and_signed_position(self):
        body = report(xyz=(100, 65526, 150))
        parsed = target.parse_hit(body)
        self.assertEqual(parsed['position'], (10000, -1000, 15000))
        for invalid in (body[:-1], body+b'\0', body[:20]+struct.pack('<I', 17)+body[24:]):
            self.assertIsNone(target.parse_hit(invalid))
        for offset in (len(body)-10, len(body)-9, len(body)-7):
            invalid = bytearray(body)
            invalid[offset] = 1
            self.assertIsNone(target.parse_hit(invalid))

    def test_damage_is_server_chosen_clamped_and_replay_protected(self):
        dummy = target.Target((10000, -1000, 15000))
        parsed = target.parse_hit(report())
        kwargs = dict(owned_items=(777108, 777106, 777103), kinds={777108: 'SHOTGUN'}, now=1.)
        replies = dummy.hit(parsed, **kwargs)
        self.assertEqual([op for op, _ in replies], [0xddf7, 0x49c6, 0x45fc])
        self.assertEqual(dummy.hp, target.HP-100)
        fields = struct.unpack('<HHIB4I6HI', replies[1][1])
        self.assertEqual(fields[:7], (200, 1, 777108, 0, target.HP-100, target.HP, 100))
        self.assertEqual(dummy.hit(parsed, **kwargs), [])
        dummy.hp = 50
        kwargs['now'] = 2.
        self.assertTrue(dummy.hit(target.parse_hit(report(frame=2)), **kwargs))
        self.assertEqual(dummy.hp, 0)
        kwargs['now'] = 3.
        self.assertEqual(dummy.hit(target.parse_hit(report(frame=3)), **kwargs), [])

    def test_unknown_target_weapon_far_hits_and_rate_are_rejected(self):
        dummy = target.Target((10000, -1000, 15000))
        kwargs = dict(owned_items=(777108,), kinds={777108: 'SHOTGUN'}, now=1.)
        for body in (report(entity=1), report(item=777103), report(xyz=(200, 0, 200))):
            self.assertEqual(dummy.hit(target.parse_hit(body), **kwargs), [])
        self.assertEqual(dummy.hp, target.HP)
        self.assertTrue(dummy.hit(target.parse_hit(report()), **kwargs))
        self.assertEqual(dummy.hit(target.parse_hit(report(frame=2)), **kwargs), [])

    def test_distinct_projectile_hashes_work_when_native_frame_counters_are_zero(self):
        dummy = target.Target((10000, -1000, 15000))
        kwargs = dict(owned_items=(777108,), kinds={777108: 'SHOTGUN'}, now=1.)
        for index, nonce in enumerate((100, 200)):
            body = bytearray(report(frame=0))
            struct.pack_into('<Q', body, 0, nonce)
            kwargs['now'] = 1.+index
            self.assertTrue(dummy.hit(target.parse_hit(body), **kwargs))
            self.assertEqual(dummy.hit(target.parse_hit(body), **kwargs), [])


    def test_native_relative_impact_with_down_range_flag_hits_distant_world_target(self):
        body=bytearray(report(xyz=(0,1,0)))
        body[-1]=1
        dummy=target.Target((12400,-2600,18400))
        parsed=target.parse_hit(body)
        self.assertIsNotNone(parsed,'native boolean down_range=1 is valid')
        replies=dummy.hit(parsed,owned_items=(777108,),kinds={777108:'SHOTGUN'},now=1.)
        self.assertTrue(replies,'relative impact is near target despite nonzero world position')
        self.assertEqual(dummy.hp,target.HP-100)
        self.assertEqual(dummy.hit(parsed,owned_items=(777108,),kinds={777108:'SHOTGUN'},now=2.),[])
        malformed=bytearray(body);malformed[-1]=2
        self.assertIsNone(target.parse_hit(malformed))


    def test_relative_impact_validation_does_not_use_world_origin(self):
        dummy=target.Target((12400,-2600,18400))
        self.assertTrue(dummy.hit(target.parse_hit(report(xyz=(0,1,0))),
            owned_items=(777108,),kinds={777108:'SHOTGUN'},now=1.),
            'native impact offset must be checked around target-local origin')


    def test_independent_saber_swings_can_reuse_native_hash_but_each_hits_once(self):
        queue=xwar_entry.BookingQueue()
        queue.register('repeat',77,struct.pack('<7I',0,4,0,0,0,0,0))
        backend=local_battle.LocalBattleBackend(queue,'127.0.0.1',30000)
        clock=[100.];backend.clock=lambda:clock[0]
        backend.training_targets_enabled=True
        backend.units_for_pilot=lambda a,p:[{'uniqid':123,'msma_id':777001,'deckslots':[0,0],
            'equipped_weapons':[777108,777106,777103]}]
        room=backend.reserve('repeat',77,struct.pack('<I',77)+bytes(153))
        room.connected=room.started=True;room.selected_index=room.selected_post=0
        room.deployment_at=99.;room.deployment_release_at=99.;backend.tick(room)
        backend.replies(room,0xEA5A,struct.pack('<IBH',0,1,0))
        swing=struct.pack('<I3HIBH',0,0,0,0,0,0,0)
        hit=report(item=777106,frame=0,xyz=(0,0,0))
        for index in range(3):
            clock[0]=100.+index
            self.assertTrue(backend.replies(room,0x2ADC,swing))
            clock[0]+=.25
            self.assertTrue(backend.replies(room,0x770D,hit),
                            'new accepted swing must not inherit previous native hash dedup')
            self.assertEqual(backend.replies(room,0x770D,hit),[])
            clock[0]+=.21
            changed_hash=bytearray(hit);struct.pack_into('<Q',changed_hash,0,index+123)
            self.assertEqual(backend.replies(room,0x770D,changed_hash),[])
            self.assertEqual(backend.replies(room,0x2ADC,swing),[])
        self.assertEqual(room.training_target.hp,target.HP-750)
        clock[0]=110.
        self.assertEqual(backend.replies(room,0x770D,hit),[])


    def test_melee_without_accepted_swing_is_rejected(self):
        dummy=target.Target((12400,-2600,18400))
        self.assertEqual(dummy.hit(target.parse_hit(report(item=777106)),
            owned_items=(777106,),kinds={777106:'WRESTLE'},now=1.),[])
