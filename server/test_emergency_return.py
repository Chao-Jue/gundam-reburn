import csv
import io
import struct
import unittest
import hangar_experiment
import local_battle
import training_target
import xwar_entry
from unittest.mock import patch


class EmergencyReturnTest(unittest.TestCase):
    def setUp(self):
        self.now=100.
        queue=xwar_entry.BookingQueue()
        queue.register('return-test',77,struct.pack('<7I',0,4,0,0,0,0,0))
        self.backend=local_battle.LocalBattleBackend(queue,'127.0.0.1',30000,clock=lambda:self.now)
        self.unit={'uniqid':123,'msma_id':777001,'deckslots':[0,0],
                   'equipped_weapons':[777108,777106,777103]}
        self.backend.units_for_pilot=lambda a,p:[self.unit]
        self.room=self.backend.reserve('return-test',77,struct.pack('<I',77)+bytes(153))
        self.room.connected=self.room.started=self.room.round_active=self.room.entities_ready=True
        self.room.selected_index=self.room.selected_post=0
        self.room.spawned_weapon_ids=tuple(self.unit['equipped_weapons'])
        self.room.deployment_available=True

    def request(self,cancel=0):
        return self.backend.replies(self.room,0x7B52,struct.pack('<I',cancel))

    def test_start_uses_the_same_time_as_generated_unit_performance(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_battle_detail.csv').decode())))
        seconds=int(next(r[2] for r in rows if r and r[0]=='WARP_TIME'))
        self.assertEqual(self.request(),[(0xFEBB,struct.pack('<iIHI',0,0,1,seconds*1000))])
        self.assertEqual(self.room.return_at,self.now+seconds)

    def test_cancel_and_duplicate_start_do_not_extend_countdown(self):
        self.request();deadline=self.room.return_at
        self.now+=1
        self.assertEqual(struct.unpack('<iIHI',self.request()[0][1]),(0,0,1,9000))
        self.assertEqual(self.room.return_at,deadline)
        self.assertEqual(self.request(1),[(0xFEBB,struct.pack('<iIHI',0,1,1,0))])
        self.now=deadline+1
        self.assertEqual(self.backend.tick(self.room),[])
        self.assertTrue(self.room.entities_ready)

    def test_configured_performance_time_changes_both_native_table_and_countdown(self):
        with patch.object(hangar_experiment,'GM_RETURN_SECONDS',3):
            self.assertEqual(struct.unpack('<iIHI',self.request()[0][1]),(0,0,1,3000))
            rows=list(csv.reader(io.StringIO(hangar_experiment.table_body('msma/msma_battle_detail.csv').decode())))
            self.assertEqual(next(r[2] for r in rows if r and r[0]=='WARP_TIME'),'3')

    def test_finish_hides_self_and_allows_redeployment_without_resetting_target(self):
        target=training_target.Target((23500,-400,13000),hp=3000)
        self.room.training_target=target
        self.request();self.now+=10
        self.assertEqual(self.backend.tick(self.room),[(0xE5FC,struct.pack('<H',1)),(0x130A,struct.pack('<H',1))])
        self.assertFalse(self.room.entities_ready)
        self.assertTrue(self.room.returned)
        self.assertEqual(self.backend.tick(self.room),[])
        self.assertIn(0x1E2F,[op for op,_ in self.backend.replies(self.room,0xE041,b'')])
        self.backend.replies(self.room,0xE650,struct.pack('<IIIBBH',0,1,0xffffffff,0,0,0xffff))
        self.backend.tick(self.room);self.now+=.5
        spawn=dict(self.backend.tick(self.room))[0x7621]
        self.assertEqual(struct.unpack_from('<3h',spawn,2+175+2),(300,5,-125))
        self.assertIs(self.room.training_target,target)
        self.assertEqual(target.hp,3000)
        self.assertFalse(self.room.returned)

    def test_malformed_requests_and_inactive_actor_are_rejected(self):
        for body in (b'',bytes(3),bytes(5),struct.pack('<I',2)):
            self.assertEqual(self.backend.replies(self.room,0x7B52,body),[])
        self.room.entities_ready=False
        reply=self.request()
        self.assertTrue(reply)
        self.assertLess(struct.unpack_from('<i',reply[0][1])[0],0)

    def test_returned_client_can_use_warp_map_without_refetching_unit_list(self):
        self.request();self.now+=10;self.backend.tick(self.room)
        # Captured native flow is800A directly, not E041 then E650.
        reply=self.backend.replies(self.room,0x800A,
            struct.pack('<IIBH',0xffffffff,0xffffffff,0,101))
        self.assertTrue(reply,'return must retain the selected mech for800A')
        self.assertEqual(self.room.selected_post,1)
        self.backend.tick(self.room);self.now+=.5
        packets=self.backend.tick(self.room)
        self.assertIn((0x0120,struct.pack('<H',1)),packets,
                      'clear the return hide reason when the owned actor reappears')
        self.assertIn(0x7621,[op for op,_ in packets])
