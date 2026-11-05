import struct
import unittest
import training_target
import local_battle
import math
from test_training_target import report


def columns(body):
    result, cursor = {}, 8
    for i in range(31):
        count = struct.unpack_from('<I', body, cursor)[0]
        cursor += 4
        width = 2 if i in (0, 1, 2, 3, 4) else 1
        if count:
            result[i] = body[cursor:cursor+count*width]
        cursor += count*width
    assert cursor == len(body)
    return result


class AirTargetTest(unittest.TestCase):
    def test_targets_are_near_each_selected_spawn(self):
        for post in (0,1):
            spawn = local_battle.deployment_points()[post][1]
            for point in (training_target.spawn_position(post),training_target.air_spawn_ground(post)):
                self.assertLessEqual(math.dist((spawn[0],spawn[2]),(point[0],point[2])),4000,
                                     'test target must be within40m of the selected spawn')

    def create(self):
        return training_target.AirTarget((30250, 0, -10500), now=10)

    def shoot(self, target, frame, now):
        return target.hit(training_target.parse_hit(report(item=777108, frame=frame, entity=201)),
                          owned_items=(777108,), kinds={777108: 'SHOTGUN'}, now=now)

    def test_patrol_is_airborne_bounded_and_tick_rate_limited(self):
        target = self.create()
        self.assertEqual(target.entity, 201)
        self.assertEqual(target.tick(now=10.01), [])
        packet = columns(target.tick(now=12)[0][1])
        self.assertEqual(packet[15], b'\x20')
        self.assertNotEqual(target.position[1], 1500)
        self.assertTrue(1200 <= target.position[1] <= 1800)
        self.assertEqual(target.tick(now=12.01), [])

    def test_two_gun_hits_fall_then_land_before_getup(self):
        target = self.create()
        first = self.shoot(target, 1, 10)
        self.assertIn(0x45fc, [op for op, _ in first])
        second = self.shoot(target, 2, 10.5)
        self.assertIn(0xa8f2, [op for op, _ in second])
        self.assertNotIn(0xe332, [op for op, _ in second])
        self.assertEqual(struct.unpack_from('<H', dict(second)[0xa8f2])[0], 201)
        falling = columns(target.tick(now=11)[0][1])
        self.assertEqual(falling[15], b'\x30')
        self.assertLess(target.position[1], 1500)
        self.assertTrue(target.airborne)
        landing = columns(target.tick(now=target.land_at+.01)[0][1])
        self.assertEqual(landing[15], b'\x10')
        self.assertFalse(target.airborne)
        self.assertEqual(target.position, target.ground)
        self.assertGreater(target.recovery_at, target.land_at)
        recovery = columns(target.tick(now=target.recovery_at+.01)[0][1])
        self.assertEqual(recovery[15], b'\0')
        self.assertEqual(struct.unpack('<H', recovery[0])[0], 201)

    def test_landed_target_uses_ground_kneel_rule_and_never_relaunches(self):
        target = self.create()
        self.shoot(target, 1, 10)
        self.shoot(target, 2, 10.5)
        target.tick(now=target.land_at+.01)
        restored = target.recovery_at+.01
        target.tick(now=restored)
        self.shoot(target, 3, restored+.5)
        replies = self.shoot(target, 4, restored+1)
        self.assertIn(0xe332, [op for op, _ in replies])
        self.assertNotIn(0xa8f2, [op for op, _ in replies])
        target.tick(now=restored+20)
        self.assertEqual(target.position, target.ground)

    def test_duplicate_and_wrong_entity_do_not_consume_dp(self):
        target = self.create()
        self.shoot(target, 1, 10)
        self.assertEqual(self.shoot(target, 1, 10.5), [])
        wrong = training_target.parse_hit(report(item=777108, entity=200))
        self.assertEqual(target.hit(wrong, owned_items=(777108,), kinds={777108: 'SHOTGUN'}, now=11), [])
        self.assertEqual(target.dp.consumed, 800)


if __name__ == '__main__':
    unittest.main()
