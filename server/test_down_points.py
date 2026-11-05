"""DP is independent of experimental HP damage and counted only on accepted hits."""
import unittest
import training_target
import down_points
from test_training_target import report


class TargetDPTest(unittest.TestCase):
    def test_airborne_gun_break_tumbles_instead_of_kneeling(self):
        from unittest.mock import patch
        target = training_target.Target((0, 1000, 0))
        target.airborne = True
        with patch.object(down_points, 'weapon_points', return_value={777108: 800}):
            for frame, now in ((1, 1.), (2, 1.5)):
                replies = target.hit(training_target.parse_hit(report(item=777108, frame=frame)),
                    owned_items=(777108,), kinds={777108: 'SHOTGUN'}, now=now)
        self.assertIn(0xa8f2, [op for op, _ in replies])
        self.assertNotIn(0xe332, [op for op, _ in replies])

    def test_test_shotgun_has_explicit_dp_for_air_break_testing(self):
        self.assertEqual(down_points.weapon_points().get(777108), 800)

    def test_reaction_expiry_emits_one_recovery_snapshot_without_another_hit(self):
        target = training_target.Target((12000, -2600, 18000))
        target.begin_melee(777106, now=1., duration=.366, dash=True)
        target.hit(training_target.parse_hit(report(item=777106)),
                   owned_items=(777106,), kinds={777106:'WRESTLE'}, now=1.)
        tick = getattr(target, 'tick', lambda **kw: [])
        active=tick(now=1.4)
        self.assertEqual([op for op,_ in active],[0x5eea],
                         'tumble must synchronize grounded active state before recovery')
        self.assertEqual(active[0][1][76],0x10)
        replies = tick(now=2.5)
        self.assertEqual([op for op, _ in replies], [0x5eea],
                         'remote target needs explicit dirty state bits to consume recovery')
        self.assertEqual(tick(now=3.), [])

    def strike(self, target, now, frame):
        target.begin_melee(777106, now=now, duration=.5)
        return target.hit(training_target.parse_hit(report(item=777106, frame=frame)),
                          owned_items=(777106,), kinds={777106: 'WRESTLE'}, now=now)

    def test_two_normal_sabers_trigger_flinch_then_kneel(self):
        target = training_target.Target((0, 0, 0))
        first = self.strike(target, 1., 1)
        self.assertIn(0x45fc, [op for op, _ in first],
                      '820 DP must cross the GM 800 flinch threshold')
        second = self.strike(target, 2., 2)
        self.assertIn(0xe332, [op for op, _ in second],
                      '1640 accumulated DP must cross the GM 1600 kneel threshold')
        self.assertEqual(target.hp, training_target.HP-500)

    def test_recovered_gauge_starts_with_flinch_again(self):
        target = training_target.Target((0, 0, 0))
        self.strike(target, 1., 1)
        result = self.strike(target, 20., 2)
        self.assertIn(0x45fc, [op for op, _ in result])
        self.assertNotIn(0xe332, [op for op, _ in result])

    def test_replay_does_not_increment_dp_and_dash_forces_tumble(self):
        target = training_target.Target((0, 0, 0))
        self.strike(target, 1., 1)
        replay = training_target.parse_hit(report(item=777106, frame=1))
        self.assertEqual(target.hit(replay, owned_items=(777106,),
                                   kinds={777106: 'WRESTLE'}, now=1.25), [])
        self.assertEqual(target.dp.consumed, 820)
        target = training_target.Target((0, 0, 0))
        target.begin_melee(777106, now=1., duration=.366, dash=True)
        replies = target.hit(replay, owned_items=(777106,), kinds={777106: 'WRESTLE'}, now=1.)
        self.assertIn(0xa8f2, [op for op, _ in replies])


class GaugeTest(unittest.TestCase):
    def test_threshold_boundary_and_single_reaction_on_large_hit(self):
        gauge = down_points.Gauge()
        self.assertIsNone(gauge.hit(799, now=0))
        self.assertEqual(gauge.hit(1, now=.2), 'flinch')
        self.assertIsNone(gauge.hit(100, now=.3))
        self.assertEqual(gauge.consumed, 800)
        self.assertEqual(gauge.hit(800, now=.6), 'kneel')
        self.assertIsNone(gauge.hit(1600, now=1.))
        self.assertEqual(gauge.hit(1600, now=2.), 'kneel')
        self.assertEqual(down_points.Gauge().hit(9999, now=0, airborne=True), 'tumble')

    def test_recovery_is_lazy_continuous_interruptible_and_rearms_when_full(self):
        gauge = down_points.Gauge()
        gauge.hit(600, now=0)
        gauge.advance(2.)
        self.assertEqual(gauge.consumed, 600)
        gauge.advance(2.5)
        self.assertEqual(gauge.consumed, 200)
        gauge.hit(100, now=2.5)
        gauge.advance(4.5)
        self.assertEqual(gauge.consumed, 300)
        gauge.advance(5.)
        self.assertEqual(gauge.consumed, 0)
        self.assertEqual(gauge.hit(800, now=5.), 'flinch')
        gauge.advance(20.)
        self.assertEqual(gauge.hit(800, now=20.), 'flinch')

    def test_missing_weapon_dp_is_not_invented_from_hp_or_pellet_count(self):
        self.assertEqual(down_points.weapon_points()[777101], 49)
        self.assertEqual(down_points.weapon_points()[777102], 800)
        self.assertEqual(down_points.weapon_points()[777106], 820)
        self.assertNotIn(999999, down_points.weapon_points())
