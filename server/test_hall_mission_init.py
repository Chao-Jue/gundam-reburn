import unittest

import fake_auth


class HallMissionInitTest(unittest.TestCase):
    def test_scene_transition_pushes_mission_info_needed_by_main_menu(self):
        # Current exe: task 0x9EA89D waits for game+0x312B0;
        # DBBC -> vt+0x134 -> 0x43F170 sets that flag.
        pushes = fake_auth.hall_replies(0xC475, bytes(4), 'test')
        self.assertIn((0xDBBC, bytes(97)), pushes)
        self.assertIn(0xC475, fake_auth.HALL_OPS)
        self.assertNotIn(0xC475, fake_auth.HALL_NO_REPLY_OPS)

    def test_member_poll_does_not_repeat_mission_initialization(self):
        pushes = fake_auth.hall_replies(0xD377, bytes(4), 'test')
        self.assertNotIn(0xDBBC, [op for op, body in pushes])


if __name__ == '__main__':
    unittest.main()
