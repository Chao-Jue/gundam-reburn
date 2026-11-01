from pathlib import Path
import unittest


class LauncherFormatTest(unittest.TestCase):
    def test_cmd_has_windows_line_endings(self):
        data = Path(__file__).with_name('start_local.cmd').read_bytes()
        self.assertNotIn(b'\n', data.replace(b'\r\n', b''),
                         'cmd.exe misparses this launcher with bare LF lines')
        self.assertTrue(data.startswith(b'@echo off\r\n'))


if __name__ == '__main__':
    unittest.main()
