"""武器特效匹配的回归测试：DXG 挂点、VRA 解析、组合渲染、服务兜底。

用真实客户端资源跑（只读）。资源不存在时跳过对应用例，不伪造结论。
"""
import sys
import unittest
from pathlib import Path

tools = Path(__file__).resolve().parent
sys.path.insert(0, str(tools))

import effect_lib
import effect_render
import weapon_effect_match as match

ASSETS = match.ASSETS
GUN = ASSETS / 'item/02/0106/model/EM_02_0106_01.dxg'
SABER = ASSETS / 'item/04/0101/model/EM_04_0101_01.dxg'
BLADE_MODEL = ASSETS / 'fx/02/model/PM_02_001_02.dxg'
FLASH = ASSETS / 'fx/01/PP_01_100_01.vra'
BLADE = ASSETS / 'fx/02/PP_02_001_01.vra'
TRAIL = ASSETS / 'fx/01/PP_01_001_01.vra'
needs_assets = unittest.skipUnless(GUN.exists() and FLASH.exists(), '需要客户端解密资源')


class SocketTest(unittest.TestCase):
    @needs_assets
    def test_kind1_socket_block_is_not_a_mesh(self):
        """回归：静态武器把挂点写成 kind=1，曾被当成网格组报「mesh 数量无效」。"""
        model = effect_render.load_model(GUN)
        self.assertEqual([m['name'] for m in model['meshes']], ['EM_02_0106_01_BRGP1'])
        names = [s['name'] for s in model['sockets']]
        self.assertIn('s_shot01', names)
        socket = model['sockets'][names.index('s_shot01')]
        # 枪口在 +Z 前端，位置应贴住包围盒最前面
        self.assertGreater(socket['matrix'][14], 60.0)

    @unittest.skipUnless(SABER.exists(), '需要客户端解密资源')
    def test_kind2_node_block_gives_saber_sockets(self):
        """军刀用 kind=2 节点块：s_shot01 刀柄端、s_shot02 刀尖。"""
        model = effect_render.load_model(SABER)
        sockets = {s['name']: s['matrix'] for s in model['sockets']}
        self.assertIn('s_shot01', sockets)
        self.assertIn('s_shot02', sockets)
        self.assertAlmostEqual(sockets['s_shot01'][13], 16.59, delta=0.5)
        self.assertAlmostEqual(sockets['s_shot02'][13], 157.28, delta=0.5)

    @unittest.skipUnless(BLADE_MODEL.exists(), '需要客户端解密资源')
    def test_effect_model_dxg_15_is_readable(self):
        """fx/ 的特效模型是 DXG 1.5，布局与 1.8 一致，应能读出网格。"""
        model = effect_render.load_model(BLADE_MODEL)
        self.assertEqual(model['version'], '1.5')
        self.assertGreater(sum(len(m['indices']) // 3 for m in model['meshes']), 0)


class EffectLibTest(unittest.TestCase):
    @unittest.skipUnless(FLASH.exists(), '需要客户端解密资源')
    def test_flash_structure(self):
        effect = effect_lib.load(FLASH)
        self.assertEqual(effect.frame, 15)
        self.assertEqual(effect.loop, 0)
        self.assertIn('Sprite', effect.kinds)
        self.assertIn('Particle', effect.kinds)
        self.assertIn('fx/image/PT_01_100_01.png', effect.textures)
        self.assertTrue(effect.sounds)
        self.assertEqual([p['name'] for p in effect.plugs][:2], ['PP_01_100_01', 'Ring'])

    @unittest.skipUnless(BLADE.exists(), '需要客户端解密资源')
    def test_model_effect_points_at_attribute_vra(self):
        """Model 的模型路径写在 {attribute (Geometry ...)} 里，不是 file。"""
        effect = effect_lib.load(BLADE)
        self.assertIn('fx/02/attr/PZ_02_001_02.vra', effect.attr_models)
        attr = effect_lib.load(ASSETS / 'fx/02/attr/PZ_02_001_02.vra')
        self.assertEqual(attr.dxg, ['fx/02/model/PM_02_001_02.dxg'])

    @unittest.skipUnless(BLADE.exists(), '需要客户端解密资源')
    def test_single_key_curve_is_padded(self):
        """Rot/Scale 常只有一个关键值，补齐后才不会解包失败。"""
        effect = effect_lib.load(BLADE)
        rot = None
        for plug in effect.plugs:
            if 'Rot' in plug['work']:
                rot = effect_lib.sample(plug['work']['Rot'], 0.5, 'rot', [0, 0, 0])
                break
        self.assertIsNotNone(rot)
        self.assertEqual(len(effect_render.pad(rot, 3, 0.0)), 3)

    @unittest.skipUnless(FLASH.exists(), '需要客户端解密资源')
    def test_classification_uses_names_and_structure(self):
        flash = effect_lib.load(FLASH)
        blade = effect_lib.load(BLADE)
        self.assertIn('other', flash.tags)          # 无名枪口闪光，不硬编成 muzzle
        self.assertIn('blade', blade.tags)          # 命名里有「刀身」
        self.assertIn('model', blade.tags)          # 有 Model 对象

    @unittest.skipUnless(FLASH.exists(), '需要客户端解密资源')
    def test_best_ratio_lands_inside_object_window(self):
        effect = effect_lib.load(FLASH)
        ratio = effect.best_ratio()
        # 该特效应在 0~0.2 内出现粒子，其余时间只剩外圈
        self.assertTrue(0.0 < ratio < 1.0)
        self.assertTrue(effect.active(ratio))


class ComposeTest(unittest.TestCase):
    @needs_assets
    def test_muzzle_flash_is_drawn_at_socket(self):
        effect = effect_lib.load(FLASH)
        image, meta = effect_render.compose(ASSETS, GUN, effect, 0.2, size=(320, 200))
        self.assertEqual(meta['socket'], 's_shot01')
        self.assertTrue(meta['drawn'])
        self.assertEqual(image.size, (320, 200))
        # 有特效的一帧应比空帧更亮（粉光叠加在枪口）
        blank = effect_render.compose(ASSETS, GUN, effect, 0.95, size=(320, 200))[0]
        import numpy as np
        self.assertGreater(float(np.asarray(image).mean()), float(np.asarray(blank).mean()))

    @unittest.skipUnless(SABER.exists() and BLADE.exists(), '需要客户端解密资源')
    def test_saber_composes_hilt_and_blade(self):
        effect = effect_lib.load(BLADE)
        image, meta = effect_render.compose(ASSETS, SABER, effect, 0.5, size=(320, 200))
        self.assertEqual(meta['socket'], 's_shot01')
        self.assertTrue(any('Model' in d for d in meta['drawn']))

    @unittest.skipUnless(GUN.exists() and TRAIL.exists(), '需要客户端解密资源')
    def test_trail_is_drawn_not_skipped(self):
        effect = effect_lib.load(TRAIL)
        _image, meta = effect_render.compose(ASSETS, GUN, effect, 0.5, size=(320, 200))
        self.assertTrue(any('Trail' in d for d in meta['drawn']))

    @needs_assets
    def test_effect_without_own_socket_falls_back_to_weapon_shot01(self):
        effect = effect_lib.load(FLASH)
        socket, how = effect_render.pick_socket(
            effect_render.load_model(GUN)['sockets'], effect.target['owner'])
        self.assertEqual((socket['name'], how), ('s_shot01', 's_shot01'))


class ServerTest(unittest.TestCase):
    @needs_assets
    def test_preview_falls_back_on_broken_effect(self):
        """单个特效画不出来时不能让页面出现破图：返回占位 PNG + 错误说明。"""
        image, meta = match.preview(str(GUN), 'fx/00/missing.vra', 0.3, 160, 100)
        self.assertIn('error', meta)
        self.assertEqual(image[:8], b'\x89PNG\r\n\x1a\n')

    @needs_assets
    def test_preview_caches_and_returns_png(self):
        image, meta = match.preview(str(GUN), 'fx/01/PP_01_100_01.vra', 0.2, 160, 100)
        self.assertNotIn('error', meta)
        self.assertEqual(image[:8], b'\x89PNG\r\n\x1a\n')


if __name__ == '__main__':
    unittest.main()
