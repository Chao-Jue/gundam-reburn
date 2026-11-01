import unittest
import numpy as np
from PIL import Image, ImageDraw
from weapon_icon_match import normalize, descriptor, references


class IconMatchTest(unittest.TestCase):
    def test_blue_striped_panel_does_not_dominate_comparison(self):
        im=Image.new('RGB',(98,34));draw=ImageDraw.Draw(im)
        for y in range(34):draw.line((0,y,97,y),fill=(5,40,90) if y%2 else (10,90,160))
        draw.rectangle((20,10,75,24),fill=(180,180,180))
        pixels=np.array(normalize(im))
        blue=(pixels[:,:,2].astype(int)>pixels[:,:,0].astype(int)*1.3)&(pixels[:,:,3]>240)
        self.assertLess(int(blue.sum()),20)

    def test_border_crop_preserves_white_inside_weapon(self):
        im=Image.new('RGB',(100,40),'white');draw=ImageDraw.Draw(im)
        draw.rectangle((15,10,80,30),fill='black');draw.rectangle((25,15,30,20),fill='white')
        processed=normalize(im)
        self.assertEqual(processed.getpixel((0,0))[3],0)
        pixels=np.array(processed)
        self.assertGreater(int(((pixels[:,:,0]>240)&(pixels[:,:,3]>240)).sum()),0)
        self.assertTrue(np.isfinite(descriptor(processed)).all())

    def test_insert_rows_inherit_but_other_templates_do_not(self):
        unit={'title':'test','source_url':'source','weapons':[
            {'name':'A','template':'武器模板','attributes':{'图片名称(png)':'枪'}},
            {'name':'B','template':'武器插入行','attributes':{}},
            {'name':'C','template':'武器模板','attributes':{}}]}
        refs=references([unit]);self.assertEqual([u['weapon'] for u in refs['枪.png']],['A','B'])
        self.assertFalse(refs['枪.png'][0]['inherited']);self.assertTrue(refs['枪.png'][1]['inherited'])


if __name__=='__main__':unittest.main()
