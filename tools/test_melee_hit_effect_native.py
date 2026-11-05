import csv,io,struct,unittest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP
import test_projectile_presentation_native as machine
import hangar_experiment,training_target

class MeleeHitEffectNativeTest(unittest.TestCase):
    def branch(self,flags):
        u=machine.ProjectilePresentationNativeTest().machine();stack=0x20008000
        u.reg_write(UC_X86_REG_ESP,stack);u.mem_write(stack+0x9c,struct.pack('<I',flags))
        paths={0x4a5dce:'shield',0x4a5d49:'impact',0x4a5d8a:'alternate',0x4a5e13:'guard',0x4a6047:'none'};got=[]
        def stop(m,a,size,data):
            if a in paths:got.append(paths[a]);m.emu_stop()
        u.hook_add(UC_HOOK_CODE,stop);u.emu_start(0x4a5d36,0x4a6266,count=100)
        return got[0]
    def test_native_feedback_flag_controls(self):
        self.assertEqual(self.branch(0),'none');self.assertEqual(self.branch(1),'shield');self.assertEqual(self.branch(2),'impact')
    def test_generated_melee_feedback_enters_body_effect(self):
        t=training_target.Target((0,0,0));t.begin_melee(777106,now=1,duration=.5)
        r={'item':777106,'entity':200,'position':(0,100,0),'encoded_position':(0,1,0),'identity':(1,0,777106,0,0),'direction':0,'region':0}
        replies=t.hit(r,owned_items={777106},kinds={777106:'WRESTLE'},now=1.2)
        flags=struct.unpack_from('<H',dict(replies)[0xddf7],6)[0]
        self.assertEqual(self.branch(flags),'impact')
        self.assertEqual(flags & 1,0,'shield-defense camera prompt must remain off')
    def test_melee_body_impact_has_existing_resource_and_scale(self):
        rows=list(csv.reader(io.StringIO(hangar_experiment.weapon_tables('item/weapon_settings.csv').decode())))[2:]
        assets=machine.ROOT/'GundamOnline_CHINA_已解密/decrypted'
        for r in rows:
            if r[30]!='WRESTLE':continue
            with self.subTest(item=r[0]):
                self.assertTrue(r[39],'CSV39 is impact effect, separate from shield branch')
                self.assertGreater(float(r[40] or 0),0)
                self.assertTrue((assets/'fx'/r[39]).is_file())
if __name__=='__main__':unittest.main()
