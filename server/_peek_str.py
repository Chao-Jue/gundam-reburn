from pathlib import Path
img = Path("D:/project/gundam-reburn/server/img_dump/main_GundamOnline_CHINA.exe").read_bytes()
B = 0x400000
for va in (0xE8B2F8, 0xE8B2AC, 0xE8B2C0):
    b = img[va - B: va - B + 48]
    print(hex(va), repr(b.split(b"\x00")[0][:48]))
