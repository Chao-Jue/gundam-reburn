import zipfile
z = zipfile.ZipFile("D:/project/gundam-reburn/GundamOnline_CHINA_已解密.zip")
names = z.namelist()
print("总条目", len(names))
print("前 8 条:", names[:8])
hit = [n for n in names if "settings" in n.lower()]
print("含 settings 的条目数", len(hit))
for n in hit[:10]:
    print("  ", n, z.getinfo(n).file_size)
dev = [n for n in names if "develop" in n.lower()]
print("含 develop 的条目数", len(dev))
for n in dev[:6]:
    print("  ", n, z.getinfo(n).file_size)
