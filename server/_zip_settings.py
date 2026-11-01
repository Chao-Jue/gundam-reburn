import zipfile
z = zipfile.ZipFile("D:/project/gundam-reburn/GundamOnline_CHINA_已解密.zip")
sel = [n for n in z.namelist() if n.startswith("decrypted/settings/")]
print("decrypted/settings/ 下条目", len(sel))
for n in sel:
    print("  %-58s %d" % (n, z.getinfo(n).file_size))
