import sys, os, zipfile, struct, hashlib
out_a, out_u, dest = sys.argv[1:4]
SMALL = ["empty","one","text10k","random40k","mixed-32767","mixed-32768","mixed-32769","mixed-65535","mixed-65536"]
def entry(path):
    with zipfile.ZipFile(path) as z:
        i = z.infolist()[0]
    b = open(path,'rb').read()
    o = i.header_offset
    assert b[o:o+4] == b'PK\x03\x04'
    nl, el = struct.unpack('<HH', b[o+26:o+30])
    data = b[o+30+nl+el : o+30+nl+el+i.compress_size]
    return dict(method=i.compress_type, flags=i.flag_bits, crc=i.CRC, csize=i.compress_size, text=i.internal_attr & 1, data=data)
lines = []
bad = 0
os.makedirs(dest, exist_ok=True)
for f in sorted(os.listdir(out_a)):
    a = entry(os.path.join(out_a, f)); u = entry(os.path.join(out_u, f))
    for k in ('method','crc','csize','text','data'):
        if a[k] != u[k]:
            print("DIFF", f, k); bad += 1
    if (a['flags'] & 6) != (u['flags'] & 6):
        print("DIFF flags", f, a['flags'], u['flags']); bad += 1
    case, mode, level, _ = f.split('.')
    print(f, a['method'], hex(a['flags']), a['csize'], hashlib.sha256(a['data']).hexdigest()[:16])
    if case in SMALL:
        name = '-'
        if a['method'] == 8:
            name = hashlib.sha256(a["data"]).hexdigest()[:16] + ".deflate"
            open(os.path.join(dest, name), 'wb').write(a['data'])
        lines.append((SMALL.index(case), mode, int(level), f"{case} {mode} {level} {a['method']} {a['flags']:04x} {a['crc']:08x} {a['csize']} {a['text']} {name}"))
lines.sort()
with open(os.path.join(dest, 'MANIFEST'), 'w') as m:
    m.write("# case mode level method gp-flags(hex) crc32(hex) csize text data-file\n")
    for l in lines: m.write(l[3] + "\n")
print("differences:", bad)
