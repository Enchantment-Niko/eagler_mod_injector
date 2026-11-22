import struct
import json
import lzma
import re
import base64
import binascii
import os
import sys
import argparse

def extract_epw_from_html(html_path):
    with open(html_path, 'r', encoding='utf-8', errors='replace') as f:
        html = f.read()
    m = re.search(
        r'data:application/octet-stream;base64,([A-Za-z0-9+/=]+)', html)
    if not m:
        raise ValueError("在 HTML 里找不到 EPW 的 base64 数据")
    return base64.b64decode(m.group(1)), html, m.group(1)

def get_epk_entries(epw):
    num = struct.unpack('<I', epw[0x60:0x64])[0]
    out = []
    for i in range(num):
        base = 0x114 + 32 * i
        fp_off = struct.unpack('<I', epw[base:base+4])[0]
        fp_len = struct.unpack('<I', epw[base+4:base+8])[0]
        lp_off = struct.unpack('<I', epw[base+8:base+12])[0]
        lp_len = struct.unpack('<I', epw[base+12:base+16])[0]
        fd_off = struct.unpack('<I', epw[base+16:base+20])[0]
        fd_clen = struct.unpack('<I', epw[base+20:base+24])[0]
        fd_dlen = struct.unpack('<I', epw[base+24:base+28])[0]
        try:
            fp = epw[fp_off:fp_off+fp_len].decode('utf-8', 'replace')
            lp = epw[lp_off:lp_off+lp_len].decode('utf-8', 'replace')
        except Exception:
            fp, lp = '?', '?'
        out.append({'index': i, 'filePath': fp, 'loadPath': lp,
                    'off': fd_off, 'clen': fd_clen, 'dlen': fd_dlen})
    return out

def xz_decompress(data):
    return lzma.decompress(data)

def xz_compress(data):

    c = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=6,
                             check=lzma.CHECK_CRC32)
    return c.compress(data) + c.flush()

def parse_epk_header(epk):
    p = 8                       
    ver_len = epk[p]; p += 1
    p += ver_len
    fn_len = epk[p]; p += 1
    p += fn_len
    comment_len = struct.unpack('>H', epk[p:p+2])[0]; p += 2
    p += comment_len
    p += 8                       
    fc_off = p
    file_count = struct.unpack('>i', epk[p:p+4])[0]; p += 4
    p += 1                    
    data_start = p
    return fc_off, file_count, data_start

def iter_epk_entries(epk, data_start):

    pos = data_start
    end = epk.find(b'END$', data_start)
    if end == -1:
        end = len(epk)
    entries = []
    while pos < end:
        tag = epk[pos:pos+4]
        if tag in (b'FILE', b'HEAD'):
            namelen = epk[pos+4]
            name = epk[pos+5:pos+5+namelen].decode('utf-8', 'replace')
            dl_start = pos + 5 + namelen
            dl = struct.unpack('>i', epk[dl_start:dl_start+4])[0]
            data_off = dl_start + 8                             
            data_len = dl - 5                              
            entry_end = data_off + data_len + 2          
            entries.append({
                'tag': tag.decode(),
                'name': name,
                'entry_start': pos,
                'entry_end': entry_end,
                'data_off': data_off,
                'data_len': data_len,
            })
            pos = entry_end
        else:
            pos += 1
    return entries, end

def build_epk_file_entry(name, file_data):
    crc = binascii.crc32(file_data) & 0xFFFFFFFF
    name_bytes = name.encode('utf-8')
    data_len = len(file_data) + 5                          
    entry = b'FILE'
    entry += bytes([len(name_bytes)])
    entry += name_bytes
    entry += struct.pack('>i', data_len)
    entry += struct.pack('>I', crc)
    entry += file_data
    entry += b':>'
    return entry

def inject_file_into_epk(epk, target_name, file_bytes):

    fc_off, file_count, data_start = parse_epk_header(epk)
    entries, end_pos = iter_epk_entries(epk, data_start)

    existing = None
    for e in entries:
        if e['tag'] == 'FILE' and e['name'] == target_name:
            existing = e
            break

    end_marker_off = epk.find(b'END$', data_start)
    if end_marker_off == -1:
        raise ValueError("在 EPK 里找不到 END$ 标记")

    if existing is not None:

        new_epk = epk[:existing['entry_start']] + epk[existing['entry_end']:]

        end_marker_off = new_epk.find(b'END$', data_start)
        action = 'replaced'
        new_count = file_count           
    else:
        new_epk = epk
        action = 'added'
        new_count = file_count + 1

    new_entry = build_epk_file_entry(target_name, file_bytes)
    new_epk = new_epk[:end_marker_off] + new_entry + new_epk[end_marker_off:]

    new_epk = (new_epk[:fc_off] + struct.pack('>i', new_count)
               + new_epk[fc_off+4:])

    return new_epk, True, action

def rebuild_epw_generic(original_epw, modifications):

    new_epw = bytearray(original_epw)
    for epk_index, new_xz, new_dlen in modifications:
        base = 0x114 + 32 * epk_index
        fd_off = struct.unpack('<I', new_epw[base+16:base+20])[0]
        fd_clen = struct.unpack('<I', new_epw[base+20:base+24])[0]

        if len(new_xz) <= fd_clen:

            new_epw[fd_off:fd_off+fd_clen] = new_xz + b'\x00' * (fd_clen - len(new_xz))
            struct.pack_into('<I', new_epw, base+20, len(new_xz))
            struct.pack_into('<I', new_epw, base+24, new_dlen)
        else:

            tail = len(new_epw)
            new_epw.extend(new_xz)
            struct.pack_into('<I', new_epw, base+16, tail)
            struct.pack_into('<I', new_epw, base+20, len(new_xz))
            struct.pack_into('<I', new_epw, base+24, new_dlen)

    struct.pack_into('<I', new_epw, 0x08, len(new_epw))

    struct.pack_into('<I', new_epw, 0x0C, 0)

    crc = binascii.crc32(bytes(new_epw[0x10:])) & 0xFFFFFFFF
    struct.pack_into('<I', new_epw, 0x0C, crc)
    return bytes(new_epw)

def is_resource_entry(name):

    if name.startswith('assets/') or name.startswith('data/'):
        return True
    base = name.split('/')[-1]
    if base in ('pack.mcmeta', 'pack.png', 'pack.png.mcmeta'):
        return True
    return False

def collect_jar_files(jar_path):

    import zipfile
    res = []
    skip = []
    with zipfile.ZipFile(jar_path) as z:
        for info in z.infolist():
            name = info.filename
            if name.endswith('/'):                  
                continue
            if is_resource_entry(name):
                with z.open(info) as f:
                    res.append((name, f.read()))
            else:
                skip.append(name)
    return res, skip

def mode_list(args):
    epw = load_epw(args)
    entries = get_epk_entries(epw)
    print(f"EPW 包含 {len(entries)} 个 EPK 档案：\n")
    for e in entries:
        print(f"  [{e['index']}] {e['filePath']}  (挂载路径: {e['loadPath']})")
    print()
    if args.epk is None:
        return
    e = entries[args.epk]
    print(f"读取 EPK[{args.epk}] {e['filePath']} ...")
    epk = xz_decompress(epw[e['off']:e['off']+e['clen']])
    print(f"  解压后大小: {len(epk)} 字节")
    all_entries, _ = iter_epk_entries(epk, parse_epk_header(epk)[2])
    print(f"  共 {len(all_entries)} 个条目\n")
    shown = 0
    for ent in all_entries:
        if args.search and args.search.lower() not in ent['name'].lower():
            continue
        print(f"    {ent['tag']:4}  {ent['name']}")
        shown += 1
        if args.limit and shown >= args.limit:
            print("    ... (用 --limit 调整上限，或 --search 过滤)")
            break
    if shown == 0:
        print("    （没有匹配的文件）")

def mode_extract(args):
    epw = load_epw(args)
    entries = get_epk_entries(epw)
    e = entries[args.epk]
    epk = xz_decompress(epw[e['off']:e['off']+e['clen']])
    _, data_start = parse_epk_header(epk)[0], parse_epk_header(epk)[2]
    all_entries, _ = iter_epk_entries(epk, data_start)
    found = [x for x in all_entries if x['name'] == args.name]
    if not found:
        print(f"在 EPK[{args.epk}] 里找不到文件: {args.name}")
        return
    x = found[0]
    data = epk[x['data_off']:x['data_off']+x['data_len']]
    out = args.output or os.path.basename(args.name)
    with open(out, 'wb') as f:
        f.write(data)
    print(f"已提取: {args.name} -> {out}  ({len(data)} 字节)")

def mode_inject(args):
    epw, html_text, b64 = (None, None, None)
    if args.html:
        epw, html_text, b64 = extract_epw_from_html(args.html)
    else:
        with open(args.epw, 'rb') as f:
            epw = f.read()

    entries = get_epk_entries(epw)
    if args.epk >= len(entries):
        raise ValueError(f"EPK 索引 {args.epk} 超出范围 (共 {len(entries)} 个)")
    e = entries[args.epk]
    print(f"目标 EPK[{args.epk}] {e['filePath']}  挂载: {e['loadPath']}")

    epk = bytearray(xz_decompress(epw[e['off']:e['off']+e['clen']]))
    original_epk = bytes(epk)
    fc_off, file_count, data_start = parse_epk_header(epk)

    to_inject = []
    skipped = []
    src = args.source
    if src.lower().endswith('.jar'):
        print(f"检测到 mod jar：{src}")
        to_inject, skipped = collect_jar_files(src)
        print(f"  可注入资源文件: {len(to_inject)} 个")
        print(f"  跳过(代码/Fabric配置): {len(skipped)} 个")
    elif os.path.isdir(src):
        for root, _, files in os.walk(src):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, src).replace(os.sep, '/')
                target = (args.target.rstrip('/') + '/' + rel) if args.target else rel
                with open(full, 'rb') as f:
                    to_inject.append((target, f.read()))
    else:
        with open(src, 'rb') as f:
            data = f.read()
        base = os.path.basename(src)
        target = (args.target.rstrip('/') + '/' + base) if args.target else base
        to_inject.append((target, data))

    changed_any = False
    for target, data in to_inject:

        lp = e['loadPath'].strip('/')
        if lp and not target.startswith(lp):

            target = (lp.rstrip('/') + '/' + target.lstrip('/'))
        new_epk, changed, action = inject_file_into_epk(
            bytes(epk), target, data)
        epk = bytearray(new_epk)
        if changed:
            changed_any = True
            size_kb = len(data) / 1024
            print(f"  [{action:7}] {target}  ({size_kb:.1f} KB)")
        else:
            print(f"  [skip   ] {target} (无变化)")

    if skipped:
        print(f"\n⚠️ 已跳过 {len(skipped)} 个代码/Fabric 配置文件")
        print("   （.class / fabric.mod.json / *.mixins.json / META-INF 等）。")
        print("   Eaglercraft WASM-GC 把 Java 编译进了 wasm，运行时无法")
        print("   加载 Fabric 字节码，这些文件即使写入游戏包也无法提供 mod 功能；")
        print("   只有资源类（assets/、data/、pack.mcmeta）会被真正注入并可用。")

    if not changed_any:
        print("\n没有任何文件被修改，跳过重建。")
        return

    new_epk_bytes = bytes(epk)
    new_xz = xz_compress(new_epk_bytes)
    print(f"\nEPK 解压大小: {len(new_epk_bytes)} 字节, 压缩后: {len(new_xz)} 字节")
    new_epw = rebuild_epw_generic(epw, [(args.epk, new_xz, len(new_epk_bytes))])

    assert new_epw[:8] == b'EAG$WASM', "魔术字不匹配"
    fl = struct.unpack('<I', new_epw[8:12])[0]
    assert fl == len(new_epw), f"长度不匹配 {fl} != {len(new_epw)}"
    crc_stored = struct.unpack('<I', new_epw[12:16])[0]
    crc_calc = binascii.crc32(new_epw[0x10:]) & 0xFFFFFFFF
    assert crc_stored == crc_calc, "CRC32 校验失败"
    print("EPW 校验通过 (magic/length/CRC32 OK)")

    if args.html and args.output:
        new_b64 = base64.b64encode(new_epw).decode('ascii')
        new_html = html_text.replace(b64, new_b64)
        assert new_b64 in new_html, "base64 替换失败"
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(new_html)
        sz = os.path.getsize(args.output)
        print(f"\n✅ 已写出: {args.output}  ({sz/1024/1024:.1f} MB)")
    elif args.epw and args.output_epw:
        with open(args.output_epw, 'wb') as f:
            f.write(new_epw)
        print(f"\n✅ 已写出: {args.output_epw}  ({len(new_epw)/1024/1024:.1f} MB)")
    else:
        print("\n⚠️ 未指定输出路径，未写出文件。")

def load_epw(args):
    if args.html:
        return extract_epw_from_html(args.html)[0]
    with open(args.epw, 'rb') as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser(
        description='Eaglercraft WASM-GC 资源/Mod 注入工具',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)

    def add_common(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument('--html', help='输入的 HTML 文件')
        g.add_argument('--epw', help='输入的 EPW 文件（已提取的）')

    p_list = sub.add_parser('list', help='列出 EPK 里的文件')
    add_common(p_list)
    p_list.add_argument('--epk', type=int, default=None,
                        help='要列出内容的 EPK 索引 (默认只列 EPK 列表)')
    p_list.add_argument('--search', help='按文件名过滤')
    p_list.add_argument('--limit', type=int, default=50, help='最多显示条数')

    p_ext = sub.add_parser('extract', help='提取 EPK 中的某个文件')
    add_common(p_ext)
    p_ext.add_argument('--epk', type=int, default=0)
    p_ext.add_argument('--name', required=True, help='EPK 内文件路径')
    p_ext.add_argument('--output', help='输出文件路径')

    p_inj = sub.add_parser('inject', help='把文件/目录注入到 EPK')
    add_common(p_inj)
    p_inj.add_argument('--epk', type=int, default=0,
                       help='目标 EPK 索引 (默认 0 = 主资源包)')
    p_inj.add_argument('--source', required=True,
                       help='要注入的文件、目录、或 .jar mod 包')
    p_inj.add_argument('--target', default='',
                       help='注入后在 EPK 内的路径前缀 (可选)')
    p_inj.add_argument('--output', help='输出 HTML 路径 (配合 --html)')
    p_inj.add_argument('--output-epw', help='输出 EPW 路径 (配合 --epw)')

    args = parser.parse_args()

    if args.cmd == 'list':
        mode_list(args)
    elif args.cmd == 'extract':
        mode_extract(args)
    elif args.cmd == 'inject':
        mode_inject(args)

if __name__ == '__main__':
    main()