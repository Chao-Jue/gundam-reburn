
'use strict';
(function () {
  const IMG = 0x400000;

  // [槽地址, 名字]；槽地址 = vtable + 0x54
  const CANDIDATES = [
    [0xe14d58, 'CGVOProtoLounge+0x54'],
    [0xe09ac8, '_proto_lounge+0x54'],
    [0xe14948, 'CGVOProtoAuth+0x54'],
    [0xe149e0, 'CGVOProtoBattle+0x54'],
    [0xe03548, '_proto_auth+0x54'],
    [0xe03b10, '_proto_battle+0x54'],
    [0xe63490, 'Codec@vce+0x54'],
    [0xe6a0d0, 'iProxyListener@ivce+0x54'],
    [0xcd07f8, 'CGVOProtoBattleReplaywar+0x54']
  ];
  const CODE_LO = 0x400000, CODE_HI = 0xe0c000;

  let base = null;
  try { base = Process.getModuleByName('GundamOnline_CHINA.exe').base; }
  catch (e) {
    try { base = Process.enumerateModules()[0].base; } catch (e2) { base = null; }
  }
  if (!base) { send({ ev: 'error', why: 'no module base' }); return; }
  const at = (va) => base.add(va - IMG);

  function hexOf(p, n) {
    let s = '';
    for (let i = 0; i < n; i++) {
      try { s += ('0' + p.add(i).readU8().toString(16)).slice(-2); }
      catch (e) { s += '??'; }
    }
    return s;
  }

  // ---- 采集缓冲（回调里只 push，不 send） ----
  const MAXREC = 4000;
  let records = [];
  let counters = {};
  let seq = 0;

  const logfn = new NativeCallback(function (buf, len, self, slotId) {
    const id = (typeof slotId === 'number') ? slotId : Number(slotId.toString());
    counters[id] = (counters[id] || 0) + 1;
    if (records.length >= MAXREC) return;
    const rec = { n: ++seq, slot: id, t: Date.now(), len: len };
    try {
      if (buf.isNull()) { rec.null_buf = true; }
      else {
        rec.op = buf.readU16();
        rec.head = hexOf(buf, Math.min(len > 0 ? len : 16, 24));
      }
    } catch (e) { rec.err = String(e); }
    try {
      // 闸门/配额：仅当 this 是协议对象时有意义。0xE13A 的通道号 = 0xC
      rec.gate = {
        flag: self.add(0x29e + 0x0c).readU8(),
        cnt: self.add(0x4e0 + 0x0c * 0x30).readU32(),
        lim: self.add(0x4e0 + 0x0c * 0x30 + 8).readU32(),
        per: self.add(0x4e0 + 0x0c * 0x30 + 0x10).readU32()
      };
    } catch (e) { rec.gate_err = String(e); }
    records.push(rec);
  }, 'void', ['pointer', 'int', 'pointer', 'int']);

  function u32le(n) { return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

  const slots = [];   // {addr, name, orig, stub, prot}
  for (let i = 0; i < CANDIDATES.length; i++) {
    const [va, name] = CANDIDATES[i];
    const p = at(va);
    let orig = 0, prot = 'r--';
    try {
      orig = p.readU32();
      const r = Process.findRangeByAddress(p);
      if (r && r.protection) prot = r.protection;
    } catch (e) { continue; }
    slots.push({ idx: i, name: name, addr: p, va: va, orig: orig, prot: prot, patched: false, stub: null });
  }

  let patchedAny = false;
  const logAddr = logfn.toUInt32();

  rpc.exports = {
    info() {
      return {
        base: base.toString(),
        logfn: '0x' + logAddr.toString(16),
        slots: slots.map(function (s) {
          const ok = s.orig >= CODE_LO && s.orig < CODE_HI;
          return {
            idx: s.idx, name: s.name, va: '0x' + s.va.toString(16),
            orig: '0x' + s.orig.toString(16), is_code: ok, prot: s.prot,
            patched: s.patched
          };
        })
      };
    },
    patch(skipNoCode) {
      const done = [];
      for (const s of slots) {
        const ok = s.orig >= CODE_LO && s.orig < CODE_HI;
        if (!ok && skipNoCode !== false) { done.push([s.name, 'skip(not code)']); continue; }
        const stub = Memory.alloc(64);
        const bytes = [].concat(
          [0x60],
          [0x68], u32le(s.idx),
          [0x51],
          [0xff, 0x74, 0x24, 0x30],
          [0xff, 0x74, 0x24, 0x30],
          [0xb8], u32le(logAddr),
          [0xff, 0xd0],
          [0x83, 0xc4, 0x10],
          [0x61],
          [0x68], u32le(s.orig),
          [0xc3]
        );
        Memory.protect(stub, 64, 'rwx');
        for (let i = 0; i < bytes.length; i++) stub.add(i).writeU8(bytes[i] & 0xff);
        try {
          Memory.protect(s.addr, 4, 'rw-');
          s.addr.writeU32(stub.toUInt32());
          try { Memory.protect(s.addr, 4, s.prot); } catch (e) {}
          s.stub = stub; s.patched = true; patchedAny = true;
          done.push([s.name, '0x' + s.orig.toString(16) + ' -> stub']);
        } catch (e) {
          done.push([s.name, 'FAIL ' + String(e)]);
        }
      }
      return done;
    },
    restore() {
      const done = [];
      for (const s of slots) {
        if (!s.patched) continue;
        try {
          Memory.protect(s.addr, 4, 'rw-');
          s.addr.writeU32(s.orig);
          try { Memory.protect(s.addr, 4, s.prot); } catch (e) {}
          s.patched = false;
          done.push([s.name, 'restored']);
        } catch (e) { done.push([s.name, 'FAIL ' + String(e)]); }
      }
      return done;
    },
    drain() {
      const out = records;
      records = [];
      return { seq: seq, counters: counters, records: out };
    },
    stats() { return { seq: seq, counters: counters, pending: records.length, patched: patchedAny }; }
  };
})();
