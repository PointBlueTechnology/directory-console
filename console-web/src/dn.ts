// Just enough RFC 4514 to decide whether one DN is at or under another, for what the UI offers. The
// server decides for real (Names.within); this only keeps the UI from offering what it would refuse.

/** The RDNs of {@code dn}, leaf first, each normalised (types and values case-folded, AVAs sorted). */
export function rdns(dn: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < dn.length; i++) {
    const c = dn[i];
    if (c === '\\' && i + 1 < dn.length) {
      cur += c + dn[++i];
    } else if (c === ',' || c === ';') {
      out.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  if (cur.trim() !== '' || out.length > 0) {
    out.push(cur);
  }
  return out.map(normalise).filter((r) => r !== '');
}

function normalise(rdn: string): string {
  const avas: string[] = [];
  let cur = '';
  for (let i = 0; i < rdn.length; i++) {
    const c = rdn[i];
    if (c === '\\' && i + 1 < rdn.length) {
      cur += c + rdn[++i];
    } else if (c === '+') {
      avas.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  avas.push(cur);
  return avas.map((a) => {
    const eq = a.indexOf('=');
    return eq < 0 ? a.trim().toLowerCase() : `${a.slice(0, eq).trim().toLowerCase()}=${a.slice(eq + 1).trim().toLowerCase()}`;
  }).sort().join('+');
}

/** Whether {@code dn} is {@code ancestor} or underneath it. */
export function within(dn: string, ancestor: string): boolean {
  const d = rdns(dn);
  const a = rdns(ancestor);
  if (a.length > d.length) {
    return false;
  }
  const offset = d.length - a.length;
  return a.every((r, i) => d[offset + i] === r);
}
