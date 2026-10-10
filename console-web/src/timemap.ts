// loginAllowedTimeMap: 42 bytes, 336 bits = 7 days x 48 half-hours, Sunday 00:00 first. Bit n is in
// byte n >> 3, least significant bit first (measured on ig4: the first half-hour is 0x01 in byte 0,
// the last is 0x80 in byte 41). A set bit allows login.

export const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
export const SLOTS = 48;

export function decode(hex: string | null): boolean[] {
  if (!hex) {
    return new Array(DAYS.length * SLOTS).fill(true); // no map: no restriction
  }
  const out: boolean[] = [];
  for (let i = 0; i < DAYS.length * SLOTS; i++) {
    const byte = parseInt(hex.substr((i >> 3) * 2, 2), 16);
    out.push(((byte >> (i & 7)) & 1) === 1);
  }
  return out;
}

export function encode(bits: boolean[]): string {
  const bytes = new Array(42).fill(0);
  bits.forEach((on, i) => {
    if (on) {
      bytes[i >> 3] |= 1 << (i & 7);
    }
  });
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function slot(day: number, half: number): number {
  return day * SLOTS + half;
}

export function label(half: number): string {
  const h = Math.floor(half / 2);
  return `${String(h).padStart(2, '0')}:${half % 2 ? '30' : '00'}`;
}
