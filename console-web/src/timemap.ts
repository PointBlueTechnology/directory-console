// loginAllowedTimeMap: 42 bytes, 336 bits = 7 days x 48 half-hours, Sunday 00:00 UTC first (eDirectory
// keeps times in UTC; iManager shows the grid in the workstation's time zone). Bit n is in
// byte n >> 3, least significant bit first (measured on a lab tree: the first half-hour is 0x01 in byte 0,
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

/**
 * The half-hours to add to UTC for {@code date}'s local time in this browser (Chicago in summer: -10),
 * or null when the zone is not a whole number of half-hours from UTC (such as +05:45).
 */
export function localShift(date = new Date()): number | null {
  const minutes = -date.getTimezoneOffset();
  return minutes % 30 === 0 ? minutes / 30 : null;
}

/** The week's half-hours seen {@code shift} half-hours from UTC: view[i] is UTC slot i - shift. */
export function toView(utc: boolean[], shift: number): boolean[] {
  const n = utc.length;
  return utc.map((_, i) => utc[(((i - shift) % n) + n) % n]);
}

/** The inverse of {@link toView}: UTC slots from a view {@code shift} half-hours from UTC. */
export function fromView(view: boolean[], shift: number): boolean[] {
  return toView(view, -shift);
}
