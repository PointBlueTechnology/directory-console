import { describe, expect, it } from 'vitest';
import { decode, encode, fromView, localShift, slot, toView } from './timemap';

describe('login time map', () => {
  it('matches what ig4 stored: first half-hour 0x01 in byte 0, last 0x80 in byte 41', () => {
    const bits = new Array(336).fill(false);
    bits[slot(0, 0)] = true;
    bits[slot(6, 47)] = true;
    expect(encode(bits)).toBe('01' + '00'.repeat(40) + '80');
    expect(decode('01' + '00'.repeat(40) + '80')).toEqual(bits);
  });

  it('treats no map as no restriction and round-trips any pattern', () => {
    expect(decode(null).every((b) => b)).toBe(true);
    const bits = Array.from({ length: 336 }, (_, i) => i % 3 === 0);
    expect(decode(encode(bits))).toEqual(bits);
  });
});

describe('time zones', () => {
  it('shows UTC half-hours in local time and back', () => {
    const utc = new Array(336).fill(false);
    utc[slot(1, 26)] = true;   // Monday 13:00 UTC
    const chicago = toView(utc, -10);   // UTC-5
    expect(chicago.indexOf(true)).toBe(slot(1, 16));   // Monday 08:00 local
    expect(fromView(chicago, -10)).toEqual(utc);
  });
  it('wraps around the week', () => {
    const utc = new Array(336).fill(false);
    utc[0] = true;   // Sunday 00:00 UTC
    expect(toView(utc, -10).indexOf(true)).toBe(slot(6, 38));   // Saturday 19:00 in UTC-5
    expect(toView(utc, 11).indexOf(true)).toBe(11);   // Sunday 05:30 in UTC+5:30
  });
  it('a zone off the half-hour grid has no shift', () => {
    expect(localShift({ getTimezoneOffset: () => -345 } as Date)).toBeNull();
    expect(localShift({ getTimezoneOffset: () => 300 } as Date)).toBe(-10);
  });
});
