import { describe, expect, it } from 'vitest';
import { decode, encode, slot } from './timemap';

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
