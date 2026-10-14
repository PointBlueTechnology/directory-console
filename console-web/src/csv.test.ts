import { describe, expect, it } from 'vitest';
import { fromCsv, toCsv } from './csv';

describe('CSV', () => {
  it('round-trips commas, quotes and line breaks', () => {
    const rows = [['key', 'value'], ['a,b', 'say "hi"'], ['multi\nline', ''], ['plain', 'R&D']];
    expect(toCsv(rows)).toBe('key,value\r\n"a,b","say ""hi"""\r\n"multi\nline",\r\nplain,R&D\r\n');
    expect(fromCsv(toCsv(rows))).toEqual(rows);
  });
  it('reads LF files and a byte-order mark', () => {
    expect(fromCsv('﻿a,b\nc,d\n')).toEqual([['a', 'b'], ['c', 'd']]);
    expect(fromCsv('a,b')).toEqual([['a', 'b']]);
  });
});
