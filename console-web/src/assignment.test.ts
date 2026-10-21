import { describe, expect, it } from 'vitest';
import { assignment } from './assignment';

describe('role assignments', () => {
  it('read as words', () => {
    expect(assignment('<assignment><start_tm>20240120205711Z</start_tm><req_tm>20240120205711Z</req_tm><req>cn=admin,ou=sa,o=system</req>'
      + '<req_desc>Role manager assignment request.</req_desc></assignment>'))
      .toBe('(since 2024-01-20 20:57; requested by admin; Role manager assignment request.)');
    expect(assignment('not xml')).toBeNull();
  });
});
