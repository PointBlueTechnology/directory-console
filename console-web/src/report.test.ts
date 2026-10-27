import { describe, expect, it } from 'vitest';
import { columnList } from './report';

describe('search reports', () => {
  it('reads a column list typed with commas or spaces, each once', () => {
    expect(columnList(' mail, title  Mail;telephoneNumber ')).toEqual(['mail', 'title', 'telephoneNumber']);
  });
});
