import { describe, expect, it } from 'vitest';
import { ApiError, daysUntil, guidPath, request, setCsrf } from './api';

function fake(status: number, body: unknown, headers: Record<string, string> = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), { status, headers });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe('request', () => {
  it('sends the CSRF token on writes only, and returns the ETag', async () => {
    setCsrf('tok');
    const { f, calls } = fake(200, { ok: true }, { ETag: '"abc"' });
    const r = await request('PATCH', '/x', { a: 1 }, { 'If-Match': '"e"' }, f);
    expect(r.etag).toBe('"abc"');
    expect((calls[0].init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok');
    expect((calls[0].init.headers as Record<string, string>)['If-Match']).toBe('"e"');
    await request('GET', '/y', undefined, {}, f);
    expect((calls[1].init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
    setCsrf(null);
  });

  it('turns a problem document into an ApiError', async () => {
    const { f } = fake(409, { type: 'urn:x', title: 'not-a-leaf', status: 409, detail: 'entry is not leaf', ndsError: -629 });
    const e = await request('DELETE', '/z', undefined, {}, f).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.code).toBe('not-a-leaf');
    expect(e.problem.ndsError).toBe(-629);
  });
});

describe('guidPath', () => {
  it('lets only a GUID into a path', () => {
    expect(guidPath('00112233445566778899aabbccddeeff')).toBe('00112233445566778899aabbccddeeff');
    expect(() => guidPath('cn=x,o=acme')).toThrow();
    expect(() => guidPath('../../session')).toThrow();
  });
});

describe('daysUntil', () => {
  const now = Date.parse('2026-10-12T12:00:00Z');
  it('counts a part day as one, ahead', () => expect(daysUntil('2026-11-02T11:59:00Z', now)).toBe(21));
  it('is negative once passed', () => expect(daysUntil('2026-10-12T11:00:00Z', now)).toBe(-1));
});
