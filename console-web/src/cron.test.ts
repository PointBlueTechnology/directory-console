import { describe, expect, it } from 'vitest';
import { describeCron } from './cron';

describe('job schedules in words', () => {
  it('reads the common forms', () => {
    expect(describeCron('0 0 * * 6')).toBe('every Saturday at 00:00');
    expect(describeCron('30 2 * * *')).toBe('every day at 02:30');
    expect(describeCron('0 7 * * 1-5')).toBe('weekdays at 07:00');
    expect(describeCron('15 1 1 * *')).toBe('on day 1 of every month at 01:15');
    expect(describeCron('*/10 * * * *')).toBe('every 10 minutes');
    expect(describeCron('5 */4 * * *')).toBe('every 4 hours, at 05 minutes past');
    expect(describeCron('0 2 * * 0,3')).toBe('every Sunday and Wednesday at 02:00');
  });
  it('leaves the rest to the cron text', () => {
    expect(describeCron('0 2 * 6 *')).toBeNull();
    expect(describeCron('nonsense')).toBeNull();
  });
});
