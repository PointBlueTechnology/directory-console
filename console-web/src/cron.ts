/** A job schedule (five cron fields: minute hour day-of-month month day-of-week) in words, when it is a common one; null otherwise. */
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

const time = (m: string, h: string) => `${h.padStart(2, '0')}:${m.padStart(2, '0')}`;

export function describeCron(cron: string): string | null {
  const f = cron.trim().split(/\s+/);
  if (f.length !== 5) {
    return null;
  }
  const [min, hour, dom, mon, dow] = f;
  const num = (s: string) => /^\d+$/.test(s);
  const every = (s: string) => /^\*\/(\d+)$/.exec(s)?.[1];
  if (every(min) && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every ${every(min)} minutes`;
  }
  if (num(min) && every(hour) && dom === '*' && mon === '*' && dow === '*') {
    return `every ${every(hour)} hours, at ${min.padStart(2, '0')} minutes past`;
  }
  if (num(min) && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every hour, at ${min.padStart(2, '0')} minutes past`;
  }
  if (!num(min) || !num(hour) || mon !== '*') {
    return null;
  }
  const at = time(min, hour);
  if (dom === '*' && dow === '*') {
    return `every day at ${at}`;
  }
  if (dom === '*' && /^[0-7](,[0-7])*$/.test(dow)) {
    return `every ${dow.split(',').map((d) => DAYS[Number(d) % 7]).join(' and ')} at ${at}`;
  }
  if (dom === '*' && dow === '1-5') {
    return `weekdays at ${at}`;
  }
  if (num(dom) && dow === '*') {
    return `on day ${dom} of every month at ${at}`;
  }
  return null;
}
