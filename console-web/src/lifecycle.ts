import type { DriverRow } from './api';

const isRunning = (d: DriverRow) => /^(running|starting)$/i.test(d.state);
const isDisabled = (d: DriverRow) => /disabled/i.test(d.startOption ?? '');

/** Which drivers a start all or stop all acts on, and why each of the others is left alone. */
export function plan(action: 'start' | 'stop', drivers: DriverRow[]) {
  const act: DriverRow[] = [];
  const skip: { d: DriverRow; why: string }[] = [];
  for (const d of drivers) {
    if (!d.guid) {
      skip.push({ d, why: 'not readable' });
    } else if (action === 'start' && isRunning(d)) {
      skip.push({ d, why: 'already running' });
    } else if (action === 'start' && isDisabled(d)) {
      skip.push({ d, why: 'disabled: it cannot start' });
    } else if (action === 'stop' && !isRunning(d)) {
      skip.push({ d, why: 'not running' });
    } else {
      act.push(d);
    }
  }
  return { act, skip };
}
