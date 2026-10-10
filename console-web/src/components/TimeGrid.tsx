import { Button, Flex, FlexItem } from '@patternfly/react-core';
import { DAYS, SLOTS, label, slot } from '../timemap';

/**
 * The login time restriction grid: 7 days x 48 half-hours. A filled cell allows login. Each cell is a
 * toggle button (keyboard and screen reader friendly); a day's name toggles the whole day.
 */
export function TimeGrid({ bits, onChange, disabled }: { bits: boolean[]; onChange: (b: boolean[]) => void; disabled?: boolean }) {
  const set = (indexes: number[], on: boolean) => {
    const next = bits.slice();
    indexes.forEach((i) => { next[i] = on; });
    onChange(next);
  };
  const day = (d: number) => Array.from({ length: SLOTS }, (_, h) => slot(d, h));
  return (
    <div>
      <Flex className="dc-tab-body" spaceItems={{ default: 'spaceItemsSm' }}>
        <FlexItem><Button variant="secondary" size="sm" isDisabled={disabled} onClick={() => onChange(bits.map(() => true))}>Allow always</Button></FlexItem>
        <FlexItem><Button variant="secondary" size="sm" isDisabled={disabled} onClick={() => onChange(bits.map(() => false))}>Allow never</Button></FlexItem>
        <FlexItem>
          <Button variant="secondary" size="sm" isDisabled={disabled}
            onClick={() => onChange(bits.map((_, i) => { const d = Math.floor(i / SLOTS); const h = i % SLOTS; return d >= 1 && d <= 5 && h >= 14 && h < 38; }))}>
            Weekdays 07:00-19:00
          </Button>
        </FlexItem>
      </Flex>
      <div className="dc-timegrid" role="group" aria-label="Login allowed times">
        <div className="dc-timegrid__row" aria-hidden="true">
          <span className="dc-timegrid__day" />
          {Array.from({ length: SLOTS / 4 }, (_, i) => <span key={i} className="dc-timegrid__hour">{label(i * 4)}</span>)}
        </div>
        {DAYS.map((name, d) => {
          const all = day(d).every((i) => bits[i]);
          return (
            <div key={name} className="dc-timegrid__row">
              <button type="button" className="dc-timegrid__day" disabled={disabled}
                aria-label={`${name}: ${all ? 'disallow' : 'allow'} the whole day`} onClick={() => set(day(d), !all)}>{name.slice(0, 3)}</button>
              {day(d).map((i, h) => (
                <button key={i} type="button" disabled={disabled}
                  className={`dc-timegrid__cell${bits[i] ? ' dc-timegrid__cell--on' : ''}`}
                  aria-pressed={bits[i]} aria-label={`${name} ${label(h)}`} title={`${name} ${label(h)}-${label(h + 1 === SLOTS ? 0 : h + 1)}`}
                  onClick={() => set([i], !bits[i])} />
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
