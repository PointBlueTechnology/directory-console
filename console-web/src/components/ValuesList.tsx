import { useState } from 'react';
import { Button } from '@patternfly/react-core';
import type { Value } from '../api';
import { ValueView } from './ValueView';

const FIRST = 10;

/**
 * An attribute's values. Unless {@code wrap}, each stays on one line, cut off with an ellipsis, and shows in full while
 * the pointer is on it (or it has focus); a long list shows its first ten until asked for the rest.
 */
export function ValuesList({ values, wrap }: { values: Value[]; wrap: boolean }) {
  const [all, setAll] = useState(false);
  const shown = all ? values : values.slice(0, FIRST);
  return (
    <>
      <ul className={wrap ? 'dc-values' : 'dc-values dc-values-clip'}>
        {shown.map((v, i) => (
          <li key={i} tabIndex={wrap ? undefined : 0} title={!wrap && typeof v === 'string' ? v : undefined}><ValueView value={v} /></li>
        ))}
      </ul>
      {values.length > FIRST && (
        <Button variant="link" isInline onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show all ${values.length}`}</Button>
      )}
    </>
  );
}

/** Whether long values wrap, as this browser last chose. */
export function useWrapValues(): [boolean, (w: boolean) => void] {
  const [wrap, setWrap] = useState(() => {
    try {
      return localStorage.getItem('dc-wrap-values') === 'true';
    } catch {
      return false;
    }
  });
  return [wrap, (w: boolean) => {
    setWrap(w);
    try {
      localStorage.setItem('dc-wrap-values', String(w));
    } catch {
      // not kept: private window or blocked storage
    }
  }];
}
