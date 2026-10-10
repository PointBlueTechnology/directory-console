import { useState } from 'react';
import { Button, Label, List, ListItem, SearchInput, Spinner } from '@patternfly/react-core';
import type { Filter, Row } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';

/** Find an object by the start of its name, among the given classes (any class when none), and pick one. */
export function ObjectPicker({ classes, onPick, label = 'Find by name', exclude = [] }: {
  classes?: string[];
  onPick: (r: Row) => void;
  label?: string;
  exclude?: string[];
}) {
  const { tree } = useSession();
  const [text, setText] = useState('');
  const [rows, setRows] = useState<Row[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const find = async () => {
    if (!text.trim()) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const name: Filter = { prefix: { cn: text.trim() } };
      const filter: Filter = classes && classes.length
        ? { and: [classes.length === 1 ? { eq: { objectClass: classes[0] } } : { or: classes.map((c) => ({ eq: { objectClass: c } })) }, name] }
        : name;
      const page = await tree.search({ filter, page: { count: 20 } });
      setRows(page.items.filter((r) => !exclude.includes(r.guid)));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <SearchInput placeholder={label} aria-label={label} value={text} onChange={(_e, v) => setText(v)}
        onSearch={() => find()} onClear={() => { setText(''); setRows(null); }} />
      {busy && <Spinner size="md" aria-label="Searching" />}
      <ProblemAlert error={error} />
      {rows && rows.length === 0 && <p className="dc-subtle dc-tab-body">Nothing found.</p>}
      {rows && rows.length > 0 && (
        <List isPlain className="dc-tab-body dc-picker">
          {rows.map((r) => (
            <ListItem key={r.guid}>
              <Button variant="link" isInline onClick={() => onPick(r)}>{r.name}</Button> <Label isCompact>{r.objectClass}</Label>
              <div className="dc-mono dc-subtle">{r.dn}</div>
            </ListItem>
          ))}
        </List>
      )}
    </div>
  );
}
