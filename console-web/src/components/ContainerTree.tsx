import { useCallback, useEffect, useState } from 'react';
import { Alert, Spinner, TreeView, type TreeViewDataItem } from '@patternfly/react-core';
import { objectIcon } from './ObjectIcon';
import type { Row } from '../api';
import { useSession } from '../session';

const MAX = 500;

type Loaded = { rows: Row[]; total: number } | 'loading' | { error: string };

/**
 * The containers of the tree, loaded a level at a time when opened. A container whose children are
 * unknown ("maybe": eDirectory's subordinateCount is 0 at a partition root however full it is) gets a
 * toggle, and opening it settles the question.
 */
export function ContainerTree({ selected, onSelect }: { selected?: string; onSelect: (row: Row) => void }) {
  const { tree } = useSession();
  const [roots, setRoots] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<Record<string, Loaded>>({});

  useEffect(() => {
    tree.roots().then((r) => setRoots(r.filter((x) => x.container || x.children !== 'no'))).catch((e) => setError(e.message));
  }, [tree]);

  const open = useCallback((guid: string) => {
    if (loaded[guid] && loaded[guid] !== 'loading' && !('error' in (loaded[guid] as object))) {
      return;
    }
    setLoaded((l) => ({ ...l, [guid]: 'loading' }));
    tree.children(guid, { kind: 'containers', count: MAX })
      .then((p) => setLoaded((l) => ({ ...l, [guid]: { rows: p.items, total: p.total } })))
      .catch((e) => setLoaded((l) => ({ ...l, [guid]: { error: e.message } })));
  }, [tree, loaded]);

  const item = (row: Row): TreeViewDataItem => {
    const state = loaded[row.guid];
    let children: TreeViewDataItem[] | undefined;
    if (state === undefined) {
      children = row.children === 'no' && !row.container ? undefined : [{ id: `${row.guid}:pending`, name: '…' }];
    } else if (state === 'loading') {
      children = [{ id: `${row.guid}:loading`, name: <Spinner size="sm" aria-label="Loading" /> }];
    } else if ('error' in state) {
      // a listing that failed is reported, never shown as an empty container
      children = [{ id: `${row.guid}:error`, name: <span className="dc-subtle">Could not list: {state.error}</span> }];
    } else {
      children = state.rows.map(item);
      if (state.total > state.rows.length) {
        children.push({ id: `${row.guid}:more`, name: <span className="dc-subtle">{state.total - state.rows.length} more: open the container to page through them</span> });
      }
      if (children.length === 0) {
        children = undefined;
      }
    }
    return { id: row.guid, name: row.name, children, icon: objectIcon(row.objectClasses, true), expandedIcon: objectIcon(row.objectClasses, true, true) };
  };

  if (error) {
    return <Alert variant="danger" isInline title="The tree could not be read">{error}</Alert>;
  }
  if (!roots) {
    return <Spinner aria-label="Loading the tree" />;
  }
  const byGuid = new Map<string, Row>();
  roots.forEach((r) => byGuid.set(r.guid, r));
  Object.values(loaded).forEach((s) => typeof s === 'object' && 'rows' in s && s.rows.forEach((r) => byGuid.set(r.guid, r)));
  const data = roots.map(item);
  const active = selected ? [{ id: selected, name: '' }] : [];
  return (
    <TreeView aria-label="Containers" data={data} activeItems={active} hasSelectableNodes
      compareItems={(a, b) => a.id === b.id}
      onExpand={(_e, i) => i.id && byGuid.has(i.id) && open(i.id)}
      onSelect={(_e, i) => { const r = i.id ? byGuid.get(i.id) : undefined; if (r) { onSelect(r); } }} />
  );
}
