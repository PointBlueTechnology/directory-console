import type { FilterNode } from './filterTree';

/**
 * A membership filter as Designer's and Identity Console's RBE editors keep it (DirXML-SPFilterXML): groups of rows,
 * each row an attribute, an AS.Op operation and a value, joined by "and" or "or" within and between groups. Only
 * the query (memberQueryURL) decides membership; this is what lets those editors show and change the filter.
 */
const OP: Record<string, string> = {
  eq: 'AS.Op.isEqual', present: 'AS.Op.isPresent', absent: 'AS.Op.isNotPresent', gte: 'AS.Op.isGreaterEqual', lte: 'AS.Op.isLessEqual', approx: 'AS.Op.isNear',
};

type Row = { attribute: string; operation: string; value: string };

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** One condition as a row; null for the tests those editors have no operation for (starts with, contains, ends with). */
function row(n: FilterNode): Row | null {
  if (n.kind === 'not' && n.child.kind === 'cond' && n.child.op === 'eq') {
    return { attribute: n.child.attribute, operation: 'AS.Op.isNotEqual', value: n.child.value };
  }
  if (n.kind !== 'cond' || !OP[n.op]) {
    return null;
  }
  return { attribute: n.attribute, operation: OP[n.op], value: n.op === 'present' || n.op === 'absent' ? '' : n.value };
}

/**
 * The criteria document for {@code node}, or null when the filter has a shape those editors cannot show (deeper
 * nesting, a NOT around a group, a substring test): then only the query is saved, which still decides membership.
 * Plain conditions under the top make one group; otherwise each child of the top is a group.
 */
export function toCriteria(node: FilterNode): string | null {
  const top = node.kind === 'and' || node.kind === 'or' ? node : { kind: 'and' as const, children: [node] };
  const flat = top.children.every((c) => c.kind !== 'and' && c.kind !== 'or');
  const groups: { op: string; rows: (Row | null)[] }[] = flat
    ? [{ op: top.kind, rows: top.children.map(row) }]
    : top.children.map((c) => (c.kind === 'and' || c.kind === 'or' ? { op: c.kind, rows: c.children.map(row) } : { op: 'and', rows: [row(c)] }));
  if (groups.length === 0 || groups.some((g) => g.rows.length === 0 || g.rows.some((r) => r === null))) {
    return null;
  }
  let x = '<selection-criterion>';
  for (const g of groups) {
    // a group's group-op joins it to the next group; a row's row-op joins it to the next row
    x += `<group><group-op>${top.kind}</group-op>`;
    for (const r of g.rows as Row[]) {
      x += `<row><attribute>${esc(r.attribute)}</attribute><operation>${r.operation}</operation><value>${esc(r.value)}</value><row-op>${g.op}</row-op></row>`;
    }
    x += '</group>';
  }
  return `${x}</selection-criterion>`;
}
