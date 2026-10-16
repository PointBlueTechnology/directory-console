import { Button, Label } from '@patternfly/react-core';
import { objectIcon } from './ObjectIcon';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { Row } from '../api';

/** Objects in a list: a container's name opens it, any row shows its details. */
export function RowsTable({ rows, selected, onOpen, onDetails, label, highlight, narrow }: {
  rows: Row[];
  selected?: string | null;
  onOpen: (r: Row) => void;
  onDetails: (r: Row) => void;
  label: string;
  highlight?: string | null;
  /** Leave out the DN column (the details drawer is open beside the list). */
  narrow?: boolean;
}) {
  return (
    <Table aria-label={label} variant="compact">
      <Thead>
        <Tr>
          <Th>Name</Th>
          <Th>Class</Th>
          {!narrow && <Th>DN</Th>}
        </Tr>
      </Thead>
      <Tbody>
        {rows.map((r) => (
          <Tr key={r.guid} isClickable onRowClick={() => onDetails(r)} isRowSelected={selected === r.guid || highlight === r.guid}>
            <Td dataLabel="Name">
              {r.container
                ? <Button variant="link" isInline icon={objectIcon(r.objectClasses, true)} onClick={(e) => { e.stopPropagation(); onOpen(r); }}>{r.name}</Button>
                : <span className="dc-row-name"><span className="dc-row-icon" aria-hidden="true">{objectIcon(r.objectClasses, false)}</span>{r.name}</span>}
              {r.childCount !== undefined && <> <Label isCompact>{r.childCount}</Label></>}
            </Td>
            <Td dataLabel="Class">{r.objectClass}</Td>
            {!narrow && <Td dataLabel="DN"><span className="dc-mono dc-subtle">{r.dn}</span></Td>}
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
}
