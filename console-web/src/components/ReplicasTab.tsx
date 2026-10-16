import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Label, Spinner } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DirObject, type ObjectComparison } from '../api';
import { useSession } from '../session';
import { useHeading } from '../heading';
import { ProblemAlert } from './Problem';
import { ValueView } from './ValueView';
import { useServerSignIn } from './ServerSignIn';
import { explain } from '../help/glossary';
import { Hint } from '../help/Help';
import { ReplicaTypeLabel } from './ReplicaType';

/**
 * One object on each server that holds its replica: whether each server has it, and the attributes
 * that each server keeps for itself (never synchronized) or whose values currently differ (for
 * example while a change is still replicating).
 */
export function ReplicasTab({ obj }: { obj: DirObject }) {
  const { tree } = useSession();
  const { run, dialog } = useServerSignIn();
  const [c, setC] = useState<ObjectComparison | null>(null);
  const [error, setError] = useState<unknown>(null);
  const level = useHeading();
  const load = useCallback(() => { setError(null); tree.compare(obj.guid).then(setC).catch(setError); }, [tree, obj.guid]);
  useEffect(load, [load]);

  if (!c) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Reading each replica" />;
  }
  const ok = c.servers.filter((s) => s.status === 'ok');
  return (
    <div className="dc-tab-body">
      <Table aria-label="Servers holding a replica" variant="compact">
        <Thead><Tr><Th>Server</Th><Th>Replica</Th><Th>This object</Th></Tr></Thead>
        <Tbody>
          {c.servers.map((s) => (
            <Tr key={s.server.guid}>
              <Td dataLabel="Server">{s.server.name}</Td>
              <Td dataLabel="Replica">{s.server.type ? <ReplicaTypeLabel type={s.server.type} /> : '—'}</Td>
              <Td dataLabel="This object">
                {s.status === 'ok' ? <Label isCompact color="green">present</Label>
                  : s.status === 'server-sign-in-required' ? (
                    <Button variant="link" isInline onClick={() => run(() => tree.read(obj.guid, s.server.guid)).then(load, setError)}>Sign in to compare</Button>
                  ) : s.status === 'no-such-object' ? <Label isCompact color="orange">not there yet (replicating)</Label>
                    : <Label isCompact color="red">{s.detail ?? s.status}</Label>}
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      {ok.length === 1 && c.servers.length > 1 && c.attributes.length === 0 && (
        <Alert component={level} variant="info" isInline isPlain title={`Only ${ok[0].server.name} has answered so far: sign in to the other servers to compare.`} />
      )}
      {(ok.length > 1 || c.attributes.length > 0) && (c.attributes.length === 0
        ? <Alert component={level} variant="success" isInline isPlain title={`The ${ok.length} replicas that answered have the same values.`} />
        : (
          <Table aria-label="Values by server" variant="compact" className="dc-tab-body">
            <Thead><Tr><Th>Attribute</Th>{ok.map((s) => <Th key={s.server.guid}>{s.server.name}</Th>)}</Tr></Thead>
            <Tbody>
              {c.attributes.map((a) => (
                <Tr key={a.name}>
                  <Td dataLabel="Attribute">
                    <span className="dc-mono">{a.name}</span>{' '}
                    {a.perReplica && <Hint text={explain('perReplica')}><Label isCompact>kept per server</Label></Hint>}{' '}
                    {a.differs && <Hint text={explain('differs')}><Label isCompact color="orange">differs</Label></Hint>}
                  </Td>
                  {ok.map((s) => (
                    <Td key={s.server.guid} dataLabel={s.server.name}>
                      {(a.values[s.server.guid] ?? []).length === 0 ? '—'
                        : <ul className="dc-values">{a.values[s.server.guid].map((v, i) => <li key={i}><ValueView value={v} /></li>)}</ul>}
                    </Td>
                  ))}
                </Tr>
              ))}
            </Tbody>
          </Table>
        ))}
      <Button variant="link" className="dc-tab-body" onClick={load}>Compare again</Button>
      {dialog}
    </div>
  );
}
