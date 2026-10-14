import { useRef, useState } from 'react';
import { Alert, Button, Label, Modal, ModalBody, ModalFooter, ModalHeader, Spinner } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DriverRow, idm } from '../api';
import { useConfirmed } from './Confirm';
import { StateLabel } from './IdmParts';
import { plan } from '../lifecycle';

type Outcome = { status: 'waiting' | 'working' | 'done' | 'failed' | 'not-run'; detail?: string };

/**
 * Start all or stop all of a driver set's drivers on one server, one driver at a time, with each one's
 * outcome. Each goes through the same per-driver operation as the driver's own Start or Stop, so the
 * server still checks each one (scope, disabled). The directory's name, if asked for, is typed once.
 */
export function BulkLifecycleModal({ action, drivers, api, serverName, onClose, onDone }: {
  action: 'start' | 'stop';
  drivers: DriverRow[];
  api: ReturnType<typeof idm>;
  serverName?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { run, dialog } = useConfirmed();
  const [{ act, skip }] = useState(() => plan(action, drivers));
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({});
  const [phase, setPhase] = useState<'review' | 'running' | 'done'>('review');
  const halt = useRef(false);
  const verb = action === 'start' ? 'Start' : 'Stop';

  const go = async () => {
    setPhase('running');
    halt.current = false;
    let typed: string | undefined;
    for (const d of act) {
      if (halt.current) {
        setOutcomes((o) => ({ ...o, [d.guid!]: { status: 'not-run' } }));
        continue;
      }
      setOutcomes((o) => ({ ...o, [d.guid!]: { status: 'working' } }));
      try {
        const r = await run((c) => {
          typed = c ?? typed;
          return api.lifecycle(d.guid!, action, typed);
        });
        const ok = !r.error && (action === 'start' ? /running|starting/i.test(r.after) : /stopped|stopping/i.test(r.after));
        setOutcomes((o) => ({ ...o, [d.guid!]: { status: ok ? 'done' : 'failed', detail: `${r.before} → ${r.after}${r.error ? ` (${r.error})` : ''}` } }));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setOutcomes((o) => ({ ...o, [d.guid!]: { status: 'failed', detail: msg } }));
        if (msg === 'Not confirmed.') {
          halt.current = true;
        }
      }
    }
    setPhase('done');
    onDone();
  };

  const failed = Object.values(outcomes).filter((o) => o.status === 'failed').length;
  return (
    <Modal isOpen onClose={phase === 'running' ? undefined : onClose} variant="medium" aria-labelledby="bulk-title">
      <ModalHeader title={`${verb} all drivers${serverName ? ` on ${serverName}` : ''}`} labelId="bulk-title" />
      <ModalBody>
        {phase === 'review' && action === 'stop' && act.length > 0 && (
          <Alert variant="warning" isInline isPlain title="Events for stopped drivers queue in their caches until they start again." className="dc-tab-body" />
        )}
        {act.length === 0 && <p>No driver needs {action === 'start' ? 'starting' : 'stopping'}.</p>}
        <Table aria-label="Drivers" variant="compact">
          <Thead><Tr><Th>Driver</Th><Th>Now</Th><Th>Outcome</Th></Tr></Thead>
          <Tbody>
            {act.map((d) => {
              const o = outcomes[d.guid!];
              return (
                <Tr key={d.dn}>
                  <Td dataLabel="Driver">{d.name}</Td>
                  <Td dataLabel="Now"><StateLabel state={d.state} /></Td>
                  <Td dataLabel="Outcome">
                    {!o && <span className="dc-subtle">{phase === 'review' ? `will ${action}` : 'waiting'}</span>}
                    {o?.status === 'working' && <Spinner size="sm" aria-label="Working" />}
                    {o?.status === 'done' && <Label color="green" isCompact>{o.detail}</Label>}
                    {o?.status === 'failed' && <Label color="red" isCompact>{o.detail}</Label>}
                    {o?.status === 'not-run' && <span className="dc-subtle">not run</span>}
                  </Td>
                </Tr>
              );
            })}
            {skip.map(({ d, why }) => (
              <Tr key={d.dn}>
                <Td dataLabel="Driver" className="dc-subtle">{d.name}</Td>
                <Td dataLabel="Now"><StateLabel state={d.state} /></Td>
                <Td dataLabel="Outcome"><span className="dc-subtle">left alone: {why}</span></Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
        {phase === 'done' && failed > 0 && <Alert variant="danger" isInline isPlain title={`${failed} driver${failed === 1 ? '' : 's'} did not ${action}.`} className="dc-tab-body" />}
        {dialog}
      </ModalBody>
      <ModalFooter>
        {phase === 'review' && act.length > 0 && (
          <Button variant={action === 'stop' ? 'danger' : 'primary'} onClick={go}>{verb} {act.length} driver{act.length === 1 ? '' : 's'}</Button>
        )}
        {phase === 'running' && <Button variant="secondary" onClick={() => { halt.current = true; }}>Stop after this driver</Button>}
        {phase !== 'running' && <Button variant="link" onClick={onClose}>{phase === 'done' ? 'Close' : 'Cancel'}</Button>}
      </ModalFooter>
    </Modal>
  );
}
