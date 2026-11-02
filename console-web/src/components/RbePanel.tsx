import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Label, Modal, ModalBody,
  ModalFooter, ModalHeader, Spinner, TextInput, Tooltip,
} from '@patternfly/react-core';
import { ArrowDownIcon, ArrowUpIcon, PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DriverRow, type RbeGrant, type RbePolicy, type RbePolicyDetail, type RbeRef, type RbeState, idm } from '../api';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';
import { StateLabel } from './IdmParts';
import { RbePolicyEditor } from './RbePolicyEditor';
import { RbeRights } from './RbeRights';

type Idm = ReturnType<typeof idm>;

const SCOPE: Record<string, string> = { base: 'this object only', one: 'one level below', sub: 'the whole subtree' };

/**
 * A driver set's role-based entitlement policies, in priority order: what each grants and to whom, reordering,
 * deleting, and restarting the Entitlements Service driver, which reads the policies (and evaluates membership)
 * only when it starts.
 */
export function RbePanel({ api, setGuid, drivers, onDriversChanged }: {
  /** The driver set page's client: its chosen server is where the Entitlements Service driver restarts. */
  api: Idm;
  setGuid: string;
  /** The set's drivers on the chosen server, for the Entitlements Service driver's state. */
  drivers: DriverRow[];
  onDriversChanged: () => void;
}) {
  const { can } = useSession();
  const operator = can('operator');
  const { run, dialog } = useConfirmed();
  const [state, setState] = useState<RbeState | null>(null);
  const [order, setOrder] = useState<RbePolicy[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [editing, setEditing] = useState<RbePolicyDetail | 'new' | null>(null);
  const load = useCallback(() => {
    setError(null);
    api.rbe(setGuid).then((s) => { setState(s); setOrder(s.policies); }, setError);
  }, [api, setGuid]);
  useEffect(load, [load]);

  if (!state || !order) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Reading entitlement policies" />}</div>;
  }
  const service = state.serviceDrivers.map((d) => ({ ...d, row: drivers.find((r) => r.guid === d.guid) }));
  const moved = order.some((p, i) => p.guid !== state.policies[i]?.guid);
  const move = (i: number, by: number) => {
    const next = [...order];
    [next[i], next[i + by]] = [next[i + by], next[i]];
    setOrder(next);
  };
  const saveOrder = () => {
    setBusy(true);
    setError(null);
    run((c) => api.rbePriorities(setGuid, state.version!, order.map((p) => p.guid), c))
      .then((s) => { setState(s); setOrder(s.policies); setPending(true); setNotice('Order saved.'); }, setError)
      .finally(() => setBusy(false));
  };
  const restart = (d: { guid: string; name: string }) => {
    setBusy(true);
    setError(null);
    run((c) => api.lifecycle(d.guid, 'restart', c))
      .then((r) => {
        setPending(false);
        setNotice(r.error ? `${d.name}: ${r.error}` : `${d.name} restarted and has read the policies.`);
        onDriversChanged();
      }, setError)
      .finally(() => setBusy(false));
  };

  return (
    <div className="dc-tab-body">
      {dialog}
      <ProblemAlert error={error} />
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" actionClose={<Button variant="plain" onClick={() => setNotice(null)} aria-label="Dismiss">×</Button>} />}
      {state.problems.length > 0 && (
        <Alert variant="danger" isInline title="The Entitlements Service driver will not start with these priorities" className="dc-tab-body">
          <ul>{state.problems.map((p) => <li key={p}>{p}</li>)}</ul>
          {operator && 'Saving an order below rewrites them as 0, 1, 2 …'}
        </Alert>
      )}
      {service.length === 0 ? (
        <Alert variant="info" isInline isPlain className="dc-tab-body"
          title="This driver set has no Entitlements Service driver: policies here grant nothing until one runs." />
      ) : (
        <div className="dc-tab-body">
          {service.map((d) => (
            <div key={d.guid}>
              Entitlements Service driver: <strong>{d.name}</strong> {d.row && <StateLabel state={d.row.state} />}
              {operator && (
                <Tooltip content="The driver reads the policies only when it starts. It stops itself when a policy's query changes.">
                  <Button variant={pending ? 'primary' : 'secondary'} size="sm" className="dc-inline-gap" isDisabled={busy} onClick={() => restart(d)}>
                    {pending ? 'Restart to apply the changes' : 'Restart'}
                  </Button>
                </Tooltip>
              )}
            </div>
          ))}
        </div>
      )}
      {operator && (
        <Button variant="secondary" size="sm" icon={<PlusIcon />} className="dc-tab-body" onClick={() => setEditing('new')}>New policy</Button>
      )}
      {!state.container || order.length === 0 ? (
        <p className="dc-subtle dc-tab-body">No role-based entitlement policies in this driver set.</p>
      ) : (
        <>
          <Table aria-label="Entitlement policies, highest priority first" variant="compact" className="dc-tab-body">
            <Thead>
              <Tr><Th modifier="fitContent">Priority</Th><Th>Policy</Th><Th>Members</Th><Th>Grants</Th>{operator && <Th screenReaderText="Move" />}</Tr>
            </Thead>
            <Tbody>
              {order.map((p, i) => (
                <Tr key={p.guid}>
                  <Td dataLabel="Priority">{i + 1}</Td>
                  <Td dataLabel="Policy">
                    <Button variant="link" isInline onClick={() => setOpen(p.guid)}>{p.name}</Button>
                    {p.legacy && <> <Label isCompact color="red" title="A legacy entitlements document: the Entitlements Service driver refuses this policy">unconverted</Label></>}
                    {p.description && <div className="dc-subtle">{p.description}</div>}
                  </Td>
                  <Td dataLabel="Members">{membership(p)}</Td>
                  <Td dataLabel="Grants">{p.grants.length === 0 ? <span className="dc-subtle">nothing</span> : p.grants.map((g) => <div key={g.dn + g.ref}>{grantText(g)}</div>)}</Td>
                  {operator && (
                    <Td dataLabel="Move" isActionCell modifier="nowrap">
                      <Button variant="plain" aria-label={`Move ${p.name} up`} isDisabled={i === 0 || busy} onClick={() => move(i, -1)} icon={<ArrowUpIcon />} />
                      <Button variant="plain" aria-label={`Move ${p.name} down`} isDisabled={i === order.length - 1 || busy} onClick={() => move(i, 1)} icon={<ArrowDownIcon />} />
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
          {operator && (moved || state.problems.length > 0) && (
            <div className="dc-tab-body">
              <Button variant="primary" onClick={saveOrder} isLoading={busy} isDisabled={busy}>Save order</Button>
              {moved && <Button variant="link" onClick={() => setOrder(state.policies)} isDisabled={busy}>Undo</Button>}
            </div>
          )}
          <p className="dc-subtle dc-tab-body">
            The Entitlements Service driver reads these policies when it starts. It then grants and revokes person by person, as
            something that decides membership changes: an attribute a query uses (when the driver's filter includes it), or a
            policy's static members. When policies grant different values of the same entitlement, the higher one wins where that
            entitlement's conflict resolution says so (set in its driver).
          </p>
        </>
      )}
      {open && (
        <PolicyModal api={api} guid={open} operator={operator} onClose={() => setOpen(null)} onEdit={(p) => { setOpen(null); setEditing(p); }}
          onDeleted={(name) => { setOpen(null); setPending(true); setNotice(`${name} deleted; the others keep their order.`); load(); }} />
      )}
      {editing && (
        <RbePolicyEditor api={api} setGuid={setGuid} serviceDriver={state.serviceDrivers[0] ?? null} policy={editing === 'new' ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={(name) => { setEditing(null); setPending(true); setNotice(`${name} saved.`); load(); }} />
      )}
    </div>
  );
}

function membership(p: RbePolicy) {
  if (!p.membership) {
    return <span className="dc-subtle">static members only</span>;
  }
  return <><span className="dc-mono">{p.membership.filter || '(all)'}</span>{p.excluded > 0 && <span className="dc-subtle"> · {p.excluded} excluded</span>}</>;
}

function grantText(g: RbeGrant) {
  const values = refValues(g.ref);
  return <>{g.driver}: <strong>{g.entitlement}</strong>{values.length > 0 && <span className="dc-subtle"> ({values.join(', ')})</span>}</>;
}

/** The values a ref document grants, from its {@code <param>} or {@code <value>} text; none for a plain grant. */
export function refValues(ref: string): string[] {
  try {
    const doc = new DOMParser().parseFromString(ref, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) {
      return [];
    }
    return Array.from(doc.querySelectorAll('param, value')).map((e) => (e.textContent ?? '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function PolicyModal({ api, guid, operator, onClose, onEdit, onDeleted }: {
  api: Idm; guid: string; operator: boolean; onClose: () => void; onEdit: (p: RbePolicyDetail) => void; onDeleted: (name: string) => void;
}) {
  const { run, dialog } = useConfirmed();
  const [p, setP] = useState<RbePolicyDetail | null>(null);
  const [members, setMembers] = useState<{ items: RbeRef[]; total: number } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [deleting, setDeleting] = useState(false);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.rbePolicy(guid).then(setP, setError); }, [api, guid]);
  const scope = useMemo(() => (p?.membership ? SCOPE[p.membership.scope] ?? p.membership.scope : null), [p]);
  const remove = (force: boolean) => {
    setBusy(true);
    setError(null);
    run((c) => api.deleteRbePolicy(guid, typed, c, force)).then(() => onDeleted(p!.name), setError).finally(() => setBusy(false));
  };
  const empty = () => {
    setBusy(true);
    setError(null);
    run((c) => api.rbeEmpty(guid, c)).then(() => api.rbePolicy(guid).then(setP), setError).finally(() => setBusy(false));
  };
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="rbe-policy-title">
      {dialog}
      <ModalHeader title={p ? p.name : 'Entitlement policy'} labelId="rbe-policy-title" description={p?.description ?? undefined} />
      <ModalBody>
        <ProblemAlert error={error} />
        {!p ? !error && <Spinner size="md" aria-label="Reading the policy" /> : (
          <>
            {p.legacy && <Alert variant="danger" isInline isPlain title="This policy has a legacy entitlements document: the Entitlements Service driver refuses it until it is converted." />}
            <DescriptionList isHorizontal isCompact className="dc-tab-body">
              <DescriptionListGroup>
                <DescriptionListTerm>Dynamic members</DescriptionListTerm>
                <DescriptionListDescription>
                  {p.membership ? (
                    <>
                      <div className="dc-mono">{p.membership.filter || '(all)'}</div>
                      <div className="dc-subtle">under <span className="dc-mono">{p.membership.base || 'the whole tree'}</span>, {scope}</div>
                    </>
                  ) : <span className="dc-subtle">none: static members only</span>}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Searched as</DescriptionListTerm>
                <DescriptionListDescription>{p.identity ? <span className="dc-mono">{p.identity.dn}</span> : <span className="dc-subtle">the Entitlements Service driver's own rights</span>}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Excluded</DescriptionListTerm>
                <DescriptionListDescription>
                  {p.excludedMembers.length === 0 ? <span className="dc-subtle">nobody</span> : p.excludedMembers.map((m) => <div key={m.dn} className="dc-mono">{m.dn}</div>)}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <Table aria-label="What the policy grants" variant="compact" className="dc-tab-body">
              <Thead><Tr><Th>Driver</Th><Th>Entitlement</Th><Th>Values</Th></Tr></Thead>
              <Tbody>
                {p.grants.length === 0 ? <Tr><Td colSpan={3}><span className="dc-subtle">This policy grants nothing.</span></Td></Tr> : p.grants.map((g) => (
                  <Tr key={g.dn + g.ref}>
                    <Td dataLabel="Driver">{g.driver}</Td>
                    <Td dataLabel="Entitlement">{g.entitlement}{g.exists === false && <> <Label isCompact color="orange" title="No such entitlement object: the grant does nothing">missing</Label></>}</Td>
                    <Td dataLabel="Values">{refValues(g.ref).join(', ') || <span className="dc-subtle">granted, no values</span>}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
            <div className="dc-tab-body">
              {!members ? (
                <Button variant="secondary" size="sm" onClick={() => api.rbeMembers(guid).then(setMembers, setError)}>Show members</Button>
              ) : (
                <>
                  <strong>{members.total} member{members.total === 1 ? '' : 's'}</strong>
                  <span className="dc-subtle"> as the directory computes them now, from the query and static members</span>
                  <ul className="dc-tab-body">{members.items.map((m) => <li key={m.dn} className="dc-mono">{m.dn}</li>)}</ul>
                </>
              )}
            </div>
            <RbeRights policy={{ guid: p.guid, dn: p.dn, name: p.name }} operator={operator} />
            {deleting && !p.emptied && (
              <Alert variant="warning" isInline title={`${p.name} still covers people`} className="dc-tab-body"
                actionLinks={<Button variant="link" isInline onClick={empty} isDisabled={busy}>Remove everyone first</Button>}>
                The Entitlements Service driver ignores a deleted policy, so whatever it granted would stay. Remove everyone first: the
                driver then revokes its grants, person by person (restart it if it stopped). Delete the policy once that is done.
              </Alert>
            )}
            {deleting && (
              <Alert variant="danger" isInline title={p.emptied ? `Delete the policy ${p.name}?` : `Delete ${p.name} anyway, leaving its grants?`} className="dc-tab-body">
                Type its name to confirm.
                <TextInput aria-label="The policy's name" value={typed} onChange={(_e, v) => setTyped(v)} />
              </Alert>
            )}
          </>
        )}
      </ModalBody>
      <ModalFooter>
        {operator && p && !deleting && <Button variant="secondary" onClick={() => onEdit(p)}>Change</Button>}
        {operator && p && !deleting && <Button variant="link" isDanger onClick={() => setDeleting(true)}>Delete</Button>}
        {deleting && <Button variant="danger" onClick={() => remove(!p?.emptied)} isLoading={busy} isDisabled={busy || typed !== p?.name}>
          {p?.emptied ? 'Delete the policy' : 'Delete anyway'}
        </Button>}
        <Button variant="link" onClick={deleting ? () => { setDeleting(false); setTyped(''); } : onClose}>{deleting ? 'Keep it' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}
