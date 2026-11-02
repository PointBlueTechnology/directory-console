import { useState } from 'react';
import { Alert, Button, Label, LabelGroup, Spinner, Title } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Acl, type DirObject, type Row, idm } from '../api';
import { useSession } from '../session';
import { useHeading } from '../heading';
import { BrowseContainers } from './ContainerChooser';
import { ObjectPicker } from './ObjectPicker';
import { ProblemAlert } from './Problem';
import { AclModal } from './RightsTab';

type Trusted = Awaited<ReturnType<ReturnType<typeof idm>['rbeRights']>>;

/**
 * An entitlement policy's rights to other objects: its members get them, being security-equivalent to it. The ACLs
 * naming it are found by reading the ACLs under a container (eDirectory cannot search an ACL by its trustee), and
 * granted or removed on each object as its Rights tab does.
 */
export function RbeRights({ policy, operator }: { policy: { guid: string; dn: string; name: string }; operator: boolean }) {
  const { me, tree } = useSession();
  const level = useHeading();
  const [under, setUnder] = useState('');
  const [found, setFound] = useState<Trusted | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [editing, setEditing] = useState<{ obj: DirObject; etag: string; initial?: Acl } | null>(null);
  const [picking, setPicking] = useState(false);

  const find = () => {
    setBusy(true);
    setError(null);
    idm(me.directory).rbeRights(policy.guid, under || undefined)
      .then(setFound, setError)
      .finally(() => setBusy(false));
  };
  const open = (guid: string, initial?: Acl) => {
    setError(null);
    tree.read(guid).then((r) => setEditing({ obj: r.data, etag: r.etag ?? '*', initial }), setError);
  };
  const remove = (guid: string, a: Acl) => {
    setError(null);
    tree.read(guid)
      .then((r) => tree.modify(guid, r.etag ?? '*', [{ op: 'remove', attribute: 'ACL', values: [a] }]))
      .then(find, setError);
  };

  return (
    <div className="dc-tab-body">
      <Title headingLevel={level} size="md">Rights to other objects</Title>
      <p className="dc-subtle">Members get these rights, being security-equivalent to the policy.</p>
      <div className="dc-row dc-tab-body">
        <span>Look under</span>
        <span className="dc-mono">{under ? under : 'the whole tree'}</span>
        <BrowseContainers label="Choose" onChoose={(dn) => { setUnder(dn); setFound(null); }} />
        {under && <Button variant="link" isInline onClick={() => { setUnder(''); setFound(null); }}>Whole tree</Button>}
        <Button variant="secondary" size="sm" onClick={find} isLoading={busy} isDisabled={busy}>Find its rights</Button>
      </div>
      <ProblemAlert error={error} />
      {busy && !found && <Spinner size="md" aria-label="Reading ACLs" />}
      {found && (
        <>
          {!found.complete && (
            <Alert variant="warning" isInline isPlain className="dc-tab-body"
              title={`Stopped after ${found.scanned.toLocaleString()} objects: look under a smaller container to see the rest.`} />
          )}
          {found.items.length === 0 ? <p className="dc-subtle dc-tab-body">No rights found ({found.scanned.toLocaleString()} {found.scanned === 1 ? 'object' : 'objects'} read).</p> : (
            <Table aria-label="Rights the policy holds" variant="compact" className="dc-tab-body">
              <Thead><Tr><Th>Object</Th><Th>Applies to</Th><Th>Rights</Th><Th>Inherited below</Th>{operator && <Th screenReaderText="Actions" />}</Tr></Thead>
              <Tbody>
                {found.items.flatMap((o) => o.acls.map((a, i) => (
                  <Tr key={`${o.guid}-${i}`}>
                    <Td dataLabel="Object" className="dc-mono">{o.dn}</Td>
                    <Td dataLabel="Applies to">{a.attribute === '[Entry Rights]' ? 'the object' : a.attribute === '[All Attributes Rights]' ? 'all attributes' : <code>{a.attribute}</code>}</Td>
                    <Td dataLabel="Rights"><LabelGroup numLabels={6}>{a.privileges.map((p) => <Label key={p} isCompact color={p === 'supervisor' ? 'orange' : 'blue'}>{p}</Label>)}</LabelGroup></Td>
                    <Td dataLabel="Inherited below">{a.scope === 'subtree' ? 'yes' : 'no'}</Td>
                    {operator && (
                      <Td isActionCell>
                        <Button variant="link" isInline onClick={() => open(o.guid, a)}>Edit</Button>{' '}
                        <Button variant="link" isInline isDanger onClick={() => remove(o.guid, a)}>Remove</Button>
                      </Td>
                    )}
                  </Tr>
                )))}
              </Tbody>
            </Table>
          )}
        </>
      )}
      {operator && (
        <div className="dc-tab-body">
          {picking
            ? <ObjectPicker label="Grant rights on" onPick={(r: Row) => { setPicking(false); open(r.guid); }} />
            : <Button variant="secondary" size="sm" onClick={() => setPicking(true)}>Grant rights on an object</Button>}
        </div>
      )}
      {editing && (
        <AclModal obj={editing.obj} etag={editing.etag} mode="trustee" initial={editing.initial} fixedTrustee={{ dn: policy.dn, name: policy.name }}
          onClose={() => setEditing(null)} onDone={() => { setEditing(null); find(); }} />
      )}
    </div>
  );
}
