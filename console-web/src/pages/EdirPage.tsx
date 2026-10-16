import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, CardBody, Dropdown, DropdownItem, DropdownList, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Label,
  LabelGroup, MenuToggle, Modal, TextInput, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, Tab, Tabs, TabTitleText, Title,
} from '@patternfly/react-core';
import { EllipsisVIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type EdirPartition, type EdirServer, type ReplicaState, edir } from '../api';
import { useSession } from '../session';
import { linkProps, navigate } from '../router';
import { useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { Hint, useHelpTopic } from '../help/Help';
import { GLOSSARY, explain } from '../help/glossary';

const TYPE_LABEL: Record<string, string> = {
  master: 'Master', 'read-write': 'Read/write', 'read-only': 'Read-only', 'subordinate-reference': 'Subordinate reference',
  'sparse-write': 'Sparse write', 'sparse-read': 'Sparse read',
};

/** What a replica type means, from the glossary. */
function typeHelp(type: string): string {
  const key = `replica.${type}`;
  return key in GLOSSARY ? GLOSSARY[key as keyof typeof GLOSSARY] : type;
}

/** A replica's type and state as labels: busy or in transition in blue, anything not "on" in orange. */
export function ReplicaLabels({ r }: { r: ReplicaState }) {
  return (
    <LabelGroup>
      <Hint text={typeHelp(r.type)}><Label isCompact color={r.type === 'master' ? 'purple' : r.type === 'subordinate-reference' ? 'grey' : 'blue'}>{TYPE_LABEL[r.type] ?? r.type}</Label></Hint>
      {r.error ? <Label isCompact color="red">{r.error}</Label>
        : r.state !== 'on' ? <Label isCompact color="orange">{r.state}</Label> : null}
      {r.transition && <Label isCompact color="blue">{r.transition}</Label>}
      {r.busy && <Label isCompact color="blue">busy</Label>}
    </LabelGroup>
  );
}

/** eDirectory administration: partitions and their replicas, and the servers. */
export function EdirPage({ tab = 'partitions' }: { tab?: 'partitions' | 'servers' }) {
  useHelpTopic(`edir.${tab}`);
  return (
    <PageSection isFilled>
      <Title headingLevel="h1">eDirectory</Title>
      <Tabs activeKey={tab} onSelect={(_e, k) => navigate(k === 'servers' ? '/edir/servers' : '/edir')} aria-label="eDirectory" mountOnEnter unmountOnExit className="dc-tab-body">
        <Tab eventKey="partitions" title={<TabTitleText>Partitions and replicas</TabTitleText>}><PartitionsView /></Tab>
        <Tab eventKey="servers" title={<TabTitleText>Servers</TabTitleText>}><ServersView /></Tab>
      </Tabs>
    </PageSection>
  );
}

function ServersView() {
  const { me } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const [servers, setServers] = useState<EdirServer[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { api.servers().then(setServers).catch(setError); }, [api]);
  if (!servers) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Loading the servers" />;
  }
  return (
    <Table aria-label="Servers" variant="compact" className="dc-tab-body">
      <Thead><Tr><Th>Server</Th><Th>Version</Th><Th>Status</Th><Th>Addresses</Th></Tr></Thead>
      <Tbody>
        {servers.map((s) => (
          <Tr key={s.dn}>
            <Td dataLabel="Server">
              <a {...linkProps(`/edir/servers/${s.guid}`)}>{s.name}</a>
              {s.connected && <> <Label isCompact color="green">connected</Label></>}
              <div className="dc-subtle dc-mono">{s.dn}</div>
            </Td>
            <Td dataLabel="Version">{s.version ?? '—'}</Td>
            <Td dataLabel="Status"><Label isCompact color={s.status === 'up' ? 'green' : 'red'}>{s.status ?? 'unknown'}</Label></Td>
            <Td dataLabel="Addresses">{s.addresses.filter((a) => a.startsWith('tcp ')).map((a) => <div key={a} className="dc-mono">{a.slice(4)}</div>)}</Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
}

type Dialog = null | { kind: 'add'; p: EdirPartition } | { kind: 'type'; p: EdirPartition; server: { guid: string; name: string }; current: string };

function PartitionsView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const admin = canAt('editor', '');
  const { run, dialog: confirmDialog } = useConfirmed();
  const sure = useAreYouSure();
  const [parts, setParts] = useState<EdirPartition[] | null>(null);
  const [servers, setServers] = useState<EdirServer[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [watchUntil, setWatchUntil] = useState(0);
  const level = useHeading();

  const load = useCallback(() => api.partitions().then((p) => { setParts(p); setError(null); }).catch(setError), [api]);
  useEffect(() => { load(); api.servers().then(setServers).catch(() => setServers([])); }, [api, load]);
  // eDirectory finishes partition operations in the background: follow them while anything is busy
  const busy = (parts ?? []).some((p) => p.busy) || Date.now() < watchUntil;
  useEffect(() => {
    if (!busy) {
      return;
    }
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [busy, load]);

  const act = async (what: string, op: (c?: string) => Promise<unknown>) => {
    setError(null);
    setNotice(null);
    try {
      await run(op);
      setNotice(`${what}: started. eDirectory finishes it in the background; this page follows it.`);
      setWatchUntil(Date.now() + 30_000);
      load();
    } catch (x) {
      setError(x);
    }
  };

  if (!parts) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the partitions" />;
  }
  return (
    <div className="dc-tab-body">
      {notice && <Alert component={level} variant="info" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {busy && <p className="dc-subtle" role="status"><Spinner size="sm" aria-label="Following" /> Following partition operations…</p>}
      <Table aria-label="Partitions" variant="compact">
        <Thead><Tr><Th>Partition</Th><Th>Entries</Th><Th>Replicas</Th>{admin && <Th screenReaderText="Actions" />}</Tr></Thead>
        <Tbody>
          {parts.map((p) => (
            <Tr key={p.dn}>
              <Td dataLabel="Partition">
                {p.id && p.id !== 'root' ? <a {...linkProps(`/objects/${p.id}`)}>{p.name}</a> : p.name}
                {p.busy && <> <Label isCompact color="blue">in progress</Label></>}
                {p.dn && <div className="dc-subtle dc-mono">{p.dn}</div>}
              </Td>
              <Td dataLabel="Entries">{p.entries ?? '—'}</Td>
              <Td dataLabel="Replicas">
                <Table aria-label={`Replicas of ${p.name}`} variant="compact" borders={false}>
                  <Tbody>
                    {p.replicas.map((r) => (
                      <Tr key={r.server.dn}>
                        <Td dataLabel="Server"><a {...linkProps(`/edir/servers/${r.server.guid}`)}>{r.server.name}</a></Td>
                        <Td dataLabel="Replica"><ReplicaLabels r={r} /></Td>
                        {admin && (
                          <Td isActionCell>
                            {r.type !== 'master' && r.type !== 'subordinate-reference' && (
                              <ReplicaMenu name={r.server.name}
                                onType={() => setDialog({ kind: 'type', p, server: r.server, current: r.type })}
                                onRemove={() => sure.ask(`Remove ${p.name}'s replica from ${r.server.name}?`,
                                  'The server keeps a subordinate reference; its copy of these entries is deleted.', 'Remove',
                                  () => act(`Remove the replica on ${r.server.name}`, (c) => api.removeReplica(p.id!, r.server.guid, c)))} />
                            )}
                          </Td>
                        )}
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </Td>
              {admin && (
                <Td isActionCell modifier="nowrap">
                  <Button variant="link" isInline isDisabled={p.busy || !p.id} onClick={() => setDialog({ kind: 'add', p })}>Add a replica</Button>
                  {p.id && p.id !== 'root' && (
                    <>{' '}<Hint text={explain('merge')}><Button variant="link" isInline isDanger isAriaDisabled={p.busy} onClick={() => sure.ask(`Merge ${p.name} into its parent?`,
                      'Its entries join the parent partition and its replicas are removed.', 'Merge',
                      () => act(`Merge ${p.name}`, (c) => api.merge(p.id!, c)))}>Merge</Button></Hint></>
                  )}
                </Td>
              )}
            </Tr>
          ))}
        </Tbody>
      </Table>
      {!admin && <p className="dc-subtle">Changing partitions and replicas needs an editor role for the whole directory.</p>}
      {dialog?.kind === 'add' && (
        <ReplicaModal title={`Add a replica of ${dialog.p.name}`}
          servers={servers.filter((s) => !dialog.p.replicas.some((r) => r.server.guid === s.guid && r.type !== 'subordinate-reference'))}
          onClose={() => setDialog(null)}
          onSave={(server, type) => { setDialog(null); act(`Add a ${TYPE_LABEL[type]} replica`, (c) => api.addReplica(dialog.p.id!, server, type, c)); }} />
      )}
      {dialog?.kind === 'type' && (
        <ReplicaModal title={`Change ${dialog.server.name}'s replica of ${dialog.p.name}`} fixedServer={dialog.server} current={dialog.current}
          onClose={() => setDialog(null)}
          onSave={(_s, type) => { setDialog(null); act(`Make the replica ${TYPE_LABEL[type]}`, (c) => api.changeReplica(dialog.p.id!, dialog.server.guid, type, c)); }} />
      )}
      {confirmDialog}
      {sure.dialog}
    </div>
  );
}

function ReplicaMenu({ name, onType, onRemove }: { name: string; onType: () => void; onRemove: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <Dropdown isOpen={open} onOpenChange={setOpen} popperProps={{ position: 'right', appendTo: 'inline' }}
      toggle={(ref) => <MenuToggle ref={ref} variant="plain" aria-label={`Replica on ${name}`} isExpanded={open} onClick={() => setOpen(!open)} icon={<EllipsisVIcon />} />}>
      <DropdownList>
        <DropdownItem onClick={() => { setOpen(false); onType(); }}>Change the type</DropdownItem>
        <DropdownItem isDanger onClick={() => { setOpen(false); onRemove(); }}>Remove</DropdownItem>
      </DropdownList>
    </Dropdown>
  );
}

function ReplicaModal({ title, servers, fixedServer, current, onClose, onSave }: {
  title: string; servers?: EdirServer[]; fixedServer?: { guid: string; name: string }; current?: string;
  onClose: () => void; onSave: (server: string, type: string) => void;
}) {
  const [server, setServer] = useState(fixedServer?.guid ?? servers?.[0]?.guid ?? '');
  const [type, setType] = useState(current === 'read-write' ? 'read-only' : 'read-write');
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="replica-title">
      <ModalHeader title={title} labelId="replica-title" />
      <ModalBody>
        <Form id="replica-form" onSubmit={(e) => { e.preventDefault(); if (server) { onSave(server, type); } }}>
          {!fixedServer && (
            <FormGroup label="Server" fieldId="replica-server" isRequired>
              {servers && servers.length > 0 ? (
                <FormSelect id="replica-server" value={server} onChange={(_e, v) => setServer(v)}>
                  {servers.map((s) => <FormSelectOption key={s.guid} value={s.guid} label={s.name} />)}
                </FormSelect>
              ) : <p>Every server already holds a replica of this partition.</p>}
            </FormGroup>
          )}
          <FormGroup label="Replica type" fieldId="replica-type" isRequired>
            <FormSelect id="replica-type" value={type} onChange={(_e, v) => setType(v)}>
              <FormSelectOption value="read-write" label="Read/write" />
              <FormSelectOption value="read-only" label="Read-only" />
              {fixedServer && <FormSelectOption value="master" label="Master (the current master becomes read/write)" />}
            </FormSelect>
            <FormHelperText><HelperText><HelperTextItem>{typeHelp(type)}</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="replica-form" variant="primary" isDisabled={!server || type === current}>Start</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** One server: its replicas and indexes, and its background processes. */
export function ServerPage({ guid }: { guid: string }) {
  const { me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const admin = canAt('editor', '');
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [s, setS] = useState<Awaited<ReturnType<typeof api.server>> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const level = useHeading();
  const load = useCallback(() => api.server(guid).then(setS).catch(setError), [api, guid]);
  useEffect(() => { load(); }, [load]);

  const act = async (what: string, op: (c?: string) => Promise<unknown>) => {
    setError(null);
    setNotice(null);
    try {
      await run(op);
      setNotice(what);
      load();
    } catch (x) {
      setError(x);
    }
  };

  if (!s) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the server" />}</PageSection>;
  }
  return (
    <PageSection isFilled>
      <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsMd' }}>
        <FlexItem><Title headingLevel="h1">{s.name}</Title></FlexItem>
        <FlexItem><Label color={s.status === 'up' ? 'green' : 'red'}>{s.status}</Label></FlexItem>
        {s.connected && <FlexItem><Label color="green">connected</Label></FlexItem>}
      </Flex>
      <p className="dc-subtle">{s.version} · <span className="dc-mono">{s.dn}</span>{s.ldapServer && <> · <a {...linkProps(`/objects/${s.ldapServer.guid}`)}>LDAP Server object</a></>}</p>
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {admin && (
        <Flex className="dc-tab-body" spaceItems={{ default: 'spaceItemsSm' }}>
          {(['limber', 'janitor', 'skulker'] as const).map((p) => (
            <FlexItem key={p}><Hint text={explain(p)}><Button variant="secondary" onClick={() => act(`${p[0].toUpperCase()}${p.slice(1)} started on ${s.name}.`, (c) => api.background(guid, p, c))}>
              Run {p}
            </Button></Hint></FlexItem>
          ))}
          {s.connected && <FlexItem><Button variant="secondary" onClick={() => act('The LDAP server re-read its configuration.', (c) => api.ldapRefresh(c))}>Refresh the LDAP server</Button></FlexItem>}
        </Flex>
      )}
      <Card className="dc-tab-body">
        <CardBody>
          <Title headingLevel="h2" size="lg">Replicas</Title>
          <Table aria-label="Replicas" variant="compact">
            <Thead><Tr><Th>Partition</Th><Th>Replica</Th><Th>Last change</Th></Tr></Thead>
            <Tbody>
              {s.replicas.map((r) => (
                <Tr key={r.partition.dn}>
                  <Td dataLabel="Partition">{r.partition.id && r.partition.id !== 'root' ? <a {...linkProps(`/objects/${r.partition.id}`)}>{r.partition.name}</a> : r.partition.name}</Td>
                  <Td dataLabel="Replica"><ReplicaLabels r={r} /></Td>
                  <Td dataLabel="Last change">{r.modified ? new Date(r.modified).toLocaleString() : '—'}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      <Card className="dc-tab-body">
        <CardBody>
          <Flex justifyContent={{ default: 'justifyContentSpaceBetween' }}>
            <FlexItem><Title headingLevel="h2" size="lg">Indexes</Title></FlexItem>
            {admin && <FlexItem><Button variant="secondary" onClick={() => setAdding(true)}>Add an index</Button></FlexItem>}
          </Flex>
          <Table aria-label="Indexes" variant="compact">
            <Thead><Tr><Th>Index</Th><Th>Attributes</Th><Th>Rule</Th><Th>Kind</Th>{admin && <Th screenReaderText="Remove" />}</Tr></Thead>
            <Tbody>
              {s.indexes.map((ix) => (
                <Tr key={ix.name + ix.rule}>
                  <Td dataLabel="Index">{ix.name}</Td>
                  <Td dataLabel="Attributes">{ix.attributes.join(', ')}</Td>
                  <Td dataLabel="Rule">{ix.rule}</Td>
                  <Td dataLabel="Kind">{ix.type === 'user' ? 'User-defined' : ix.type === 'system' ? 'System' : ix.type === 'operational' ? 'Operational' : 'With its attribute'}</Td>
                  {admin && (
                    <Td isActionCell>
                      {ix.removable && <Button variant="link" isInline isDanger onClick={() => sure.ask(`Remove the index ${ix.name}?`,
                        `Searches on ${ix.attributes.join(', ')} on ${s.name} can become slower.`, 'Remove',
                        () => act(`Index ${ix.name} removed.`, (c) => api.removeIndex(guid, ix.name, c)))}>Remove</Button>}
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      {adding && <IndexModal onClose={() => setAdding(false)} onSave={(b) => { setAdding(false); act(`Index ${b.name} added; Limber builds it.`, (c) => api.addIndex(guid, b, c)); }} />}
      {dialog}
      {sure.dialog}
    </PageSection>
  );
}

function IndexModal({ onClose, onSave }: { onClose: () => void; onSave: (b: { name: string; attributes: string[]; rule: string }) => void }) {
  const { tree } = useSession();
  const [names, setNames] = useState<string[]>([]);
  const [name, setName] = useState('');
  const [attribute, setAttribute] = useState('');
  const [rule, setRule] = useState('value');
  useEffect(() => { tree.attributes().then((a) => setNames(a.map((x) => x.name).sort((x, y) => x.localeCompare(y)))).catch(() => setNames([])); }, [tree]);
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="index-title">
      <ModalHeader title="Add an index" labelId="index-title" />
      <ModalBody>
        <Form id="index-form" onSubmit={(e) => { e.preventDefault(); if (name.trim() && attribute) { onSave({ name: name.trim(), attributes: [attribute], rule }); } }}>
          <FormGroup label="Attribute" fieldId="index-attr" isRequired>
            <FormSelect id="index-attr" value={attribute} onChange={(_e, v) => { setAttribute(v); if (!name) { setName(`${v}_${rule}`); } }}>
              <FormSelectOption value="" label="Choose an attribute" isPlaceholder />
              {names.map((n) => <FormSelectOption key={n} value={n} label={n} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup label="Matching" fieldId="index-rule" isRequired>
            <FormSelect id="index-rule" value={rule} onChange={(_e, v) => setRule(v)}>
              <FormSelectOption value="value" label="Value (equality and ordering)" />
              <FormSelectOption value="presence" label="Presence" />
              <FormSelectOption value="substring" label="Substring" />
            </FormSelect>
          </FormGroup>
          <FormGroup label="Index name" fieldId="index-name" isRequired>
            <TextInput id="index-name" value={name} onChange={(_e, v) => setName(v)} />
          </FormGroup>
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="index-form" variant="primary" isDisabled={!name.trim() || !attribute}>Add</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
