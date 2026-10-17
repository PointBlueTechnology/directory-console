import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActionGroup, Alert, Button, Card, CardBody, CardTitle, Checkbox, ExpandableSection, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSelect,
  FormSelectOption, HelperText, HelperTextItem, Label, Spinner, TextArea, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AuditConfig, type CefSettings, type EdirServer, type EncryptionOverview, type SnmpGroup, type SnmpTrap, edir } from '../api';
import { useSession } from '../session';
import { linkProps } from '../router';
import { ProblemAlert } from './Problem';
import { useAreYouSure, useConfirmed } from './Confirm';

const CATEGORY: Record<string, string> = { security: 'Security events', object: 'Object events', attribute: 'Attribute events', ldap: 'LDAP events' };
/** Events that can flood the log on a busy server. */
const NOISY = new Set(['DSA_READ', 'SEARCH', 'READ_ATTRIBUTE', 'LDAP_SEARCH', 'LDAP_SEARCH_RESPONSE', 'LDAP_SEARCH_ENTRY_RESPONSE', 'COMPARE_ATTRIBUTE_VALUE']);
const words = (key: string) => key.toLowerCase().replace(/^ldap_/, 'LDAP ').replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
const lines = (v: string) => v.split('\n').map((x) => x.trim()).filter(Boolean);

/** CEF auditing: per server, which events eDirectory sends and what they include. */
export function AuditView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const edit = canAt('editor', '');
  const [servers, setServers] = useState<EdirServer[] | null>(null);
  const [server, setServer] = useState('');
  const [a, setA] = useState<AuditConfig | null>(null);
  const [s, setS] = useState<CefSettings | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  useEffect(() => { api.servers().then((ss) => { setServers(ss); setServer((cur) => cur || ss[0]?.guid || ''); }, setError); }, [api]);
  const show = useCallback((x: AuditConfig) => { setA(x); setS(x.settings); }, []);
  useEffect(() => {
    if (server) {
      setA(null);
      setNotice(null);
      api.audit(server).then(show, setError);
    }
  }, [api, server, show]);

  if (!servers) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Reading the servers" />;
  }
  const dirty = a && s && JSON.stringify(a.settings) !== JSON.stringify(s);
  const set = (patch: Partial<CefSettings>) => setS((x) => (x ? { ...x, ...patch } : x));
  const toggle = (ev: string, on: boolean) => s && set({ events: on ? [...s.events, ev] : s.events.filter((e) => e !== ev) });
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!s) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      show(await confirmed.run((c) => api.changeAudit(server, s, c)));
      setNotice('Saved. eDirectory applies it within three minutes, or at once if cefauditds is reloaded on the server.');
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dc-tab-body">
      <p className="dc-subtle">
        Which events each server sends as CEF, and what they include. Where they go (syslog, a file, TLS, caching) is set in auditlogconfig.properties on the
        server itself, and the cefauditds module must be loaded there.
      </p>
      <FormGroup label="Server" fieldId="audit-server" className="dc-tab-body">
        <FormSelect id="audit-server" value={server} onChange={(_e, v) => setServer(v)}>
          {servers.map((x) => <FormSelectOption key={x.guid} value={x.guid} label={x.name} />)}
        </FormSelect>
      </FormGroup>
      <ProblemAlert error={error} />
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      {!a || !s ? (server && !error ? <Spinner aria-label="Reading the audit settings" /> : null) : !a.supported ? (
        <Alert variant="info" isInline title={`${a.server.name}'s eDirectory is too old for CEF auditing.`} className="dc-tab-body" />
      ) : (
        <Form onSubmit={save} className="dc-tab-body">
          {!a.configured && <Alert variant="info" isInline isPlain title="Nothing is stored for this server: eDirectory's defaults apply (shown below)." />}
          <Checkbox id="cef-replicated" label="Don't send events that arrive through replication" isChecked={s.noReplicatedEvents} isDisabled={!edit}
            onChange={(_e, v) => set({ noReplicatedEvents: v })} />
          <Checkbox id="cef-large" label="Log large values (over 768 bytes)" isChecked={s.logLargeValues} isDisabled={!edit} onChange={(_e, v) => set({ logLargeValues: v })} />
          <Checkbox id="cef-values" label="Log attribute values (add value, delete value)" isChecked={s.logAttributeValues} isDisabled={!edit}
            onChange={(_e, v) => set({ logAttributeValues: v })} />
          <Checkbox id="cef-encrypted" label="Log values of encrypted attributes" isChecked={s.logEncryptedAttributeValues} isDisabled={!edit}
            onChange={(_e, v) => set({ logEncryptedAttributeValues: v })} description="They are written to the log in clear text." />
          {Object.entries(a.events).map(([cat, evs]) => (
            <ExpandableSection key={cat} isIndented toggleText={`${CATEGORY[cat] ?? cat} (${evs.filter((x) => s.events.includes(x)).length} of ${evs.length})`}>
              {evs.map((ev) => (
                <Checkbox key={ev} id={`cef-${ev}`} label={<>{words(ev)}{NOISY.has(ev) && <Label isCompact color="orange" className="dc-gap-left">high volume</Label>}</>}
                  isChecked={s.events.includes(ev)} isDisabled={!edit} onChange={(_e, on) => toggle(ev, on)} />
              ))}
            </ExpandableSection>
          ))}
          <ExpandableSection isIndented toggleText="Filtering">
            <FormGroup label="Object events only for these classes" fieldId="cef-objects">
              <TextArea id="cef-objects" value={s.objectClasses.join('\n')} isDisabled={!edit} rows={3} resizeOrientation="vertical"
                onChange={(_e, v) => set({ objectClasses: lines(v) })} />
              <FormHelperText><HelperText><HelperTextItem>eDirectory class names, one per line, such as User or Organizational Unit. Empty: every class.</HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
            {([['attributeFilter', 'Attribute events only for', 'Empty: every class and attribute.'], ['exclude', 'Never audit', 'Commonly: Last Login Time, Login Time, Revision, Partition Status.']] as const).map(([k, label, help]) => (
              <Flex key={k}>
                <FlexItem grow={{ default: 'grow' }}>
                  <FormGroup label={`${label}: classes`} fieldId={`cef-${k}-classes`}>
                    <TextArea id={`cef-${k}-classes`} value={s[k].classes.join('\n')} isDisabled={!edit} rows={3} resizeOrientation="vertical"
                      onChange={(_e, v) => set({ [k]: { ...s[k], classes: lines(v) } })} />
                  </FormGroup>
                </FlexItem>
                <FlexItem grow={{ default: 'grow' }}>
                  <FormGroup label={`${label}: attributes`} fieldId={`cef-${k}-attrs`}>
                    <TextArea id={`cef-${k}-attrs`} value={s[k].attributes.join('\n')} isDisabled={!edit} rows={3} resizeOrientation="vertical"
                      onChange={(_e, v) => set({ [k]: { ...s[k], attributes: lines(v) } })} />
                    <FormHelperText><HelperText><HelperTextItem>{help}</HelperTextItem></HelperText></FormHelperText>
                  </FormGroup>
                </FlexItem>
              </Flex>
            ))}
          </ExpandableSection>
          {(s.unknown?.length ?? 0) > 0 && <p className="dc-subtle">Also stored, and kept as it is: <span className="dc-mono">{s.unknown!.join(', ')}</span></p>}
          {edit && (
            <ActionGroup>
              <Button type="submit" isLoading={busy} isDisabled={busy || !dirty}>Save</Button>
              <Button variant="link" isDisabled={!dirty} onClick={() => show(a)}>Discard changes</Button>
              {a.configured && (
                <Button variant="link" isDanger onClick={() => sure.ask(`Use eDirectory's defaults on ${a.server.name}?`,
                  'The stored audit settings are removed; eDirectory then audits its default events.', 'Use defaults',
                  () => confirmed.run((c) => api.resetAudit(server, c)).then((x) => { show(x); setNotice('Back to eDirectory\'s defaults.'); }, setError))}>Use eDirectory's defaults</Button>
              )}
            </ActionGroup>
          )}
        </Form>
      )}
      {confirmed.dialog}
      {sure.dialog}
    </div>
  );
}

/** SNMP groups: which traps the servers send, and how often. */
export function SnmpView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const edit = canAt('editor', '');
  const [groups, setGroups] = useState<SnmpGroup[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const confirmed = useConfirmed();
  const load = useCallback(() => { setError(null); api.snmp().then(setGroups, setError); }, [api]);
  useEffect(load, [load]);
  const change = (g: SnmpGroup, body: Parameters<typeof api.changeSnmp>[1], what: string) => {
    setError(null);
    setNotice(null);
    confirmed.run((c) => api.changeSnmp(g.guid, body, c)).then((x) => {
      setGroups((gs) => gs!.map((y) => (y.guid === x.guid ? x : y)));
      setNotice(`${what} The SNMP subagent may need restarting on the server to pick it up.`);
    }, setError);
  };
  if (!groups) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading the SNMP groups" />;
  }
  return (
    <div className="dc-tab-body">
      <p className="dc-subtle">Which eDirectory traps each server's SNMP subagent sends. Where traps go, and community strings, are set in the server's SNMP agent, not here.</p>
      <ProblemAlert error={error} />
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      {groups.length === 0 && <p>No SNMP groups.</p>}
      {groups.map((g) => (
        <Card key={g.guid} className="dc-tab-body">
          <CardTitle><Title headingLevel="h2" size="lg">{g.name}</Title></CardTitle>
          <CardBody>
            <p className="dc-subtle">For {g.servers.map((x) => x.name).join(', ') || 'no servers'}.</p>
            <Flex alignItems={{ default: 'alignItemsFlexEnd' }} className="dc-tab-body">
              <FlexItem>
                <Checkbox id={`snmp-off-${g.guid}`} label="Send no traps" isChecked={g.trapsDisabled} isDisabled={!edit}
                  onChange={(_e, v) => change(g, { trapsDisabled: v }, v ? 'Traps turned off.' : 'Traps turned on.')} />
              </FlexItem>
              <FlexItem>
                <IntervalField id={`snmp-interval-${g.guid}`} label="Default interval (seconds)" value={g.trapInterval ?? 0} edit={edit}
                  onSave={(v) => change(g, { trapInterval: v }, 'Default interval saved.')} />
              </FlexItem>
            </Flex>
            <ExpandableSection toggleText={`Traps (${g.traps.filter((t) => t.active).length} of ${g.traps.length} sent)`} isIndented>
              <TextInput aria-label="Filter traps" placeholder="Filter" value={filter} onChange={(_e, v) => setFilter(v)} className="dc-tab-body" />
              <Table aria-label={`${g.name} traps`} variant="compact">
                <Thead><Tr><Th>Trap</Th><Th>Sent</Th><Th>Failure traps</Th><Th>Interval</Th></Tr></Thead>
                <Tbody>
                  {g.traps.filter((t) => !filter || t.name.toLowerCase().includes(filter.toLowerCase())).map((t: SnmpTrap) => (
                    <Tr key={t.number}>
                      <Td dataLabel="Trap">{t.name} <span className="dc-subtle">({t.number})</span></Td>
                      <Td dataLabel="Sent"><Checkbox id={`t-${g.guid}-${t.number}-a`} aria-label={`Send ${t.name}`} isChecked={t.active} isDisabled={!edit}
                        onChange={(_e, v) => change(g, { traps: { [t.number]: { active: v } } }, `${t.name} ${v ? 'on' : 'off'}.`)} /></Td>
                      <Td dataLabel="Failure traps"><Checkbox id={`t-${g.guid}-${t.number}-f`} aria-label={`Failure traps for ${t.name}`} isChecked={t.failure} isDisabled={!edit}
                        onChange={(_e, v) => change(g, { traps: { [t.number]: { failure: v } } }, `Failure traps for ${t.name} ${v ? 'on' : 'off'}.`)} /></Td>
                      <Td dataLabel="Interval">
                        <IntervalField id={`t-${g.guid}-${t.number}-i`} label={`Interval for ${t.name}`} hideLabel value={t.interval} edit={edit}
                          onSave={(v) => change(g, { traps: { [t.number]: { interval: v } } }, `Interval for ${t.name} saved.`)} />
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              <p className="dc-subtle">An interval of 0 uses the group's default.</p>
            </ExpandableSection>
          </CardBody>
        </Card>
      ))}
      {confirmed.dialog}
    </div>
  );
}

function IntervalField({ id, label, hideLabel, value, edit, onSave }: { id: string; label: string; hideLabel?: boolean; value: number; edit: boolean; onSave: (v: number) => void }) {
  const [v, setV] = useState(String(value));
  useEffect(() => setV(String(value)), [value]);
  const n = Number(v);
  const ok = v !== '' && Number.isInteger(n) && n >= 0 && n <= 2592000;
  const input = (
    <Flex spaceItems={{ default: 'spaceItemsSm' }} flexWrap={{ default: 'nowrap' }}>
      <FlexItem><TextInput id={id} aria-label={hideLabel ? label : undefined} type="number" min={0} max={2592000} value={v} isDisabled={!edit}
        validated={ok ? 'default' : 'error'} onChange={(_e, x) => setV(x)} style={{ width: '8rem' }} /></FlexItem>
      {edit && String(value) !== v && <FlexItem><Button variant="link" isInline isDisabled={!ok} onClick={() => onSave(n)}>Save</Button></FlexItem>}
    </Flex>
  );
  return hideLabel ? input : <FormGroup label={label} fieldId={id}>{input}</FormGroup>;
}

/** Encrypted attributes and encrypted replication, read-only for now; and where FIPS mode is set. */
export function EncryptionView() {
  const { me } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const [e, setE] = useState<EncryptionOverview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => { setError(null); api.encryption().then(setE, setError); }, [api]);
  useEffect(load, [load]);
  if (!e) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading the encryption settings" />;
  }
  const policyName = (dn: string | null) => (dn ? e.policies.find((p) => p.dn.toLowerCase() === dn.toLowerCase())?.name ?? dn : null);
  return (
    <div className="dc-tab-body">
      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">Encrypted attributes</Title></CardTitle>
        <CardBody>
          <p className="dc-subtle">An encrypted attribute policy names attributes a server keeps encrypted on disk; a server uses at most one. Encryption cannot be undone
            securely (values written in clear text before stay on disk), so policies are shown here and changed in Identity Console for now.</p>
          {e.policies.length === 0 ? <p>No encrypted attribute policies.</p> : (
            <Table aria-label="Encrypted attribute policies" variant="compact">
              <Thead><Tr><Th>Policy</Th><Th>Attributes</Th><Th>Secure channel only</Th><Th>Servers</Th></Tr></Thead>
              <Tbody>
                {e.policies.map((p) => (
                  <Tr key={p.dn}>
                    <Td dataLabel="Policy"><a {...linkProps(`/objects/${p.guid}`)}>{p.name}</a><div className="dc-subtle dc-mono">{p.dn}</div></Td>
                    <Td dataLabel="Attributes">{p.attributes.map((x) => <div key={x.attribute}>{x.attribute} <span className="dc-subtle">({x.scheme || '?'})</span></div>)}</Td>
                    <Td dataLabel="Secure channel only">{p.requiresSecureChannel ? 'Yes' : <Label isCompact color="orange">No: readable in clear text</Label>}</Td>
                    <Td dataLabel="Servers">{p.servers.map((x) => x.name).join(', ') || <span className="dc-subtle">none</span>}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
          <p className="dc-subtle dc-tab-body">Servers: {e.servers.map((x) => `${x.name} (${policyName(x.policy) ?? 'no policy'})`).join(', ')}</p>
        </CardBody>
      </Card>
      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">Encrypted replication</Title></CardTitle>
        <CardBody>
          <p className="dc-subtle">Deprecated from eDirectory 9.2.7: Enhanced Background Authentication (Security &gt; EBA) secures server-to-server traffic instead, and takes precedence.</p>
          {e.replication.length === 0 ? <p>Not configured on any partition.</p> : (
            <Table aria-label="Encrypted replication" variant="compact">
              <Thead><Tr><Th>Partition</Th><Th>Setting</Th></Tr></Thead>
              <Tbody>
                {e.replication.map((r) => (
                  <Tr key={r.partition.dn}>
                    <Td dataLabel="Partition">{r.partition.name}</Td>
                    <Td dataLabel="Setting">{r.values.map((v) => <div key={v.raw}>{v.on ? 'On' : 'Off'}{v.wholePartition ? ', whole partition' : ', between particular replicas'} <span className="dc-subtle dc-mono">{v.raw}</span></div>)}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>
      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">FIPS mode</Title></CardTitle>
        <CardBody>
          <p>FIPS mode is set on each server in nds.conf (n4u.server.fips_tls) and needs ndsd restarted; it is not stored in the directory, so the console cannot show
            or change it. In FIPS mode an LDAP server uses only High ciphers, whatever its cipher level says (eDirectory &gt; LDAP).</p>
        </CardBody>
      </Card>
    </div>
  );
}

/** A server's replica filter: what its filtered (sparse) replicas hold. Read-only: a change resyncs every filtered replica on it. */
export function ReplicaFilterCard({ guid }: { guid: string }) {
  const { me } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const [f, setF] = useState<Awaited<ReturnType<typeof api.replicaFilter>> | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { api.replicaFilter(guid).then(setF, setError); }, [api, guid]);
  return (
    <Card className="dc-tab-body">
      <CardTitle><Title headingLevel="h2" size="lg">Replica filter</Title></CardTitle>
      <CardBody>
        <ProblemAlert error={error} />
        {!f ? (!error && <Spinner size="md" aria-label="Reading the replica filter" />) : f.classes.length === 0 ? (
          <p>No filter: this server holds no filtered replicas{f.sparseReplicas.length > 0 ? ', though it lists some' : ''}.</p>
        ) : (
          <>
            <p className="dc-subtle">Its filtered replicas ({f.sparseReplicas.map((r) => r.name).join(', ') || 'none yet'}) hold only these classes and attributes.
              Changing the filter resynchronises every filtered replica on the server.</p>
            <Table aria-label="Replica filter" variant="compact">
              <Thead><Tr><Th>Class</Th><Th>Attributes</Th></Tr></Thead>
              <Tbody>
                {f.classes.map((c) => (
                  <Tr key={c.class}>
                    <Td dataLabel="Class">{c.class}</Td>
                    <Td dataLabel="Attributes">{c.attributes.length ? c.attributes.join(', ') : <span className="dc-subtle">all</span>}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </>
        )}
      </CardBody>
    </Card>
  );
}
