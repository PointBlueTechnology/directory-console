import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActionGroup, Alert, AlertActionLink, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, CardTitle, Checkbox, Flex, FlexItem, Form, FormGroup,
  FormHelperText, FormSection, FormSelect, FormSelectOption, HelperText, HelperTextItem, PageSection, Spinner, TextArea, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type LdapMapping, type LdapObject, type LdapSettings, type TlsConfig, edir, security } from '../api';
import { useSession } from '../session';
import { useHeading } from '../heading';
import { linkProps } from '../router';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { useServerSignIn } from '../components/ServerSignIn';
import { ObjectPicker } from '../components/ObjectPicker';
import { FieldHelp, useHelpTopic } from '../help/Help';
import { explain } from '../help/glossary';

/** Bind restrictions, as the Administration Guide describes them (the low three bits). */
const BINDS = [
  'None', 'Disallow anonymous simple bind', 'Disallow non-anonymous simple bind', 'Disallow anonymous and non-anonymous simple bind',
  'Disallow unauthenticated bind (no password)', 'Disallow anonymous and unauthenticated bind', 'Disallow non-anonymous and unauthenticated bind',
  'Disallow anonymous, non-anonymous and unauthenticated bind',
];
/** Cipher level (16 x n). */
const CIPHERS = [
  'None (export ciphers)', 'Low (56- or 64-bit)', 'Medium (128-bit)', 'High (more than 128-bit)', 'Suite B (128-bit)', 'Suite B (128-bit only)', 'Suite B (192-bit)',
];
/** Cipher suite level (256 x n): Identity Console's choices, not documented elsewhere. */
const SUITES = ['None', 'Low (256-bit)', 'Medium (512-bit)', 'High (768-bit)'];
const REFERRALS = [
  ['Always chain', 'Never refers clients to other servers.'],
  ['Prefer chaining', 'Chains, except for persistent searches. The default.'],
  ['Prefer referrals', 'Refers clients to servers that run LDAP; chains otherwise.'],
  ['Always refer', 'As Prefer referrals, and returns the default referral when a server cannot be reached.'],
];
const DEFAULT_REFERRAL: [number, string][] = [
  [1, 'The base DN is not found'], [2, 'The base DN is on a server that cannot be reached'], [4, 'An entry in the search is on a server that cannot be reached'],
];
const TRACE: [number, string][] = [
  [8192, 'Critical errors'], [4096, 'Non-critical errors'], [1, 'Informational messages'], [8, 'Connections'], [64, 'Configuration processing'],
  [128, 'Extended operations'], [16, 'Packet dumps (hex)'], [16384, 'More connection and operation detail (hex)'],
];
/** What a refresh applies and what needs the LDAP module reloaded (as Identity Console treats them). */
const NEED_RELOAD = new Set(['ldapTLSRequired', 'sslEnableMutualAuthentication', 'ldapBindRestrictions', 'ldapSSLConfig', 'ldapInterfaces']);

const num = (v: unknown, d = 0) => (typeof v === 'number' ? v : d);
const bool = (v: unknown) => v === true;

/** The settings that differ from what was read: only those are sent. */
function changed(before: LdapSettings, after: LdapSettings): LdapSettings {
  const out: LdapSettings = {};
  for (const k of Object.keys(after)) {
    if (JSON.stringify(after[k]) !== JSON.stringify(before[k])) {
      out[k] = after[k];
    }
  }
  return out;
}

/** After a save: refresh or reload the LDAP servers it concerns, here or later. */
function useApply(servers: { guid: string | null; name: string; hostGuid?: string | null }[], onApplied?: () => void) {
  const { me } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const signIn = useServerSignIn();
  const sure = useAreYouSure();
  const [connected, setConnected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { api.servers().then((ss) => setConnected(ss.find((x) => x.connected)?.guid ?? null), () => {}); }, [api]);
  const run = async (reload: boolean) => {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      for (const s of servers) {
        if (s.guid) {
          await signIn.run(() => (reload ? api.reloadLdapServer(s.guid!) : api.refreshLdapServer(s.guid!)));
        }
      }
      setDone(`${servers.map((s) => s.name).join(', ')} ${reload ? 'reloaded' : 're-read the configuration'}.`);
      onApplied?.();
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  const apply = (reload: boolean) => {
    const ownServer = servers.find((s) => s.hostGuid && s.hostGuid === connected);
    if (!reload) {
      run(false);
    } else {
      sure.ask(`Reload ${servers.length === 1 ? servers[0].name : 'these LDAP servers'}?`,
        `The LDAP module restarts, which drops every LDAP connection to ${servers.map((s) => s.name).join(', ')} for a moment.${ownServer
          ? ' That includes the console\'s own: everyone signed in to the console will have to sign in again.' : ''}`,
        'Reload', () => run(true));
    }
  };
  const view = (
    <>
      {done && <Alert variant="success" isInline isPlain title={done} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {signIn.dialog}
      {sure.dialog}
    </>
  );
  return { apply, busy, view, setDone };
}

/** A notice after saving: what applies the change, with the button that does it. */
function Saved({ needs, apply, busy }: { needs: 'refresh' | 'reload'; apply: (reload: boolean) => void; busy: boolean }) {
  return (
    <Alert variant="info" isInline className="dc-tab-body"
      title={needs === 'reload' ? 'Saved. The LDAP server applies these settings when its LDAP module is reloaded.' : 'Saved. The LDAP server applies it when refreshed, or by itself within 30 minutes.'}
      actionLinks={<AlertActionLink onClick={() => apply(needs === 'reload')} isDisabled={busy}>{needs === 'reload' ? 'Reload now' : 'Refresh now'}</AlertActionLink>} />
  );
}

/** One editable number: empty means not set, which eDirectory reads as its default. */
function NumberField({ id, label, help, more, value, onChange }: { id: string; label: string; help: string; more?: string; value: unknown; onChange: (v: number | null) => void }) {
  return (
    <FormGroup label={label} fieldId={id} labelHelp={more ? <FieldHelp label={label}>{more}</FieldHelp> : undefined}>
      <TextInput id={id} type="number" min={0} value={typeof value === 'number' ? String(value) : ''} onChange={(_e, v) => onChange(v === '' ? null : Math.max(0, Number(v)))} />
      <FormHelperText><HelperText><HelperTextItem>{help}</HelperTextItem></HelperText></FormHelperText>
    </FormGroup>
  );
}

function ReferralFields({ s, set, prefix }: { s: LdapSettings; set: (k: string, v: LdapSettings[string]) => void; prefix: string }) {
  const behaviour = num(s.ldapDefaultReferralBehavior);
  return (
    <>
      {([['ldapSearchReferralUsage', 'Referrals for searches'], ['lDAPOtherReferralUsage', 'Referrals for other operations']] as const).map(([k, label]) => (
        <FormGroup key={k} label={label} fieldId={`${prefix}-${k}`}>
          <FormSelect id={`${prefix}-${k}`} value={String(num(s[k], 1))} onChange={(_e, v) => set(k, Number(v))}>
            {REFERRALS.map(([l], i) => <FormSelectOption key={l} value={String(i)} label={l} />)}
          </FormSelect>
          <FormHelperText><HelperText><HelperTextItem>{REFERRALS[num(s[k], 1)]?.[1]}</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
      ))}
      <FormGroup label="Return the default referral when" fieldId={`${prefix}-default-referral`} role="group"
        labelHelp={<FieldHelp label="Default referral">Only when the referral setting is Always refer.</FieldHelp>}>
        {DEFAULT_REFERRAL.map(([bit, label]) => (
          <Checkbox key={bit} id={`${prefix}-dr-${bit}`} label={label} isChecked={(behaviour & bit) !== 0}
            onChange={(_e, on) => set('ldapDefaultReferralBehavior', on ? behaviour | bit : behaviour & ~bit)} />
        ))}
      </FormGroup>
    </>
  );
}

/** ldapSSLConfig: protocols as checkboxes, ciphers and TLS 1.3 suites as text; empty uses the cipher level. */
function TlsFields({ value, onChange, prefix }: { value: unknown; onChange: (v: TlsConfig) => void; prefix: string }) {
  const t: TlsConfig = { protocol: '', ciphers: '', ciphersuites: '', ...(value as Partial<TlsConfig> | null ?? {}) };
  const has = (p: string) => t.protocol.includes(`+${p}`);
  const toggle = (p: string, on: boolean) => {
    const ps = ['TLSv1.2', 'TLSv1.3'].filter((x) => (x === p ? on : has(x)));
    onChange({ ...t, protocol: ps.map((x) => `+${x}`).join('') });
  };
  const custom = t.protocol !== '' && !/^(\+TLSv1\.[23])*$/.test(t.protocol);
  return (
    <>
      <FormGroup label="Protocols" fieldId={`${prefix}-tls12`} role="group">
        {custom ? <p className="dc-mono">{t.protocol}</p> : (
          <>
            <Checkbox id={`${prefix}-tls12`} label="TLS 1.2" isChecked={has('TLSv1.2')} onChange={(_e, on) => toggle('TLSv1.2', on)} />
            <Checkbox id={`${prefix}-tls13`} label="TLS 1.3" isChecked={has('TLSv1.3')} onChange={(_e, on) => toggle('TLSv1.3', on)} />
          </>
        )}
        <FormHelperText><HelperText><HelperTextItem>None chosen: eDirectory's defaults, limited by each server's cipher level.</HelperTextItem></HelperText></FormHelperText>
      </FormGroup>
      <FormGroup label="Ciphers (TLS 1.2)" fieldId={`${prefix}-ciphers`}>
        <TextArea id={`${prefix}-ciphers`} className="dc-mono" value={t.ciphers} onChange={(_e, v) => onChange({ ...t, ciphers: v.trim() })} resizeOrientation="vertical" rows={2} />
        <FormHelperText><HelperText><HelperTextItem>An OpenSSL cipher list, such as ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384.</HelperTextItem></HelperText></FormHelperText>
      </FormGroup>
      <FormGroup label="Cipher suites (TLS 1.3)" fieldId={`${prefix}-suites`}>
        <TextInput id={`${prefix}-suites`} className="dc-mono" value={t.ciphersuites} onChange={(_e, v) => onChange({ ...t, ciphersuites: v.trim() })} />
        <FormHelperText><HelperText><HelperTextItem>Separated by colons, such as TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256.</HelperTextItem></HelperText></FormHelperText>
      </FormGroup>
    </>
  );
}

/** One LDAP Server object: ports, TLS, limits, searches, compatibility and trace. */
export function LdapServerPage({ guid }: { guid: string }) {
  const { me, canAt } = useSession();
  useHelpTopic('edir.ldap-server');
  const level = useHeading();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const pki = useMemo(() => security(me.directory), [me.directory]);
  const [o, setO] = useState<LdapObject | null>(null);
  const [s, setS] = useState<LdapSettings>({});
  const [certs, setCerts] = useState<{ guid: string; name: string }[]>([]);
  const [certificate, setCertificate] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const [needs, setNeeds] = useState<'refresh' | 'reload' | null>(null);
  const confirmed = useConfirmed();
  const edit = canAt('editor', '');
  const show = useCallback((x: LdapObject) => { setO(x); setS(x.settings); setCertificate(x.certificate ?? ''); }, []);
  const load = useCallback(() => { setError(null); api.ldapServer(guid).then(show, setError); }, [api, guid, show]);
  useEffect(load, [load]);
  useEffect(() => {
    if (o?.host?.dn) {
      pki.pki().then((p) => setCerts(p.serverCertificates.filter((k) => k.guid && k.server?.dn.toLowerCase() === o.host!.dn.toLowerCase())
        .map((k) => ({ guid: k.guid!, name: k.name.replace(/ - [^-]*$/, '') }))), () => {});
    }
  }, [pki, o?.host?.dn]);
  const applier = useApply(o ? [{ guid: o.guid, name: o.name, hostGuid: o.host?.guid }] : [], () => setNeeds(null));

  if (!o) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading the LDAP server" />}</PageSection>;
  }
  const set = (k: string, v: LdapSettings[string]) => setS((x) => ({ ...x, [k]: v }));
  const diff = changed(o.settings, s);
  const certChanged = certificate !== (o.certificate ?? '') && certificate !== '';
  const dirty = Object.keys(diff).length > 0 || certChanged;
  const br = num(s.ldapBindRestrictions, 48);
  const setBr = (bind: number, cipher: number, suite: number) => set('ldapBindRestrictions', bind + 16 * cipher + 256 * suite);
  const [bind, cipher, suite] = [br & 7, (br >> 4) & 7, (br >> 8) & 3];
  const trace = num(s.ldapTraceLevel);
  const interfaces = Array.isArray(s.ldapInterfaces) ? (s.ldapInterfaces as string[]) : [];

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setNeeds(null);
    applier.setDone(null);
    try {
      let after = o;
      if (Object.keys(diff).length > 0) {
        after = await confirmed.run((c) => api.changeLdapServer(guid, diff, c));
      }
      if (certChanged) {
        const k = certs.find((x) => x.name === certificate);
        if (k) {
          await confirmed.run((c) => pki.useForLdap(guid, k.guid, c));
          after = await api.ldapServer(guid);
        }
      }
      show(after);
      setNeeds(certChanged || Object.keys(diff).some((k) => NEED_RELOAD.has(k)) ? 'reload' : 'refresh');
    } catch (x) {
      setError(x);
    } finally {
      setSaving(false);
    }
  };

  return (
    <PageSection isFilled>
      <Breadcrumb>
        <BreadcrumbItem><a {...linkProps('/edir/ldap')}>LDAP</a></BreadcrumbItem>
        <BreadcrumbItem isActive>{o.name}</BreadcrumbItem>
      </Breadcrumb>
      <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsCenter' }}>
        <FlexItem grow={{ default: 'grow' }}>
          <Title headingLevel="h1">{o.name}</Title>
          <p className="dc-subtle">On {o.host?.guid ? <a {...linkProps(`/edir/servers/${o.host.guid}`)}>{o.host.name}</a> : o.host?.name ?? '—'}
            {o.group && <>, in {o.group.guid ? <a {...linkProps(`/edir/ldap-groups/${o.group.guid}`)}>{o.group.name}</a> : o.group.name}</>}</p>
        </FlexItem>
        {edit && (
          <FlexItem>
            <Button variant="secondary" isDisabled={applier.busy} onClick={() => applier.apply(false)}>Refresh</Button>{' '}
            <Button variant="secondary" isDanger isDisabled={applier.busy} onClick={() => applier.apply(true)}>Reload</Button>
          </FlexItem>
        )}
      </Flex>
      {needs && <Saved needs={needs} apply={applier.apply} busy={applier.busy} />}
      {applier.view}
      <Card className="dc-tab-body">
        <CardBody>
          <Form onSubmit={save} isWidthLimited>
            <FormSection title="Connections" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <FormGroup label="Listens on" fieldId="ldap-interfaces" labelHelp={<FieldHelp label="Listens on">One per line: ldap:// or ldaps://, an address (empty for every address) and a port. IPv6 addresses go in brackets. A change needs a reload.</FieldHelp>}>
                <TextArea id="ldap-interfaces" className="dc-mono" value={interfaces.join('\n')} isDisabled={!edit} resizeOrientation="vertical" rows={2}
                  onChange={(_e, v) => set('ldapInterfaces', v.split('\n').map((x) => x.trim()).filter(Boolean))} />
              </FormGroup>
              <FormGroup label="Server certificate" fieldId="ldap-cert">
                <FormSelect id="ldap-cert" value={certificate} isDisabled={!edit} onChange={(_e, v) => setCertificate(v)}>
                  {!certificate && <FormSelectOption value="" label="None" />}
                  {certificate && !certs.some((k) => k.name === certificate) && <FormSelectOption value={certificate} label={certificate} />}
                  {certs.map((k) => <FormSelectOption key={k.guid} value={k.name} label={k.name} />)}
                </FormSelect>
                <FormHelperText><HelperText><HelperTextItem>One of {o.host?.name ?? 'its server'}'s certificates, offered to LDAPS and StartTLS clients.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              <Checkbox id="ldap-tls-required" label="Require TLS for all operations" isChecked={bool(s.ldapTLSRequired)} isDisabled={!edit} onChange={(_e, v) => set('ldapTLSRequired', v)} />
              <FormGroup label="Client certificates" fieldId="ldap-client-certs" labelHelp={<FieldHelp label="Client certificates">{explain('clientCertificates')}</FieldHelp>}>
                <FormSelect id="ldap-client-certs" value={String(num(s.ldapTLSVerifyClientCertificate))} isDisabled={!edit} onChange={(_e, v) => set('ldapTLSVerifyClientCertificate', Number(v))}>
                  <FormSelectOption value="0" label="Not requested" />
                  <FormSelectOption value="1" label="Requested" />
                  <FormSelectOption value="2" label="Required" />
                </FormSelect>
              </FormGroup>
              <Checkbox id="ldap-mutual" label="Enable and require mutual authentication" isChecked={bool(s.sslEnableMutualAuthentication)} isDisabled={!edit}
                onChange={(_e, v) => set('sslEnableMutualAuthentication', v)} description={explain('mutualAuthentication')} />
              <FormGroup label="Bind restrictions" fieldId="ldap-binds">
                <FormSelect id="ldap-binds" value={String(bind)} isDisabled={!edit} onChange={(_e, v) => setBr(Number(v), cipher, suite)}>
                  {BINDS.map((l, i) => <FormSelectOption key={l} value={String(i)} label={l} />)}
                </FormSelect>
              </FormGroup>
              <FormGroup label="Cipher level" fieldId="ldap-cipher" labelHelp={<FieldHelp label="Cipher level">The weakest ciphers clients may use. In FIPS mode only High applies. A list of protocols or ciphers below overrides it.</FieldHelp>}>
                <FormSelect id="ldap-cipher" value={String(cipher)} isDisabled={!edit} onChange={(_e, v) => setBr(bind, Number(v), suite)}>
                  {CIPHERS.map((l, i) => <FormSelectOption key={l} value={String(i)} label={l} />)}
                </FormSelect>
              </FormGroup>
              <FormGroup label="Cipher suite level" fieldId="ldap-suite" labelHelp={<FieldHelp label="Cipher suite level">{explain('cipherSuiteLevel')}</FieldHelp>}>
                <FormSelect id="ldap-suite" value={String(suite)} isDisabled={!edit} onChange={(_e, v) => setBr(bind, cipher, Number(v))}>
                  {SUITES.map((l, i) => <FormSelectOption key={l} value={String(i)} label={l} />)}
                </FormSelect>
              </FormGroup>
            </FormSection>
            <FormSection title="TLS protocols and ciphers" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <p className="dc-subtle">Set here, they apply to this server and override its LDAP group's.</p>
              <TlsFields prefix="srv" value={s.ldapSSLConfig} onChange={(v) => set('ldapSSLConfig', v)} />
            </FormSection>
            <FormSection title="Limits" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <NumberField id="ldap-size" label="Search entry limit" help="0 means no limit. Administrators of this LDAP Server object are not limited." value={s.searchSizeLimit} onChange={(v) => set('searchSizeLimit', v)} />
              <NumberField id="ldap-time" label="Search time limit (seconds)" help="0 means no limit." value={s.searchTimeLimit} onChange={(v) => set('searchTimeLimit', v)} />
              <NumberField id="ldap-bind-limit" label="Bind limit" help="The most concurrent bound connections; 0 means no limit." value={s.ldapServerBindLimit} onChange={(v) => set('ldapServerBindLimit', v)} />
              <NumberField id="ldap-idle" label="Idle timeout (seconds)" help="Closes a connection idle this long; 0 means never." value={s.ldapServerIdleTimeout} onChange={(v) => set('ldapServerIdleTimeout', v)} />
            </FormSection>
            <FormSection title="Searches and events" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <Checkbox id="ldap-filtered" label="Use filtered replicas for searches" isChecked={num(s.filteredReplicaUsage) === 1} isDisabled={!edit} onChange={(_e, v) => set('filteredReplicaUsage', v ? 1 : 0)}
                description={explain('filteredReplicaUsage')} />
              <Checkbox id="ldap-psearch" label="Allow persistent searches" isChecked={bool(s.ldapEnablePSearch)} isDisabled={!edit} onChange={(_e, v) => set('ldapEnablePSearch', v)}
                description={explain('persistentSearch')} />
              <NumberField id="ldap-psearch-max" label="Most persistent searches" help="0 means no limit." value={s.ldapMaximumPSearchOperations} onChange={(v) => set('ldapMaximumPSearchOperations', v)} />
              <Checkbox id="ldap-psearch-limits" label="Persistent searches for events ignore the limits" isChecked={bool(s.ldapIgnorePSearchLimitsForEvents)} isDisabled={!edit}
                onChange={(_e, v) => set('ldapIgnorePSearchLimitsForEvents', v)} />
              <Checkbox id="ldap-events" label="Allow event monitoring" isChecked={bool(s.ldapEnableMonitorEvents)} isDisabled={!edit} onChange={(_e, v) => set('ldapEnableMonitorEvents', v)} />
              <NumberField id="ldap-events-max" label="Most event monitoring load" help="0 means no limit." value={s.ldapMaximumMonitorEventsLoad} onChange={(v) => set('ldapMaximumMonitorEventsLoad', v)} />
              <ReferralFields prefix="srv" s={s} set={set} />
              <p className="dc-subtle">Referral settings here override the LDAP group's.</p>
            </FormSection>
            <FormSection title="Compatibility" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              {([
                ['ldapNonStdAllUserAttrsMode', 'Return operational attributes with * (non-standard)'],
                ['nonStdClientSchemaCompatMode', 'Non-standard client schema compatibility'],
                ['ldapDerefAlias', 'Dereference aliases in searches'],
                ['ldapDerefAliasOnAuth', 'Dereference aliases on bind'],
                ['ldapGeneralizedTime', 'Return times as Generalized Time'],
                ['ldapPermissiveModify', 'Permissive modify (no error for a value already there or not there)'],
              ] as const).map(([k, l]) => <Checkbox key={k} id={`ldap-${k}`} label={l} isChecked={bool(s[k])} isDisabled={!edit} onChange={(_e, v) => set(k, v)} />)}
              <NumberField id="ldap-lburp" label="Bulk load (LBURP) writer threads" help="1 to 64." more={explain('lburp')} value={s.ldapLBURPNumWriterThreads} onChange={(v) => set('ldapLBURPNumWriterThreads', v)} />
            </FormSection>
            <FormSection title="Trace" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <p className="dc-subtle">What the LDAP server writes to ndstrace.</p>
              {TRACE.map(([bit, l]) => (
                <Checkbox key={bit} id={`ldap-trace-${bit}`} label={l} isChecked={(trace & bit) !== 0} isDisabled={!edit}
                  onChange={(_e, on) => set('ldapTraceLevel', on ? trace | bit : trace & ~bit)} />
              ))}
            </FormSection>
            <ProblemAlert error={error} />
            {edit && (
              <ActionGroup>
                <Button type="submit" isLoading={saving} isDisabled={saving || !dirty}>Save</Button>
                <Button variant="link" isDisabled={!dirty} onClick={() => show(o)}>Discard changes</Button>
              </ActionGroup>
            )}
          </Form>
        </CardBody>
      </Card>
      {confirmed.dialog}
    </PageSection>
  );
}

/** A class or attribute mapping table, edited in place. */
function Mappings({ title, value, onChange, edit, kind }: { title: string; value: LdapMapping[]; onChange: (v: LdapMapping[]) => void; edit: boolean; kind: 'class' | 'attribute' }) {
  const [filter, setFilter] = useState('');
  const [nds, setNds] = useState('');
  const [ldap, setLdap] = useState('');
  const shown = value.map((m, i) => ({ m, i })).filter(({ m }) => !filter || `${m.eDirectory} ${m.ldap.join(' ')}`.toLowerCase().includes(filter.toLowerCase()));
  const names = (v: string) => v.split(/[\s,]+/).filter(Boolean);
  const valid = nds.trim() !== '' && !nds.includes('$') && names(ldap).length > 0 && names(ldap).every((n) => /^[A-Za-z][A-Za-z0-9-]*$/.test(n));
  return (
    <Card className="dc-tab-body">
      <CardTitle><Title headingLevel="h2" size="lg">{title} ({value.length})</Title></CardTitle>
      <CardBody>
        <p className="dc-subtle">How LDAP clients name eDirectory {kind === 'class' ? 'classes' : 'attributes'}: the first LDAP name is the one the server returns; the others are accepted too.</p>
        <TextInput aria-label={`Filter ${title.toLowerCase()}`} placeholder="Filter" value={filter} onChange={(_e, v) => setFilter(v)} className="dc-tab-body" />
        <Table aria-label={title} variant="compact">
          <Thead><Tr><Th>eDirectory name</Th><Th>LDAP names</Th><Th>Description</Th>{edit && <Th screenReaderText="Remove" />}</Tr></Thead>
          <Tbody>
            {shown.slice(0, 200).map(({ m, i }) => (
              <Tr key={`${m.eDirectory}-${i}`}>
                <Td dataLabel="eDirectory name">{m.eDirectory}</Td>
                <Td dataLabel="LDAP names" className="dc-mono">
                  {edit ? <TextInput aria-label={`LDAP names for ${m.eDirectory}`} value={m.ldap.join(', ')}
                    onChange={(_e, v) => onChange(value.map((x, j) => (j === i ? { ...x, ldap: names(v) } : x)))} /> : m.ldap.join(', ')}
                </Td>
                <Td dataLabel="Description">{m.description ?? ''}{m.obsolete && <span className="dc-subtle"> (obsolete)</span>}</Td>
                {edit && <Td isActionCell><Button variant="link" isInline isDanger onClick={() => onChange(value.filter((_x, j) => j !== i))}>Remove</Button></Td>}
              </Tr>
            ))}
          </Tbody>
        </Table>
        {shown.length > 200 && <p className="dc-subtle">Showing 200 of {shown.length}; filter to find others.</p>}
        {edit && (
          <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsFlexEnd' }}>
            <FlexItem><FormGroup label="eDirectory name" fieldId={`map-${kind}-nds`}><TextInput id={`map-${kind}-nds`} value={nds} onChange={(_e, v) => setNds(v)} /></FormGroup></FlexItem>
            <FlexItem grow={{ default: 'grow' }}><FormGroup label="LDAP names" fieldId={`map-${kind}-ldap`}><TextInput id={`map-${kind}-ldap`} className="dc-mono" value={ldap} onChange={(_e, v) => setLdap(v)} placeholder="first, others" /></FormGroup></FlexItem>
            <FlexItem><Button variant="secondary" isDisabled={!valid} onClick={() => { onChange([...value, { eDirectory: nds.trim(), ldap: names(ldap) }]); setNds(''); setLdap(''); }}>Add</Button></FlexItem>
          </Flex>
        )}
      </CardBody>
    </Card>
  );
}

/** One LDAP Group object: TLS for simple binds, the proxy user, referrals, TLS settings and the name mappings. */
export function LdapGroupPage({ guid }: { guid: string }) {
  const { me, canAt } = useSession();
  useHelpTopic('edir.ldap-group');
  const level = useHeading();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const [o, setO] = useState<LdapObject | null>(null);
  const [s, setS] = useState<LdapSettings>({});
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const [needs, setNeeds] = useState<'refresh' | 'reload' | null>(null);
  const [picking, setPicking] = useState(false);
  const confirmed = useConfirmed();
  const edit = canAt('editor', '');
  const show = useCallback((x: LdapObject) => { setO(x); setS(x.settings); }, []);
  const load = useCallback(() => { setError(null); api.ldapGroup(guid).then(show, setError); }, [api, guid, show]);
  useEffect(load, [load]);
  const [members, setMembers] = useState<{ guid: string | null; name: string; hostGuid?: string | null }[]>([]);
  useEffect(() => {
    if (o?.servers) {
      api.ldap().then((c) => setMembers((o.servers ?? []).map((m) => {
        const srv = c.servers.find((x) => x.guid === m.guid);
        return { guid: m.guid, name: m.name, hostGuid: srv?.host?.guid ?? null };
      })), () => setMembers((o.servers ?? []).map((m) => ({ guid: m.guid, name: m.name }))));
    }
  }, [api, o?.servers]);
  const applier = useApply(members, () => setNeeds(null));

  if (!o) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading the LDAP group" />}</PageSection>;
  }
  const set = (k: string, v: LdapSettings[string]) => setS((x) => ({ ...x, [k]: v }));
  const diff = changed(o.settings, s);
  const dirty = Object.keys(diff).length > 0;
  const save = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setSaving(true);
    setError(null);
    setNeeds(null);
    applier.setDone(null);
    try {
      const after = await confirmed.run((c) => api.changeLdapGroup(guid, diff, c));
      show(after);
      setNeeds(after.needs ?? 'refresh');
    } catch (x) {
      setError(x);
    } finally {
      setSaving(false);
    }
  };
  const mappings = (k: string) => (Array.isArray(s[k]) ? (s[k] as LdapMapping[]) : []);

  return (
    <PageSection isFilled>
      <Breadcrumb>
        <BreadcrumbItem><a {...linkProps('/edir/ldap')}>LDAP</a></BreadcrumbItem>
        <BreadcrumbItem isActive>{o.name}</BreadcrumbItem>
      </Breadcrumb>
      <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsCenter' }}>
        <FlexItem grow={{ default: 'grow' }}>
          <Title headingLevel="h1">{o.name}</Title>
          <p className="dc-subtle">Its LDAP servers: {(o.servers ?? []).map((m, i) => (
            <span key={m.dn}>{i > 0 && ', '}{m.guid ? <a {...linkProps(`/edir/ldap-servers/${m.guid}`)}>{m.name}</a> : m.name}</span>
          ))}{(o.servers ?? []).length === 0 && 'none'}</p>
        </FlexItem>
        {edit && members.length > 0 && (
          <FlexItem><Button variant="secondary" isDisabled={applier.busy} onClick={() => applier.apply(false)}>Refresh its servers</Button></FlexItem>
        )}
      </Flex>
      {needs && <Saved needs={needs} apply={applier.apply} busy={applier.busy} />}
      {applier.view}
      <Card className="dc-tab-body">
        <CardBody>
          <Form onSubmit={save} isWidthLimited>
            <FormSection title="Binds" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <Checkbox id="grp-tls-simple" label="Require TLS for simple binds with a password" isChecked={s.ldapAllowClearTextPassword === false} isDisabled={!edit}
                onChange={(_e, v) => set('ldapAllowClearTextPassword', !v)}
                description="When on, a client must use LDAPS or StartTLS before sending a password." />
              <FormGroup label="Proxy user" fieldId="grp-proxy" labelHelp={<FieldHelp label="Proxy user">Anonymous LDAP clients get this user's rights. Leave it empty for [Public]'s.</FieldHelp>}>
                <Flex alignItems={{ default: 'alignItemsCenter' }}>
                  <FlexItem grow={{ default: 'grow' }}><TextInput id="grp-proxy" className="dc-mono" value={typeof s.ldapAnonymousIdentity === 'string' ? s.ldapAnonymousIdentity : ''}
                    isDisabled={!edit} onChange={(_e, v) => set('ldapAnonymousIdentity', v.trim() === '' ? null : v)} placeholder="none: anonymous clients have [Public]'s rights" /></FlexItem>
                  {edit && <FlexItem><Button variant="link" onClick={() => setPicking(!picking)}>{picking ? 'Close' : 'Find…'}</Button></FlexItem>}
                </Flex>
                {picking && <ObjectPicker classes={['inetOrgPerson']} label="Find the proxy user" onPick={(r) => { set('ldapAnonymousIdentity', r.dn); setPicking(false); }} />}
              </FormGroup>
            </FormSection>
            <FormSection title="Referrals" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <ReferralFields prefix="grp" s={s} set={set} />
            </FormSection>
            <FormSection title="TLS protocols and ciphers" titleElement={level === 'h2' ? 'h3' : 'h2'}>
              <p className="dc-subtle">For every server in the group, unless a server sets its own.</p>
              <TlsFields prefix="grp" value={s.ldapSSLConfig} onChange={(v) => set('ldapSSLConfig', v)} />
            </FormSection>
            <ProblemAlert error={error} />
            {edit && (
              <ActionGroup>
                <Button type="submit" isLoading={saving} isDisabled={saving || !dirty}>Save</Button>
                <Button variant="link" isDisabled={!dirty} onClick={() => show(o)}>Discard changes</Button>
              </ActionGroup>
            )}
          </Form>
        </CardBody>
      </Card>
      <Mappings title="Class mappings" kind="class" edit={edit} value={mappings('ldapClassList')} onChange={(v) => set('ldapClassList', v)} />
      <Mappings title="Attribute mappings" kind="attribute" edit={edit} value={mappings('ldapAttributeList')} onChange={(v) => set('ldapAttributeList', v)} />
      {edit && dirty && (
        <Flex className="dc-tab-body"><FlexItem><Button onClick={() => save()} isLoading={saving} isDisabled={saving}>Save</Button></FlexItem>
          <FlexItem><Button variant="link" onClick={() => show(o)}>Discard changes</Button></FlexItem></Flex>
      )}
      {confirmed.dialog}
    </PageSection>
  );
}
