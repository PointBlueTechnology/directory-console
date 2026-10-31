import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActionGroup, Alert, Button, Card, CardBody, Checkbox, ClipboardCopy, FileUpload, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, FormSection, FormSelect, FormSelectOption, Flex, FlexItem, HelperText,
  HelperTextItem, Label, LabelGroup, List, ListItem, PageSection, Radio, Spinner, Tab, Tabs, TabTitleText, TextArea, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { DownloadIcon, PlusIcon, UploadIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AcmeState, type ConfigVersion, type RestorePending, records, type DirectorySettings, type ServiceAccountCheck, type ExpirySettings, type ExpiryState, type SyslogState, acme, expiry, syslog, type OidcSettings, type Preset, type RoleMappingJson, type UpdateState, UPGRADING_URL, consoleSettings, settings, updates } from '../api';
import { useSession } from '../session';
import { HeadingLevel, useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { RoleMappings } from '../components/RoleMappings';
import { PresetEditor, presetJson } from '../components/PresetEditor';
import { useStepUp } from '../components/StepUp';
import { TreesSection } from '../components/TreesSection';
import { FieldHelp, Hint, useHelpTopic } from '../help/Help';
import { explain } from '../help/glossary';
import { useAreYouSure } from '../components/Confirm';
import { ExpiryLabel, Fingerprint } from '../components/Certificates';
import { TrustedCertificates } from '../components/TrustedCertificates';
import { navigate, useLocation } from '../router';

/** A whole number from {@code min} to {@code max}. */
const sessionOk = (v: string, min: number, max: number) => /^\d+$/.test(v.trim()) && Number(v) >= min && Number(v) <= max;

const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);

/**
 * Who may sign in to this directory and what they may do (sections 7.3 and 7.4): role mappings,
 * task presets and single sign-on. Admins only; a change needs a sign-in within the last 10 minutes.
 */
export function SettingsPage() {
  const { me } = useSession();
  const api = useMemo(() => settings(me.directory), [me.directory]);
  const [s, setS] = useState<DirectorySettings | null>(null);
  const [etag, setEtag] = useState<string | undefined>();
  const [error, setError] = useState<unknown>(null);
  // the tab is in the address (?tab=), so a link such as the expiry banner's opens it
  const { query } = useLocation();
  const tab = query.get('tab') ?? 'directory';
  const setTab = (k: string | number) => navigate(`/settings?tab=${encodeURIComponent(String(k))}`, true);
  useHelpTopic(`settings.${String(tab)}`);
  const load = useCallback(() => {
    setError(null);
    api.get().then((r) => { setS(r.data); setEtag(r.etag); }).catch(setError);
  }, [api]);
  useEffect(load, [load]);
  const saved = (r: { data: DirectorySettings; etag?: string }) => { setS(r.data); setEtag(r.etag); };

  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Settings</Title>
      {s && <p className="dc-subtle">{s.name} · {s.tier}</p>}
      <ProblemAlert error={error} onRetry={load} />
      {!s && !error && <Spinner aria-label="Loading the settings" />}
      {s && (
        <HeadingLevel.Provider value="h2">
          <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Settings" mountOnEnter className="dc-tab-body">
            <Tab eventKey="directory" title={<TabTitleText>Directory</TabTitleText>}>
              <DirectorySection s={s} api={api} etag={etag} onSaved={saved} />
            </Tab>
            <Tab eventKey="roles" title={<TabTitleText>Role mappings</TabTitleText>}>
              <RolesSection s={s} etag={etag} save={(v) => api.roles(v, etag)} onSaved={saved} />
            </Tab>
            <Tab eventKey="presets" title={<TabTitleText>Task presets</TabTitleText>}>
              <PresetsSection s={s} etag={etag} save={(v) => api.presets(v, etag)} exportAll={api.exportPresets} onSaved={saved} />
            </Tab>
            <Tab eventKey="sso" title={<TabTitleText>Single sign-on</TabTitleText>}>
              <SsoSection s={s} save={(v) => api.oidc(v, etag)} test={api.testMapping} check={api.checkServiceAccount} onSaved={saved} />
              {s.oidc && s.serviceAccount && <PasswordSignInSection s={s} save={(v) => api.login(v, etag)} onSaved={saved} />}
            </Tab>
            <Tab eventKey="trees" title={<TabTitleText>Directories</TabTitleText>}>
              <TreesSection />
            </Tab>
            <Tab eventKey="other" title={<TabTitleText>Other directories</TabTitleText>}>
              <OtherDirectoriesSection />
            </Tab>
            <Tab eventKey="trust" title={<TabTitleText>Trusted certificates</TabTitleText>}>
              <TrustedCertificates />
            </Tab>
            <Tab eventKey="certificate" title={<TabTitleText>Console certificate</TabTitleText>}>
              <ConsoleCertificateSection />
            </Tab>
            <Tab eventKey="expiry" title={<TabTitleText>Certificate expiry</TabTitleText>}>
              <ExpirySection />
            </Tab>
            <Tab eventKey="syslog" title={<TabTitleText>Syslog</TabTitleText>}>
              <SyslogSection />
            </Tab>
            <Tab eventKey="backup" title={<TabTitleText>History and backup</TabTitleText>}>
              <HistoryAndBackupSection />
            </Tab>
            <Tab eventKey="updates" title={<TabTitleText>Updates</TabTitleText>}>
              <UpdatesSection />
            </Tab>
            <Tab eventKey="proxy" title={<TabTitleText>Reverse proxy</TabTitleText>}>
              <ProxySection />
            </Tab>
          </Tabs>
        </HeadingLevel.Provider>
      )}
    </PageSection>
  );
}

/**
 * The directory itself: its tier, how names are found at sign-in, and the console's service account.
 * First sign-in leaves these for later (production, no search bases, no service account): until a
 * service account is set, people sign in with their full name (DN) and single sign-on is unavailable.
 */
function DirectorySection({ s, api, etag, onSaved }: {
  s: DirectorySettings; api: ReturnType<typeof settings>; etag?: string; onSaved: (r: { data: DirectorySettings; etag?: string }) => void;
}) {
  const { run, dialog } = useStepUp();
  const sure = useAreYouSure();
  const [tier, setTier] = useState(s.tier);
  const [bases, setBases] = useState(s.login.searchBases.join('\n'));
  const [duplicates, setDuplicates] = useState(s.login.duplicates);
  const [saDn, setSaDn] = useState(s.serviceAccount ?? '');
  const [idleMinutes, setIdleMinutes] = useState(String(s.session.idleMinutes));
  const [maxHours, setMaxHours] = useState(String(s.session.maxHours));
  const [agentOn, setAgentOn] = useState(s.agentKeys.enabled);
  const [agentDays, setAgentDays] = useState(String(s.agentKeys.maxDays));
  const [agentApprove, setAgentApprove] = useState(s.agentKeys.approveChanges);
  const [appsUrl, setAppsUrl] = useState(s.apps.url ?? '');
  const [appsClient, setAppsClient] = useState(s.apps.clientId ?? 'rbpmrest');
  const [appsSecret, setAppsSecret] = useState('');
  const [saPassword, setSaPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const go = (what: string, call: () => Promise<{ data: DirectorySettings; etag?: string }>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    run(call).then((r) => { onSaved(r); setNotice(what); setSaPassword(''); }, setError).finally(() => setBusy(false));
  };
  const basesChanged = lines(bases).join('|') !== s.login.searchBases.join('|') || duplicates !== s.login.duplicates;
  return (
    <div className="dc-tab-body">
      <Form onSubmit={(e) => e.preventDefault()}>
        <FormSection title="Tier" titleElement="h3">
          <FormGroup role="radiogroup" fieldId="dir-tier" isStack>
            <Radio id="dir-tier-production" name="dir-tier" label="Production" description="Changes ask for the directory's name to be typed first."
              isChecked={tier === 'production'} onChange={() => setTier('production')} />
            <Radio id="dir-tier-lab" name="dir-tier" label="Lab" description="Changes go ahead without that extra step."
              isChecked={tier === 'lab'} onChange={() => setTier('lab')} />
          </FormGroup>
          <ActionGroup><Button variant="secondary" isDisabled={busy || tier === s.tier} onClick={() => go(`The tier is now ${tier}.`, () => api.tier(tier as 'production' | 'lab', etag))}>Save the tier</Button></ActionGroup>
        </FormSection>
        <FormSection title="Sessions" titleElement="h3">
          <p className="dc-subtle">For everyone signed in to this directory, including people signed in now. People are warned two minutes before an idle sign-out.</p>
          <FormGroup label="Sign out after this many idle minutes" fieldId="dir-idle">
            <TextInput id="dir-idle" type="number" min={5} max={240} value={idleMinutes} onChange={(_e, v) => setIdleMinutes(v)}
              validated={sessionOk(idleMinutes, 5, 240) ? 'default' : 'error'} />
            <FormHelperText><HelperText><HelperTextItem variant={sessionOk(idleMinutes, 5, 240) ? 'default' : 'error'}>5 to 240 minutes; 30 by default.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="End every session after this many hours" fieldId="dir-max">
            <TextInput id="dir-max" type="number" min={1} max={24} value={maxHours} onChange={(_e, v) => setMaxHours(v)}
              validated={sessionOk(maxHours, 1, 24) ? 'default' : 'error'} />
            <FormHelperText><HelperText><HelperTextItem variant={sessionOk(maxHours, 1, 24) ? 'default' : 'error'}>1 to 24 hours, however active the person is; 12 by default.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ActionGroup>
            <Button variant="secondary" isDisabled={busy || !sessionOk(idleMinutes, 5, 240) || !sessionOk(maxHours, 1, 24)
              || (Number(idleMinutes) === s.session.idleMinutes && Number(maxHours) === s.session.maxHours)}
              onClick={() => go('The session limits are saved.', () => api.sessionLimits({ idleMinutes: Number(idleMinutes), maxHours: Number(maxHours) }, etag))}>Save the session limits</Button>
          </ActionGroup>
        </FormSection>
        <FormSection title="Agent keys" titleElement="h3">
          <p className="dc-subtle">
            People make agent keys under their name &gt; Agent keys, so an AI agent can use this console&apos;s MCP server as them, with their own rights.
            Keys need the service account. Turning them off stops every key here at once.
          </p>
          <FormGroup fieldId="dir-agent-on">
            <Checkbox id="dir-agent-on" label="Allow agent keys" isChecked={agentOn} onChange={(_e, v) => setAgentOn(v)} isDisabled={!s.serviceAccount && !agentOn} />
          </FormGroup>
          <FormGroup label="Longest life of a key, in days" fieldId="dir-agent-days">
            <TextInput id="dir-agent-days" type="number" min={1} max={90} value={agentDays} onChange={(_e, v) => setAgentDays(v)}
              validated={sessionOk(agentDays, 1, 90) ? 'default' : 'error'} />
            <FormHelperText><HelperText><HelperTextItem variant={sessionOk(agentDays, 1, 90) ? 'default' : 'error'}>1 to 90 days; 90 by default. Keys made with single sign-on live at most 14 days.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup fieldId="dir-agent-approve">
            <Checkbox id="dir-agent-approve" label="Changes an agent asks for wait for the person's approval in the console" isChecked={agentApprove}
              onChange={(_e, v) => setAgentApprove(v)}
              description="On by default. Off, an agent's changes go ahead within its key's roles; on a production directory the agent then needs its name, typed by the person." />
          </FormGroup>
          <ActionGroup>
            <Button variant="secondary" isDisabled={busy || !sessionOk(agentDays, 1, 90) || (agentOn && !s.serviceAccount)
              || (agentOn === s.agentKeys.enabled && Number(agentDays) === s.agentKeys.maxDays && agentApprove === s.agentKeys.approveChanges)}
              onClick={() => go('The agent key settings are saved.', () => api.agentKeys({ enabled: agentOn, maxDays: Number(agentDays), approveChanges: agentApprove }, etag))}>Save the agent key settings</Button>
          </ActionGroup>
        </FormSection>
        <FormSection title="Identity Applications for agents" titleElement="h3">
          <p className="dc-subtle">
            With an address here, agent keys made with a password can also use Identity Applications as their person: approval tasks, requests,
            assignments. The console signs the person in once with OSP and keeps the refresh token, which needs a client with a secret.
          </p>
          <FormGroup label="Identity Applications address" fieldId="dir-apps-url">
            <TextInput id="dir-apps-url" value={appsUrl} onChange={(_e, v) => setAppsUrl(v)} placeholder="https://apps.example.com" />
          </FormGroup>
          <FormGroup label="OSP client" fieldId="dir-apps-client">
            <TextInput id="dir-apps-client" value={appsClient} onChange={(_e, v) => setAppsClient(v)} />
            <FormHelperText><HelperText><HelperTextItem>rbpmrest is the documented REST client.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Client secret" fieldId="dir-apps-secret">
            <TextInput id="dir-apps-secret" type="password" value={appsSecret} onChange={(_e, v) => setAppsSecret(v)} autoComplete="new-password"
              placeholder={s.apps.clientSecretSet ? 'Set (leave empty to keep it)' : ''} />
            <FormHelperText><HelperText><HelperTextItem>Kept encrypted, never shown again.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ActionGroup>
            <Button variant="secondary" isDisabled={busy || !appsUrl.trim().startsWith('https://') || (!s.apps.clientSecretSet && !appsSecret)}
              onClick={() => go('The Identity Applications settings are saved.', () => api.apps({ url: appsUrl.trim(), clientId: appsClient.trim() || undefined,
                clientSecret: appsSecret || undefined }, etag))}>Save Identity Applications</Button>
            {s.apps.url && <Button variant="link" isDanger isDisabled={busy} onClick={() => sure.ask('Remove Identity Applications for agents?',
              'Agent keys stop offering the Identity Applications tools. Keys keep their sign-ins until they are revoked or expire.', 'Remove',
              () => go('Identity Applications for agents is removed.', () => api.apps(null, etag)))}>Remove it</Button>}
          </ActionGroup>
        </FormSection>
        <FormSection title="Service account" titleElement="h3">
          <p className="dc-subtle">
            {s.serviceAccount ? `The console uses ${s.serviceAccount}.` : 'None yet: people sign in with their full name (DN), and single sign-on is unavailable.'}
            {' '}The console uses it to find people by their short name at sign-in and for single sign-on. It needs to read the people it finds.
          </p>
          <FormGroup label="Full name (DN)" fieldId="dir-sa-dn">
            <TextInput id="dir-sa-dn" className="dc-mono" value={saDn} onChange={(_e, v) => setSaDn(v)} placeholder="cn=console,ou=services,o=system" />
          </FormGroup>
          <FormGroup label="Password" fieldId="dir-sa-pw">
            <TextInput id="dir-sa-pw" type="password" value={saPassword} onChange={(_e, v) => setSaPassword(v)} autoComplete="new-password" />
            <FormHelperText><HelperText><HelperTextItem>Checked by signing in as it, then kept encrypted.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ActionGroup>
            <Button variant="secondary" isDisabled={busy || !saDn.trim() || !saPassword} onClick={() => go('The service account is saved.', () => api.serviceAccount({ dn: saDn.trim(), password: saPassword }, etag))}>Save the service account</Button>
            {s.serviceAccount && <Button variant="link" isDanger isDisabled={busy} onClick={() => sure.ask('Remove the service account?',
              'Single sign-on stops, and so does finding people by a short name at sign-in, until a service account is set again.', 'Remove',
              () => go('The service account is removed.', () => api.serviceAccount(null, etag)))}>Remove it</Button>}
          </ActionGroup>
          {s.serviceAccount && <ServiceAccountRights check={api.checkServiceAccount} />}
        </FormSection>
        <FormSection title="Finding people at sign-in" titleElement="h3">
          <FormGroup label="Search bases" fieldId="dir-bases">
            <TextArea id="dir-bases" className="dc-mono" value={bases} onChange={(_e, v) => setBases(v)} resizeOrientation="vertical" placeholder="ou=users,o=acme" />
            <FormHelperText><HelperText><HelperTextItem>One DN per line, where a short name is looked for; none searches the whole directory. Needs the service account.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup role="radiogroup" label="When a name matches several people" fieldId="dir-dup" isStack>
            <Radio id="dir-dup-choose" name="dir-dup" label="Let them choose their account" isChecked={duplicates === 'choose'} onChange={() => setDuplicates('choose')} />
            <Radio id="dir-dup-error" name="dir-dup" label="Ask for the full name" isChecked={duplicates === 'error'} onChange={() => setDuplicates('error')} />
          </FormGroup>
          <ActionGroup><Button variant="secondary" isDisabled={busy || !basesChanged} onClick={() => go('The sign-in options are saved.', () => api.login({ searchBases: lines(bases), duplicates }, etag))}>Save the sign-in options</Button></ActionGroup>
        </FormSection>
      </Form>
      <Outcome error={error} notice={notice} />
      {dialog}
      {sure.dialog}
    </div>
  );
}

/**
 * Console-wide: this console's version, and the daily check for a newer release (GitHub's public release
 * list; nothing about this installation is sent). A check that fails changes nothing else.
 */
function UpdatesSection() {
  const { run, dialog } = useStepUp();
  const [state, setState] = useState<UpdateState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { updates.version().then((v) => setState(v.update ?? null), setError); }, []);
  const go = (call: () => Promise<UpdateState>) => {
    setBusy(true);
    setError(null);
    run(call).then(setState, setError).finally(() => setBusy(false));
  };
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console. Once a day the console asks GitHub for the latest Directory Console release, and tells
        administrators when a newer one is out. Nothing about this installation is sent. If the check fails, the console works as usual.</p>
      {!state && !error && <Spinner size="md" aria-label="Loading" />}
      {state && (
        <>
          <DescriptionList isHorizontal isCompact className="dc-tab-body">
            <DescriptionListGroup><DescriptionListTerm>This console</DescriptionListTerm><DescriptionListDescription>{state.current}</DescriptionListDescription></DescriptionListGroup>
            <DescriptionListGroup><DescriptionListTerm>Latest release</DescriptionListTerm><DescriptionListDescription>
              {state.latest ? <>{state.latest} {state.newer && <Label isCompact color="blue">newer</Label>}{state.newer === false && <Label isCompact color="green">up to date</Label>}</> : <span className="dc-subtle">not known yet</span>}
              {state.url && <> · <a href={state.url} target="_blank" rel="noreferrer">release notes</a></>}
              {' · '}<a href={UPGRADING_URL} target="_blank" rel="noreferrer">how to upgrade</a>
            </DescriptionListDescription></DescriptionListGroup>
            <DescriptionListGroup><DescriptionListTerm>Last checked</DescriptionListTerm><DescriptionListDescription>
              {state.checkedAt ? new Date(state.checkedAt).toLocaleString() : <span className="dc-subtle">not yet</span>}
            </DescriptionListDescription></DescriptionListGroup>
          </DescriptionList>
          {state.enabled && state.error && (
            <Alert variant="warning" isInline isPlain className="dc-tab-body" title="The last check could not reach the release server">
              {state.error}. If this console has no internet access, turn the check off. A proxy can be given to the container as HTTPS_PROXY.
            </Alert>
          )}
          <Checkbox id="update-check" className="dc-tab-body" label="Check for new versions once a day" isChecked={state.enabled} isDisabled={busy}
            onChange={(_e, v) => go(() => updates.setEnabled(v))} />
          <Button variant="secondary" className="dc-tab-body" isLoading={busy} isDisabled={busy || !state.enabled} onClick={() => go(updates.checkNow)}>Check now</Button>
        </>
      )}
      <ProblemAlert error={error} />
      {dialog}
    </div>
  );
}

/** Console-wide: earlier versions of the configuration, and backups of the whole data volume. */
function HistoryAndBackupSection() {
  const { run, dialog } = useStepUp();
  const sure = useAreYouSure();
  const [versions, setVersions] = useState<ConfigVersion[] | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [changes, setChanges] = useState<Record<number, { path: string; before: unknown; after: unknown }[]>>({});
  const [pending, setPending] = useState<RestorePending | null>(null);
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [withAudit, setWithAudit] = useState(true);
  const [file, setFile] = useState('');
  const [data, setData] = useState('');
  const [restorePass, setRestorePass] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => { records.history().then(setVersions, setError); records.pending().then(setPending, () => {}); }, []);
  const show = (v: number) => {
    setOpen(open === v ? null : v);
    if (!changes[v]) {
      records.version(v).then((x) => setChanges((c) => ({ ...c, [v]: x.changes })), setError);
    }
  };
  const act = (what: string, call: () => Promise<unknown>, after: (x: never) => void) => {
    setBusy(what);
    setError(null);
    setNotice(null);
    call().then((x) => after(x as never), setError).finally(() => setBusy(null));
  };
  const val = (v: unknown) => (v === undefined ? '—' : typeof v === 'object' && v !== null && 'set' in (v as object) ? '(a secret)' : String(v));
  const passOk = pass.length >= 12 && pass === pass2;
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console.</p>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {pending && (
        <Alert variant="warning" isInline className="dc-tab-body" title="A restore is waiting: restart the console to apply it"
          actionLinks={<Button variant="link" isInline onClick={() => act('cancel', records.cancel, () => { setPending(null); setNotice('The restore was cancelled.'); })}>Cancel it</Button>}>
          From a backup made {pending.createdAt ? new Date(pending.createdAt).toLocaleString() : '(unknown)'}{pending.consoleVersion ? ` by version ${pending.consoleVersion}` : ''}.
          At the next start the configuration, trust store, the console's certificate and the configuration key are replaced; everyone signs in again.
        </Alert>
      )}
      <Title headingLevel="h3" size="md" className="dc-tab-body">Configuration history</Title>
      <p className="dc-subtle">Every change to the console's settings is kept. Restoring a version makes it current again, as a new version; secrets come back with it.
        The trust store and the console's certificate are not part of it.</p>
      {!versions ? <Spinner size="md" aria-label="Loading" /> : (
        <Table aria-label="Configuration versions" variant="compact">
          <Thead><Tr><Th>Version</Th><Th>Saved</Th><Th>By</Th><Th>Change</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {versions.slice(0, 50).map((v) => (
              <Tr key={v.version}>
                <Td dataLabel="Version">{v.version}{v.current && <> <Label isCompact color="green">current</Label></>}</Td>
                <Td dataLabel="Saved">{v.savedAt ? new Date(v.savedAt).toLocaleString() : '—'}</Td>
                <Td dataLabel="By" className="dc-mono">{v.savedBy}</Td>
                <Td dataLabel="Change">
                  <Button variant="link" isInline onClick={() => show(v.version)}>{v.reason || 'change'}</Button>
                  {open === v.version && (changes[v.version] ? (
                    <ul className="dc-mono dc-subtle">
                      {changes[v.version].length === 0 ? <li>no setting changed</li> : changes[v.version].map((c) => <li key={c.path}>{c.path}: {val(c.before)} → {val(c.after)}</li>)}
                    </ul>
                  ) : <Spinner size="sm" aria-label="Loading" />)}
                </Td>
                <Td isActionCell>
                  {!v.current && <Button variant="link" isInline onClick={() => sure.ask(`Go back to version ${v.version}?`,
                    'The console\'s settings become what they were then, as a new version. Changes made since are undone (they stay in the history).', 'Go back',
                    () => act('restore', () => run(() => records.restoreVersion(v.version)), (x: ConfigVersion[]) => { setVersions(x); setNotice(`Version ${v.version} is current again.`); }))}>Restore</Button>}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      <Title headingLevel="h3" size="md" className="dc-tab-body">Back up</Title>
      <p className="dc-subtle">A file with the configuration and its history, the trust store, the console's key and certificate, and the configuration key, encrypted
        with your passphrase. Keep the file and the passphrase apart: with both, anyone can read the console's secrets.</p>
      <Form isWidthLimited onSubmit={(e) => { e.preventDefault(); if (passOk) act('backup', () => run(() => records.backup(pass, withAudit)), () => { setPass(''); setPass2(''); setNotice('The backup was downloaded.'); }); }}>
        <FormGroup label="Passphrase" fieldId="backup-pass">
          <TextInput id="backup-pass" type="password" autoComplete="new-password" value={pass} onChange={(_e, v) => setPass(v)} validated={pass && pass.length < 12 ? 'error' : 'default'} />
          <FormHelperText><HelperText><HelperTextItem>At least 12 characters. It is not kept anywhere: without it the backup cannot be restored.</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
        <FormGroup label="Passphrase again" fieldId="backup-pass2">
          <TextInput id="backup-pass2" type="password" autoComplete="new-password" value={pass2} onChange={(_e, v) => setPass2(v)} validated={pass2 && pass2 !== pass ? 'error' : 'default'} />
        </FormGroup>
        <Checkbox id="backup-audit" label="Include the audit log" isChecked={withAudit} onChange={(_e, v) => setWithAudit(v)}
          description="It is restored only onto a console whose audit log is empty (a new volume)." />
        <ActionGroup><Button type="submit" isLoading={busy === 'backup'} isDisabled={busy !== null || !passOk}>Download a backup</Button></ActionGroup>
      </Form>
      <Title headingLevel="h3" size="md" className="dc-tab-body">Restore</Title>
      <p className="dc-subtle">The backup is checked now and applied when the console next starts (restart the container). Until then nothing changes, and you can cancel it.</p>
      <Form isWidthLimited onSubmit={(e) => { e.preventDefault(); act('stage', () => run(() => records.stage(data, restorePass)), (x: RestorePending) => { setPending(x); setRestorePass(''); setNotice('The backup is checked and waiting: restart the console to apply it.'); }); }}>
        <FormGroup label="Backup file" fieldId="restore-file">
          <FileUpload id="restore-file" filename={file} filenamePlaceholder="Choose a .dcbackup file" browseButtonText="Choose" hideDefaultPreview value={data ? '(read)' : ''}
            onFileInputChange={(_e, f) => {
              setFile(f.name);
              const r = new FileReader();
              r.onload = () => setData(String(r.result).replace(/^data:[^,]*,/, ''));
              r.readAsDataURL(f);
            }} onClearClick={() => { setFile(''); setData(''); }} />
        </FormGroup>
        <FormGroup label="Its passphrase" fieldId="restore-pass">
          <TextInput id="restore-pass" type="password" autoComplete="off" value={restorePass} onChange={(_e, v) => setRestorePass(v)} />
        </FormGroup>
        <ActionGroup><Button type="submit" variant="secondary" isLoading={busy === 'stage'} isDisabled={busy !== null || !data || !restorePass}>Check and restore at the next start</Button></ActionGroup>
      </Form>
      {dialog}
      {sure.dialog}
    </div>
  );
}

const LETS_ENCRYPT = 'https://acme-v02.api.letsencrypt.org/directory';
const LETS_ENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

/** Console-wide: the console's own TLS certificate, and getting and renewing it from an ACME CA with DNS-01. */
function ConsoleCertificateSection() {
  const { run, dialog } = useStepUp();
  const [st, setSt] = useState<AcmeState | null>(null);
  const [draft, setDraft] = useState<AcmeState | null>(null);
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const show = (x: AcmeState) => { setSt(x); setDraft(x); setSecret(''); };
  useEffect(() => { acme.get().then(show, setError); }, []);
  if (!st || !draft) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />}</div>;
  }
  const dns = draft.dns ?? { host: '', port: 53, zone: '', keyName: '', algorithm: 'hmac-sha256' as const };
  const setDns = (patch: Partial<typeof dns>) => setDraft({ ...draft, dns: { ...dns, ...patch } });
  const act = (what: string, call: () => Promise<unknown>, after: (x: never) => void) => {
    setBusy(what);
    setError(null);
    setNotice(null);
    call().then((x) => after(x as never), setError).finally(() => setBusy(null));
  };
  const save = () => act('save', () => run(() => acme.save({
    enabled: draft.enabled, directoryUrl: draft.directoryUrl, email: draft.email || null, names: draft.names,
    dns: dns.host ? { ...dns, secret: secret || undefined } : null,
  })), (x: AcmeState) => { show(x); setNotice('Saved.'); });
  const last = st.last;
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console: the certificate it presents for HTTPS.</p>
      <DescriptionList isHorizontal isCompact className="dc-tab-body">
        <DescriptionListGroup><DescriptionListTerm>Issued by</DescriptionListTerm><DescriptionListDescription className="dc-mono">{st.current.issuer}</DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Valid until</DescriptionListTerm><DescriptionListDescription><ExpiryLabel notAfter={st.current.notAfter} /></DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Fingerprint</DescriptionListTerm><DescriptionListDescription><Fingerprint sha256={st.current.sha256} /></DescriptionListDescription></DescriptionListGroup>
        {st.current.names && <DescriptionListGroup><DescriptionListTerm>Names</DescriptionListTerm><DescriptionListDescription className="dc-mono">{st.current.names.join(', ')}</DescriptionListDescription></DescriptionListGroup>}
      </DescriptionList>
      {st.current.selfSigned && <Alert variant="info" isInline isPlain className="dc-tab-body" title="This is the certificate the console made for itself: browsers warn about it. Upload one, or get one from an ACME CA." />}
      <UploadCertificate st={st} onDone={(x) => { show(x); setNotice('The certificate is installed: reload the page to see it in use.'); }} />
      <Title headingLevel="h3" size="md" className="dc-tab-body">From an ACME certificate authority</Title>
      <p className="dc-subtle">The console proves it controls its names with DNS-01: it adds a TXT record to your DNS zone with a dynamic update (RFC 2136) signed with a
        TSIG key, removes it afterwards, and installs the certificate without a restart. Once a day it renews when 30 days or fewer remain.</p>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {last && last.at && (last.ok
        ? <Alert variant="success" isInline isPlain className="dc-tab-body" title={`Last certificate ${new Date(last.at).toLocaleString()}: from ${last.issuer}, until ${new Date(last.notAfter!).toLocaleDateString()}.`} />
        : <Alert variant="danger" isInline className="dc-tab-body" title={`The last attempt failed (${new Date(last.at).toLocaleString()})`}>{last.error}{last.steps?.length ? <><br /><span className="dc-subtle">Done before that: {last.steps.join('; ')}</span></> : null}</Alert>)}
      <Form className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); save(); }} isWidthLimited>
        <Checkbox id="acme-on" label="Get and renew the console's certificate automatically" isChecked={draft.enabled} onChange={(_e, v) => setDraft({ ...draft, enabled: v })} />
        <FormGroup label="Certificate authority" fieldId="acme-dir">
          <FormSelect id="acme-dir-choice" aria-label="Certificate authority" value={[LETS_ENCRYPT, LETS_ENCRYPT_STAGING].includes(draft.directoryUrl) ? draft.directoryUrl : 'other'}
            onChange={(_e, v) => setDraft({ ...draft, directoryUrl: v === 'other' ? '' : v })}>
            <FormSelectOption value={LETS_ENCRYPT} label="Let's Encrypt" />
            <FormSelectOption value={LETS_ENCRYPT_STAGING} label="Let's Encrypt staging (test certificates)" />
            <FormSelectOption value="other" label="Another ACME CA (its directory URL)" />
          </FormSelect>
          {![LETS_ENCRYPT, LETS_ENCRYPT_STAGING].includes(draft.directoryUrl) && (
            <TextInput id="acme-dir" className="dc-mono dc-tab-body" value={draft.directoryUrl} onChange={(_e, v) => setDraft({ ...draft, directoryUrl: v })} placeholder="https://ca.example.com/acme/directory" />
          )}
          <FormHelperText><HelperText><HelperTextItem>An internal CA's certificate must be trusted by the console (Trusted certificates, for every directory).</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
        <FormGroup label="Contact e-mail" fieldId="acme-email">
          <TextInput id="acme-email" value={draft.email ?? ''} onChange={(_e, v) => setDraft({ ...draft, email: v })} placeholder="optional: the CA writes about problems" />
        </FormGroup>
        <FormGroup label="The console's names" fieldId="acme-names">
          <TextArea id="acme-names" className="dc-mono" rows={2} resizeOrientation="vertical" value={draft.names.join('\n')}
            onChange={(_e, v) => setDraft({ ...draft, names: v.split(/[\s,]+/).filter(Boolean) })} />
          <FormHelperText><HelperText><HelperTextItem>One per line, as people type them in the browser. The first also names the certificate.</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
        <FormSection title="DNS updates" titleElement="h4">
          <FormGroup label="DNS server" fieldId="acme-dns-host">
            <TextInput id="acme-dns-host" value={dns.host} onChange={(_e, v) => setDns({ host: v })} placeholder="the zone's primary server" />
          </FormGroup>
          <FormGroup label="Port" fieldId="acme-dns-port">
            <TextInput id="acme-dns-port" type="number" value={String(dns.port)} onChange={(_e, v) => setDns({ port: Number(v) })} style={{ maxWidth: '8rem' }} />
          </FormGroup>
          <FormGroup label="Zone" fieldId="acme-dns-zone">
            <TextInput id="acme-dns-zone" value={dns.zone} onChange={(_e, v) => setDns({ zone: v })} placeholder="example.com" />
          </FormGroup>
          <FormGroup label="TSIG key name" fieldId="acme-dns-key">
            <TextInput id="acme-dns-key" className="dc-mono" value={dns.keyName} onChange={(_e, v) => setDns({ keyName: v })} />
          </FormGroup>
          <FormGroup label="Algorithm" fieldId="acme-dns-alg">
            <FormSelect id="acme-dns-alg" value={dns.algorithm} onChange={(_e, v) => setDns({ algorithm: v as 'hmac-sha256' })}>
              <FormSelectOption value="hmac-sha256" label="HMAC-SHA256" />
              <FormSelectOption value="hmac-sha512" label="HMAC-SHA512" />
            </FormSelect>
          </FormGroup>
          <FormGroup label="TSIG secret" fieldId="acme-dns-secret">
            <TextInput id="acme-dns-secret" type="password" autoComplete="new-password" value={secret} onChange={(_e, v) => setSecret(v)}
              placeholder={st.dns?.secret ? 'Set: leave empty to keep it' : 'base64, as the DNS server shows it'} />
            <FormHelperText><HelperText><HelperTextItem>Give the key only the right to change TXT records under _acme-challenge in the zone.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </FormSection>
        <ActionGroup>
          <Button type="submit" isLoading={busy === 'save'} isDisabled={busy !== null}>Save</Button>
          <Button variant="secondary" isLoading={busy === 'dns'} isDisabled={busy !== null || !st.dns} onClick={() => act('dns', acme.dnsTest,
            (r: { ok: boolean; error?: string }) => setNotice(r.ok ? 'The DNS server took a test record, answered it, and removed it.' : `DNS test failed: ${r.error}`))}>Test DNS</Button>
          <Button variant="secondary" isLoading={busy === 'issue'} isDisabled={busy !== null || !st.dns || st.names.length === 0}
            onClick={() => act('issue', () => run(acme.issue), (x: AcmeState) => { show(x); if (x.last?.ok) setNotice('A new certificate is installed: reload the page to see it in use.'); })}>Get a certificate now</Button>
        </ActionGroup>
      </Form>
      {dialog}
    </div>
  );
}

/** Upload the console's certificate: a PKCS#12 file, or PEM certificates and a private key. */
function UploadCertificate({ st, onDone }: { st: AcmeState; onDone: (x: AcmeState) => void }) {
  const { run, dialog } = useStepUp();
  const [format, setFormat] = useState<'pkcs12' | 'pem'>('pkcs12');
  const [file, setFile] = useState('');
  const [data, setData] = useState('');
  const [certificate, setCertificate] = useState('');
  const [key, setKey] = useState('');
  const [password, setPassword] = useState('');
  const [anyName, setAnyName] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const ready = format === 'pkcs12' ? !!data && !!password : !!certificate.trim() && !!key.trim();
  const upload = () => {
    setBusy(true);
    setError(null);
    const body = format === 'pkcs12' ? { pkcs12: data, password, anyName } : { certificate, key, password: password || undefined, anyName };
    run(() => acme.upload(body)).then((x) => {
      setData(''); setFile(''); setCertificate(''); setKey(''); setPassword('');
      onDone(x);
    }, setError).finally(() => setBusy(false));
  };
  return (
    <>
      <Title headingLevel="h3" size="md" className="dc-tab-body">Upload a certificate</Title>
      {st.enabled ? (
        <p className="dc-subtle">The console gets its certificate from an ACME CA, which would replace an uploaded one. To upload, turn that off below first.</p>
      ) : (
        <Form className="dc-tab-body" isWidthLimited onSubmit={(e) => { e.preventDefault(); if (ready) upload(); }}>
          <FormGroup role="radiogroup" fieldId="cert-format" label="Format" isInline>
            <Radio id="cert-p12" name="cert-format" label="PKCS#12 (.pfx, .p12)" isChecked={format === 'pkcs12'} onChange={() => setFormat('pkcs12')} />
            <Radio id="cert-pem" name="cert-format" label="PEM (certificate and key)" isChecked={format === 'pem'} onChange={() => setFormat('pem')} />
          </FormGroup>
          {format === 'pkcs12' ? (
            <FormGroup label="File" fieldId="cert-file">
              <FileUpload id="cert-file" filename={file} filenamePlaceholder="Choose a .pfx or .p12 file" browseButtonText="Choose" hideDefaultPreview value={data ? '(read)' : ''}
                onFileInputChange={(_e, f) => {
                  setFile(f.name);
                  const r = new FileReader();
                  r.onload = () => setData(String(r.result).replace(/^data:[^,]*,/, ''));
                  r.readAsDataURL(f);
                }} onClearClick={() => { setFile(''); setData(''); }} />
            </FormGroup>
          ) : (
            <>
              <FormGroup label="Certificate, with its chain" fieldId="cert-pem-text">
                <TextArea id="cert-pem-text" className="dc-mono" rows={5} resizeOrientation="vertical" value={certificate} onChange={(_e, v) => setCertificate(v)}
                  placeholder="-----BEGIN CERTIFICATE-----" />
                <FormHelperText><HelperText><HelperTextItem>The server certificate and the intermediate CAs, in any order.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              <FormGroup label="Private key" fieldId="cert-pem-key">
                <TextArea id="cert-pem-key" className="dc-mono" rows={4} resizeOrientation="vertical" value={key} onChange={(_e, v) => setKey(v)}
                  placeholder="-----BEGIN PRIVATE KEY-----" />
                <FormHelperText><HelperText><HelperTextItem>PKCS#8, RSA or EC; encrypted keys need their password below.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
            </>
          )}
          <FormGroup label={format === 'pkcs12' ? 'Password' : 'Key password (if the key is encrypted)'} fieldId="cert-password">
            <TextInput id="cert-password" type="password" autoComplete="off" value={password} onChange={(_e, v) => setPassword(v)} />
          </FormGroup>
          <Checkbox id="cert-any-name" isChecked={anyName} onChange={(_e, v) => setAnyName(v)}
            label={`The certificate need not name ${st.publicHost ?? 'the console\'s address'}`}
            description="Only when a reverse proxy in front of the console connects to it by another name; browsers would refuse it otherwise." />
          <ProblemAlert error={error} />
          <ActionGroup><Button type="submit" isLoading={busy} isDisabled={busy || !ready}>Install</Button></ActionGroup>
        </Form>
      )}
      {dialog}
    </>
  );
}

const FACILITIES = ['authpriv', 'auth', 'audit', 'user', 'daemon', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];

/** Console-wide: every audit-log entry sent on to a syslog server, as CEF. */
function SyslogSection() {
  const { run, dialog } = useStepUp();
  const [st, setSt] = useState<SyslogState | null>(null);
  const [draft, setDraft] = useState<SyslogState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const show = (x: SyslogState) => { setSt(x); setDraft(x); };
  useEffect(() => { syslog.get().then(show, setError); }, []);
  if (!st || !draft) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />}</div>;
  }
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    run(() => syslog.save({ enabled: draft.enabled, host: draft.host?.trim() || null, port: draft.port, transport: draft.transport, facility: draft.facility }))
      .then((x) => { show(x); setNotice('Saved.'); }, setError).finally(() => setBusy(false));
  };
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console. Every entry written to the console's audit log (sign-ins, changes, refusals, exports, certificate expiry
        notices) is also sent to a syslog server as it happens: an RFC 5424 message carrying CEF, the format eDirectory's own audit events use, so a SIEM
        reads both alike. Delivery is best effort; the console's own audit log keeps every entry.</p>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {st.enabled && (
        <DescriptionList isHorizontal isCompact className="dc-tab-body">
          <DescriptionListGroup><DescriptionListTerm>Sent</DescriptionListTerm><DescriptionListDescription>{st.sent ?? 0}{st.lastSent && <span className="dc-subtle">, last {new Date(st.lastSent).toLocaleString()}</span>}</DescriptionListDescription></DescriptionListGroup>
          <DescriptionListGroup><DescriptionListTerm>Waiting</DescriptionListTerm><DescriptionListDescription>{st.waiting ?? 0}</DescriptionListDescription></DescriptionListGroup>
          <DescriptionListGroup><DescriptionListTerm>Dropped</DescriptionListTerm><DescriptionListDescription>{st.dropped ? <Label isCompact color="orange">{st.dropped}</Label> : 0}</DescriptionListDescription></DescriptionListGroup>
        </DescriptionList>
      )}
      {st.enabled && st.lastError && <Alert variant="warning" isInline isPlain title={`The syslog server could not be reached: ${st.lastError}`} className="dc-tab-body" />}
      <Form onSubmit={save} isWidthLimited className="dc-tab-body">
        <Checkbox id="syslog-on" label="Send audit entries to syslog" isChecked={draft.enabled} onChange={(_e, v) => setDraft({ ...draft, enabled: v })} />
        <FormGroup label="Syslog server" fieldId="syslog-host">
          <TextInput id="syslog-host" value={draft.host ?? ''} onChange={(_e, v) => setDraft({ ...draft, host: v })} placeholder="siem.example.com" />
        </FormGroup>
        <FormGroup label="Transport" fieldId="syslog-transport">
          <FormSelect id="syslog-transport" value={draft.transport} onChange={(_e, v) => setDraft({ ...draft, transport: v as SyslogState['transport'], port: v === 'tls' ? 6514 : 514 })}>
            <FormSelectOption value="tls" label="TLS (RFC 5425, port 6514)" />
            <FormSelectOption value="tcp" label="TCP (port 514), not encrypted" />
            <FormSelectOption value="udp" label="UDP (port 514), not encrypted, may lose messages" />
          </FormSelect>
          <FormHelperText><HelperText><HelperTextItem>With TLS, the server's certificate must be from a public CA or a CA the console trusts (Trusted certificates), and name the host.</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
        <FormGroup label="Port" fieldId="syslog-port">
          <TextInput id="syslog-port" type="number" value={String(draft.port)} onChange={(_e, v) => setDraft({ ...draft, port: Number(v) })} style={{ maxWidth: '8rem' }} />
        </FormGroup>
        <FormGroup label="Facility" fieldId="syslog-facility" labelHelp={<FieldHelp label="Facility">{explain('syslogFacility')}</FieldHelp>}>
          <FormSelect id="syslog-facility" value={draft.facility} onChange={(_e, v) => setDraft({ ...draft, facility: v })}>
            {FACILITIES.map((f) => <FormSelectOption key={f} value={f} label={f} />)}
          </FormSelect>
        </FormGroup>
        <ActionGroup>
          <Button type="submit" isLoading={busy} isDisabled={busy}>Save</Button>
          <Button variant="secondary" isDisabled={busy || !st.host} onClick={() => {
            setBusy(true);
            setNotice(null);
            setError(null);
            syslog.test().then((r) => setNotice(r.ok ? `A test message went to ${st.host}.` : `Not sent: ${r.error}`), setError).finally(() => setBusy(false));
          }}>Send a test</Button>
        </ActionGroup>
      </Form>
      {dialog}
    </div>
  );
}

const KIND_TEXT: Record<string, string> = { console: 'Console', trusted: 'Trusted by the console', ca: 'Directory CA', server: 'Server certificate', 'trusted-root': 'Trusted root' };

/** Console-wide: the daily certificate expiry check and where its notices go. */
function ExpirySection() {
  const { run, dialog } = useStepUp();
  const [st, setSt] = useState<ExpiryState | null>(null);
  const [draft, setDraft] = useState<ExpirySettings | null>(null);
  const [mailPw, setMailPw] = useState('');
  const [secrets, setSecrets] = useState<Record<number, string>>({});
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const show = (x: ExpiryState) => { setSt(x); setDraft(x.settings); setMailPw(''); setSecrets({}); };
  useEffect(() => { expiry.get().then(show, setError); }, []);
  const act = (call: () => Promise<unknown>, after: (x: never) => void) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    call().then((x) => after(x as never), setError).finally(() => setBusy(false));
  };
  if (!st || !draft) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />}</div>;
  }
  const mail = draft.email;
  const setMail = (patch: Partial<NonNullable<ExpirySettings['email']>>) => setDraft({ ...draft, email: { ...(mail ?? { host: '', port: 587, security: 'starttls', from: '', to: [] }), ...patch } });
  const save = () => act(() => run(() => expiry.save({
    ...draft,
    email: mail && mail.host ? { ...mail, password: mailPw || undefined } : null,
    webhooks: draft.webhooks.filter((w) => w.url.trim()).map((w, i) => ({ url: w.url.trim(), secret: secrets[i] || undefined, clearSecret: w.clearSecret })),
  })), (x: ExpiryState) => { show(x); setNotice('Saved.'); });
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console. Once a day it looks at its own TLS certificate, the certificates it trusts, and each directory's CA, server
        certificates and trusted roots (for directories with a service account). Anything expired or expiring soon is shown here, written to the audit log,
        and sent to the recipients below: when it enters the warning window, again a week before, and when it has expired.</p>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      <Card className="dc-tab-body">
        <CardBody>
          <Flex alignItems={{ default: 'alignItemsCenter' }}>
            <FlexItem grow={{ default: 'grow' }}><Title headingLevel="h3" size="md">Last check {st.checkedAt ? <span className="dc-subtle">{new Date(st.checkedAt).toLocaleString()}</span> : <span className="dc-subtle">not yet</span>}</Title></FlexItem>
            <FlexItem><Button variant="secondary" size="sm" isLoading={busy} isDisabled={busy} onClick={() => act(expiry.checkNow, (x: ExpiryState) => setSt({ ...x, settings: st.settings }))}>Check now</Button></FlexItem>
          </Flex>
          {(st.errors ?? []).map((e) => <Alert key={e} variant="warning" isInline isPlain title={`Not checked: ${e}`} />)}
          {st.findings && (st.findings.length === 0 ? <p className="dc-tab-body">Nothing expired or expiring within {st.settings.warnDays} days.</p> : (
            <Table aria-label="Certificates to attend to" variant="compact">
              <Thead><Tr><Th>Certificate</Th><Th>Kind</Th><Th>Where</Th><Th>Expires</Th></Tr></Thead>
              <Tbody>
                {st.findings.map((f) => (
                  <Tr key={`${f.where}-${f.name}-${f.notAfter}`}>
                    <Td dataLabel="Certificate">{f.name}</Td>
                    <Td dataLabel="Kind">{KIND_TEXT[f.kind] ?? f.kind}</Td>
                    <Td dataLabel="Where">{f.where}</Td>
                    <Td dataLabel="Expires"><ExpiryLabel notAfter={f.notAfter} /></Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ))}
        </CardBody>
      </Card>
      <Form className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); save(); }} isWidthLimited>
        <Checkbox id="expiry-on" label="Check once a day" isChecked={draft.enabled} onChange={(_e, v) => setDraft({ ...draft, enabled: v })} />
        <FormGroup label="Warn this many days ahead" fieldId="expiry-days" labelHelp={<FieldHelp label="Warn this many days ahead">{explain('warnDays')}</FieldHelp>}>
          <TextInput id="expiry-days" type="number" min={1} max={365} value={String(draft.warnDays)} onChange={(_e, v) => setDraft({ ...draft, warnDays: Number(v) })} style={{ maxWidth: '8rem' }} />
          <FormHelperText><HelperText><HelperTextItem>1 to 365. This sets when notices go out, and when the banner at the top of every page starts warning; Security &gt; Certificates and the default-certificate check always warn 30 days ahead.</HelperTextItem></HelperText></FormHelperText>
        </FormGroup>
        <FormSection title="E-mail" titleElement="h3">
          <FormGroup label="Mail server" fieldId="expiry-host">
            <TextInput id="expiry-host" value={mail?.host ?? ''} onChange={(_e, v) => setMail({ host: v })} placeholder="smtp.example.com (empty: no e-mail)" />
          </FormGroup>
          {mail?.host && (
            <>
              <FormGroup label="Security" fieldId="expiry-security">
                <FormSelect id="expiry-security" value={mail.security} onChange={(_e, v) => setMail({ security: v as 'starttls', port: v === 'tls' ? 465 : 587 })}>
                  <FormSelectOption value="starttls" label="STARTTLS (port 587)" />
                  <FormSelectOption value="tls" label="TLS (port 465)" />
                  <FormSelectOption value="none" label="None (a relay on a trusted network; no password)" />
                </FormSelect>
              </FormGroup>
              <FormGroup label="Port" fieldId="expiry-port">
                <TextInput id="expiry-port" type="number" value={String(mail.port)} onChange={(_e, v) => setMail({ port: Number(v) })} style={{ maxWidth: '8rem' }} />
              </FormGroup>
              {mail.security !== 'none' && (
                <>
                  <FormGroup label="User name" fieldId="expiry-user">
                    <TextInput id="expiry-user" value={mail.user ?? ''} onChange={(_e, v) => setMail({ user: v })} autoComplete="off" placeholder="empty: no sign-in" />
                  </FormGroup>
                  {mail.user && (
                    <FormGroup label="Password" fieldId="expiry-pw">
                      <TextInput id="expiry-pw" type="password" autoComplete="new-password" value={mailPw} onChange={(_e, v) => setMailPw(v)}
                        placeholder={mail.password ? 'Set: leave empty to keep it' : ''} />
                    </FormGroup>
                  )}
                </>
              )}
              <FormGroup label="From" fieldId="expiry-from">
                <TextInput id="expiry-from" value={mail.from} onChange={(_e, v) => setMail({ from: v })} placeholder="directory-console@example.com" />
              </FormGroup>
              <FormGroup label="To" fieldId="expiry-to">
                <TextArea id="expiry-to" value={mail.to.join('\n')} onChange={(_e, v) => setMail({ to: v.split(/[\s,;]+/).filter(Boolean) })} rows={2} resizeOrientation="vertical" />
                <FormHelperText><HelperText><HelperTextItem>One address per line. The mail server's certificate must be from a public CA.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
            </>
          )}
        </FormSection>
        <FormSection title="Webhooks" titleElement="h3">
          <p className="dc-subtle">Each notice is POSTed as JSON (event, subject, text, certificates). With a secret, an X-Console-Signature header carries
            sha256= and the HMAC-SHA256 of the body.</p>
          {draft.webhooks.map((w, i) => (
            <Flex key={i} alignItems={{ default: 'alignItemsFlexEnd' }}>
              <FlexItem grow={{ default: 'grow' }}>
                <FormGroup label="URL" fieldId={`hook-${i}`}>
                  <TextInput id={`hook-${i}`} value={w.url} onChange={(_e, v) => setDraft({ ...draft, webhooks: draft.webhooks.map((x, j) => (j === i ? { ...x, url: v } : x)) })} placeholder="https://hooks.example.com/…" />
                </FormGroup>
              </FlexItem>
              <FlexItem>
                <FormGroup label="Secret" fieldId={`hook-secret-${i}`}>
                  <TextInput id={`hook-secret-${i}`} type="password" autoComplete="new-password" value={secrets[i] ?? ''} onChange={(_e, v) => setSecrets({ ...secrets, [i]: v })}
                    placeholder={w.secret ? 'Set: leave empty to keep it' : 'optional'} />
                </FormGroup>
              </FlexItem>
              <FlexItem><Button variant="link" isDanger onClick={() => setDraft({ ...draft, webhooks: draft.webhooks.filter((_x, j) => j !== i) })}>Remove</Button></FlexItem>
            </Flex>
          ))}
          {draft.webhooks.length < 5 && <div><Button variant="link" isInline onClick={() => setDraft({ ...draft, webhooks: [...draft.webhooks, { url: '' }] })}>Add a webhook</Button></div>}
        </FormSection>
        <ActionGroup>
          <Button type="submit" isLoading={busy} isDisabled={busy}>Save</Button>
          <Button variant="secondary" isDisabled={busy} onClick={() => act(expiry.test, (x: { results: { destination: string; ok: boolean; error?: string }[] }) =>
            setNotice(x.results.length === 0 ? 'No e-mail or webhooks saved yet.' : x.results.map((r) => `${r.destination}: ${r.ok ? 'sent' : `not sent (${r.error})`}`).join(' · ')))}>Send a test</Button>
        </ActionGroup>
      </Form>
      {dialog}
    </div>
  );
}

/**
 * Console-wide: whether people may sign in to directories they enter themselves. They
 * work there with their own eDirectory rights only, and the certificates they accept are their own.
 */
function OtherDirectoriesSection() {
  const { run, dialog } = useStepUp();
  const [on, setOn] = useState<boolean | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => { consoleSettings.get().then((v) => setOn(v.otherDirectories), setError); }, []);
  const change = (v: boolean) => {
    setError(null);
    setNotice(null);
    run(() => consoleSettings.put({ otherDirectories: v })).then((r) => {
      setOn(r.otherDirectories);
      setNotice(r.otherDirectories ? 'People may now sign in to directories they enter.' : 'Only the configured directories can be signed in to.');
    }, setError);
  };
  return (
    <div className="dc-tab-body">
      <p>This applies to the whole console, not only this directory. When it is on, the sign-in page offers "Another directory…": a person types an eDirectory server's address, their full name (DN) and password.</p>
      <List>
        <ListItem>They work there with their own eDirectory rights only: no role mappings, task presets, Identity Manager or console settings.</ListItem>
        <ListItem>A certificate the console does not trust is shown to them; once they confirm its fingerprint and their password is accepted, it is trusted for their own sign-ins to that address only. Their certificates are listed on the Certificates page, where you can remove them.</ListItem>
        <ListItem>The configured directories' addresses are refused there: only administrators trust their certificates.</ListItem>
      </List>
      {on === null && !error && <Spinner size="md" aria-label="Loading" />}
      {on !== null && (
        <Checkbox id="other-directories" label="Let people sign in to directories they enter themselves" isChecked={on} onChange={(_e, v) => change(v)} />
      )}
      <Outcome error={error} notice={notice} />
      {dialog}
    </div>
  );
}

/**
 * Console-wide: the reverse proxies whose X-Forwarded-For header is believed. Audit entries and
 * sign-in throttling then see the person's address rather than the proxy's. A request from any other
 * address keeps its own, so nobody can choose the address they are recorded under.
 */
function ProxySection() {
  const { run, dialog } = useStepUp();
  const [saved, setSaved] = useState<string[] | null>(null);
  const [text, setText] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    consoleSettings.get().then((v) => { setSaved(v.trustedProxies); setText(v.trustedProxies.join('\n')); }, setError);
  }, []);
  const entries = text.split(/[\s,]+/).filter(Boolean);
  const save = () => {
    setError(null);
    setNotice(null);
    setBusy(true);
    run(() => consoleSettings.put({ trustedProxies: entries })).then((r) => {
      setSaved(r.trustedProxies);
      setText(r.trustedProxies.join('\n'));
      setNotice(r.trustedProxies.length ? 'X-Forwarded-For is now believed from these addresses.' : 'Every request is recorded under its own address.');
    }, setError).finally(() => setBusy(false));
  };
  return (
    <div className="dc-tab-body">
      <p>When the console is reached through a reverse proxy or load balancer, list its addresses here. Requests from them are recorded under the client address the proxy reports in X-Forwarded-For; requests from anywhere else keep their own address, whatever header they send.</p>
      {saved === null && !error && <Spinner size="md" aria-label="Loading" />}
      {saved !== null && (
        <Form onSubmit={(e) => { e.preventDefault(); save(); }}>
          <FormGroup label="Trusted proxies" fieldId="proxies">
            <TextArea id="proxies" className="dc-mono" rows={4} value={text} onChange={(_e, v) => setText(v)} placeholder={'10.0.0.5\n10.20.0.0/16'} />
            <FormHelperText><HelperText><HelperTextItem>IP addresses or CIDR ranges, one per line. Empty: no proxy is trusted.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ActionGroup>
            <Button type="submit" isLoading={busy} isDisabled={busy || entries.join('\n') === saved.join('\n')}>Save</Button>
          </ActionGroup>
        </Form>
      )}
      <Outcome error={error} notice={notice} />
      {dialog}
    </div>
  );
}

type Saver<T> = (v: T) => Promise<{ data: DirectorySettings; etag?: string }>;

/** Save through the step-up check, with the outcome shown. */
function useSave<T>(save: Saver<T>, onSaved: (r: { data: DirectorySettings; etag?: string }) => void) {
  const { run, dialog } = useStepUp();
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const go = async (v: T, done: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      onSaved(await run(() => save(v)));
      setNotice(done);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return { go, busy, error, notice, dialog };
}

function Outcome({ error, notice }: { error: unknown; notice: string | null }) {
  const level = useHeading();
  return (
    <>
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
    </>
  );
}

function RolesSection({ s, save, onSaved }: { s: DirectorySettings; etag?: string; save: Saver<RoleMappingJson[]>; onSaved: (r: { data: DirectorySettings; etag?: string }) => void }) {
  const [draft, setDraft] = useState(s.roles);
  useEffect(() => setDraft(s.roles), [s.roles]);
  const { go, busy, error, notice, dialog } = useSave(save, onSaved);
  const dirty = JSON.stringify(draft) !== JSON.stringify(s.roles);
  return (
    <div className="dc-tab-body">
      <p>Members of these eDirectory groups get these grants when they sign in with their name and password. <Hint text={explain('breakGlass')}><span tabIndex={0} className="dc-term">Break-glass accounts</span></Hint> ({s.breakGlass.join(', ') || 'none'}) are always admins.</p>
      <RoleMappings value={draft} onChange={setDraft} presets={s.presets} />
      <Outcome error={error} notice={notice} />
      <ActionGroup>
        <Button variant="primary" isDisabled={!dirty || busy} isLoading={busy} onClick={() => go(draft, 'Role mappings saved.')}>Save</Button>
        <Button variant="link" isDisabled={!dirty} onClick={() => setDraft(s.roles)}>Discard changes</Button>
      </ActionGroup>
      {dialog}
    </div>
  );
}

function PresetsSection({ s, save, exportAll, onSaved }: {
  s: DirectorySettings; etag?: string; save: Saver<Record<string, unknown>>; exportAll: () => Promise<Record<string, unknown>>;
  onSaved: (r: { data: DirectorySettings; etag?: string }) => void;
}) {
  const [editing, setEditing] = useState<null | { preset: Preset | null }>(null);
  const { go, busy, error, notice, dialog } = useSave(save, onSaved);
  const file = useRef<HTMLInputElement>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const all = (list: Preset[]) => Object.fromEntries(list.map((p) => [p.id, presetJson(p)]));
  const grantedTo = (id: string) => [...s.roles, ...(s.oidc?.roles ?? [])].filter((r) => (r.presets ?? []).includes(id)).map((r) => r.group);

  const download = async () => {
    const blob = new Blob([JSON.stringify(await exportAll(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `task-presets-${s.id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const upload = async (f: File) => {
    setImportError(null);
    try {
      const parsed: unknown = JSON.parse(await f.text());
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('not an object of id → preset');
      }
      await go({ ...all(s.presets), ...(parsed as Record<string, unknown>) }, `Imported ${Object.keys(parsed).length} preset(s).`);
    } catch (x) {
      setImportError(`That file is not a task preset export: ${x instanceof Error ? x.message : String(x)}`);
    }
  };

  return (
    <div className="dc-tab-body">
      <p>A task preset is a restricted action, such as resetting a password or editing a phone number, that a role mapping grants, possibly only under some containers.</p>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem><Button variant="secondary" icon={<PlusIcon />} onClick={() => setEditing({ preset: null })}>New preset</Button></ToolbarItem>
          <ToolbarItem><Button variant="link" icon={<DownloadIcon />} onClick={download} isDisabled={s.presets.length === 0}>Export</Button></ToolbarItem>
          <ToolbarItem>
            <Button variant="link" icon={<UploadIcon />} onClick={() => file.current?.click()}>Import</Button>
            <input ref={file} type="file" accept="application/json,.json" hidden aria-label="Import task presets"
              onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) { upload(f); } }} />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      {importError && <Alert variant="danger" isInline isPlain title={importError} />}
      {s.presets.length === 0 ? (
        <EmptyState titleText="No task presets" headingLevel="h2"><EmptyStateBody>Create one, or import an export from another console.</EmptyStateBody></EmptyState>
      ) : (
        <Table aria-label="Task presets" variant="compact">
          <Thead><Tr><Th>Preset</Th><Th>Class</Th><Th>Actions</Th><Th>Granted to</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {s.presets.map((p) => {
              const to = grantedTo(p.id);
              return (
                <Tr key={p.id}>
                  <Td dataLabel="Preset">{p.name}<div className="dc-subtle dc-mono">{p.id}</div></Td>
                  <Td dataLabel="Class" className="dc-mono">{p.objectClass}</Td>
                  <Td dataLabel="Actions"><LabelGroup>{p.actions.map((a) => <Label key={a} isCompact>{a === 'attributes' ? `${p.attributes.length} field(s)` : a}</Label>)}</LabelGroup></Td>
                  <Td dataLabel="Granted to">{to.length ? to.map((g) => <div key={g}>{g}</div>) : <span className="dc-subtle">Nobody yet</span>}</Td>
                  <Td isActionCell modifier="nowrap">
                    <Button variant="link" isInline onClick={() => setEditing({ preset: p })}>Edit</Button>{' '}
                    <Button variant="link" isInline isDanger isDisabled={to.length > 0 || busy}
                      onClick={() => go(all(s.presets.filter((x) => x.id !== p.id)), `${p.name} removed.`)}>Remove</Button>
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      )}
      <Outcome error={error} notice={notice} />
      {editing && (
        <PresetEditor initial={editing.preset} taken={s.presets.map((p) => p.id)} onClose={() => setEditing(null)}
          onSave={(p) => {
            setEditing(null);
            const list = editing.preset ? s.presets.map((x) => (x.id === p.id ? p : x)) : [...s.presets, p];
            go(all(list), `${p.name} saved.`);
          }} />
      )}
      {dialog}
    </div>
  );
}

function SsoSection({ s, save, test, check, onSaved }: {
  s: DirectorySettings; save: Saver<OidcSettings | null>; test: (v: string) => Promise<{ matches: string[]; neverProxy: boolean }>;
  check: () => Promise<ServiceAccountCheck>;
  onSaved: (r: { data: DirectorySettings; etag?: string }) => void;
}) {
  const blank: OidcSettings = { issuer: '', clientId: '', label: 'single sign-on', claim: 'preferred_username', attribute: 'uid', groupsClaim: 'groups', roles: [] };
  const [o, setO] = useState<OidcSettings>(s.oidc ?? blank);
  const [secret, setSecret] = useState('');
  const [publicClient, setPublicClient] = useState(!!s.oidc && !s.oidc.clientSecretSet);
  const [bases, setBases] = useState((s.oidc?.searchBases ?? []).join('\n'));
  const [never, setNever] = useState((s.oidc?.neverProxy ?? []).join('\n'));
  const [probe, setProbe] = useState('');
  const [probeResult, setProbeResult] = useState<string | null>(null);
  const { go, busy, error, notice, dialog } = useSave(save, onSaved);
  useEffect(() => {
    setO(s.oidc ?? blank);
    setBases((s.oidc?.searchBases ?? []).join('\n'));
    setNever((s.oidc?.neverProxy ?? []).join('\n'));
    setSecret('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.oidc]);
  const field = (k: keyof OidcSettings) => (_e: unknown, v: string) => setO({ ...o, [k]: v });

  if (!s.serviceAccount) {
    return <Alert className="dc-tab-body" variant="warning" isInline title="Single sign-on needs the console's service account">
      The console finds and acts for people who sign in through single sign-on with this directory's service account. Configure one first.
    </Alert>;
  }
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const body: OidcSettings = {
      ...o, searchBases: lines(bases), neverProxy: lines(never),
      ...(publicClient ? { clientSecret: false as const } : secret ? { clientSecret: secret } : {}),
    };
    delete body.clientSecretSet;
    go(body, 'Single sign-on saved.');
  };
  return (
    <div className="dc-tab-body">
      <ServiceAccountRights check={check} />
      <Form onSubmit={submit} isWidthLimited>
        <FormSection title="Identity provider" titleElement="h2">
          <FormGroup label="Redirect URI to register at the provider" fieldId="sso-redirect">
            <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" id="sso-redirect" className="dc-mono">{s.redirectUri}</ClipboardCopy>
          </FormGroup>
          <FormGroup label="Issuer" fieldId="sso-issuer" isRequired>
            <TextInput id="sso-issuer" type="url" value={o.issuer} onChange={field('issuer')} placeholder="https://idp.example.com/realms/acme" isRequired />
            <FormHelperText><HelperText><HelperTextItem>Its certificate must be from a public CA, or from a CA the console trusts (Trusted certificates).</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Client id" fieldId="sso-client" isRequired>
            <TextInput id="sso-client" value={o.clientId} onChange={field('clientId')} isRequired />
          </FormGroup>
          <FormGroup label="Client secret" fieldId="sso-secret">
            <TextInput id="sso-secret" type="password" autoComplete="off" value={secret} onChange={(_e, v) => setSecret(v)} isDisabled={publicClient}
              placeholder={s.oidc?.clientSecretSet ? 'Set — leave empty to keep it' : ''} />
            <Checkbox id="sso-public" label="Public client (PKCE only, no secret)" description={explain('publicClient')} isChecked={publicClient} onChange={(_e, v) => setPublicClient(v)} />
          </FormGroup>
          <FormGroup label="Button label" fieldId="sso-label">
            <TextInput id="sso-label" value={o.label ?? ''} onChange={field('label')} />
            <FormHelperText><HelperText><HelperTextItem>Shown as “Sign in with …” on the sign-in page.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Scopes" fieldId="sso-scopes">
            <TextInput id="sso-scopes" value={o.scopes ?? ''} onChange={field('scopes')} placeholder="openid profile email" />
          </FormGroup>
          <FormGroup label="Groups claim" fieldId="sso-groups">
            <TextInput id="sso-groups" value={o.groupsClaim ?? ''} onChange={field('groupsClaim')} placeholder="groups" className="dc-mono" />
            <FormHelperText><HelperText><HelperTextItem>A dotted path such as realm_access.roles also works.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </FormSection>
        <FormSection title="Finding the person in eDirectory" titleElement="h2">
          <FormGroup label="Claim" fieldId="sso-claim" isRequired labelHelp={<FieldHelp label="Claim">{explain('claim')}</FieldHelp>}>
            <TextInput id="sso-claim" value={o.claim ?? ''} onChange={field('claim')} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Matches the attribute" fieldId="sso-attribute" isRequired labelHelp={<FieldHelp label="Matches the attribute">{explain('claimAttribute')}</FieldHelp>}>
            <TextInput id="sso-attribute" value={o.attribute ?? ''} onChange={field('attribute')} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Under these containers" fieldId="sso-bases">
            <TextArea id="sso-bases" value={bases} onChange={(_e, v) => setBases(v)} className="dc-mono" resizeOrientation="vertical" />
            <FormHelperText><HelperText><HelperTextItem>
              One DN per line; empty uses the sign-in search bases. The service account needs Supervisor over these people (and nobody else).
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Never act as" fieldId="sso-never" labelHelp={<FieldHelp label="Never act as">{explain('neverActAs')}</FieldHelp>}>
            <TextArea id="sso-never" value={never} onChange={(_e, v) => setNever(v)} className="dc-mono" resizeOrientation="vertical" />
            <FormHelperText><HelperText><HelperTextItem>
              One DN per line, besides the service account and the break-glass accounts, which never sign in this way.
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </FormSection>
        <FormSection title="Provider groups" titleElement="h2">
          <HeadingLevel.Provider value="h3">
            <RoleMappings idp value={o.roles ?? []} onChange={(roles) => setO({ ...o, roles })} presets={s.presets} />
          </HeadingLevel.Provider>
        </FormSection>
        <Outcome error={error} notice={notice} />
        <ActionGroup>
          <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy || !o.issuer || !o.clientId}>Save</Button>
          {s.oidc && <Button variant="danger" isDisabled={busy} onClick={() => go(null, 'Single sign-on turned off.')}>Turn single sign-on off</Button>}
        </ActionGroup>
      </Form>
      {s.oidc && (
        <Form className="dc-tab-body" isWidthLimited onSubmit={async (e) => {
          e.preventDefault();
          setProbeResult(null);
          try {
            const r = await test(probe);
            setProbeResult(r.matches.length === 0 ? 'No active account matches.' : r.matches.length > 1 ? `Several accounts match (${r.matches.join('; ')}): sign-in would be refused.`
              : r.neverProxy ? `${r.matches[0]} — but it is on the never-act-as list, so sign-in would be refused.` : `${r.matches[0]}`);
          } catch (x) {
            setProbeResult(x instanceof Error ? x.message : 'The test failed.');
          }
        }}>
          <FormSection title="Try the mapping" titleElement="h2">
            <FormGroup label={`A value of ${s.oidc.claim}`} fieldId="sso-probe">
              <TextInput id="sso-probe" value={probe} onChange={(_e, v) => setProbe(v)} />
            </FormGroup>
            {probeResult && <p className="dc-mono" role="status">{probeResult}</p>}
            <ActionGroup><Button type="submit" variant="secondary" isDisabled={!probe}>Find the account</Button></ActionGroup>
          </FormSection>
        </Form>
      )}
      {dialog}
    </div>
  );
}

/**
 * Whether people may still sign in with a password once single sign-on is set up. Off, only the
 * break-glass accounts and the accounts listed here may; they keep the roles their groups give them.
 */
function PasswordSignInSection({ s, save, onSaved }: {
  s: DirectorySettings; save: Saver<{ direct: boolean; allowed: string[] }>;
  onSaved: (r: { data: DirectorySettings; etag?: string }) => void;
}) {
  const { me } = useSession();
  const [direct, setDirect] = useState(s.directLogin);
  const [allowed, setAllowed] = useState(s.login.allowed.join('\n'));
  const { go, busy, error, notice, dialog } = useSave(save, onSaved);
  useEffect(() => {
    setDirect(s.directLogin);
    setAllowed(s.login.allowed.join('\n'));
  }, [s.directLogin, s.login.allowed]);
  const same = (a: string, b: string) => a.replace(/\s+/g, '').toLowerCase() === b.replace(/\s+/g, '').toLowerCase();
  const list = lines(allowed);
  const changed = direct !== s.directLogin || list.join('|') !== s.login.allowed.join('|');
  const meListed = [...s.breakGlass, ...list].some((d) => same(d, me.dn));
  return (
    <div className="dc-tab-body">
      <Form onSubmit={(e) => { e.preventDefault(); go({ direct, allowed: list }, direct ? 'Everyone may sign in with a password again.' : 'Only single sign-on and the listed accounts can sign in now.'); }} isWidthLimited>
        <FormSection title="Password sign-in" titleElement="h2">
          <FormGroup role="radiogroup" fieldId="pw-direct" isStack>
            <Radio id="pw-direct-on" name="pw-direct" label="Anyone may sign in with a password or with single sign-on" isChecked={direct} onChange={() => setDirect(true)} />
            <Radio id="pw-direct-off" name="pw-direct" label="Single sign-on only, except the accounts below"
              description="The sign-in page offers single sign-on first; the password form is for the listed accounts." isChecked={!direct} onChange={() => setDirect(false)} />
          </FormGroup>
          <p className="dc-subtle">
            Always allowed: <Hint text={explain('breakGlass')}><span tabIndex={0} className="dc-term">break-glass accounts</span></Hint>{' '}
            {s.breakGlass.length ? <span className="dc-mono">{s.breakGlass.join(', ')}</span> : '(none)'}.
          </p>
          <FormGroup label="Also allowed to sign in with a password" fieldId="pw-allowed" labelHelp={<FieldHelp label="Also allowed">{explain('passwordAllowed')}</FieldHelp>}>
            <TextArea id="pw-allowed" className="dc-mono" value={allowed} onChange={(_e, v) => setAllowed(v)} resizeOrientation="vertical"
              placeholder="cn=jsmith,ou=admins,o=acme" isDisabled={direct} />
            <FormHelperText><HelperText><HelperTextItem>One full name (DN) per line. They keep the roles their groups give them.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {!direct && me.via !== 'oidc' && !meListed && (
            <Alert variant="warning" isInline isPlain title="You signed in with a password and are not on this list: next time, sign in with single sign-on." />
          )}
        </FormSection>
        <Outcome error={error} notice={notice} />
        <ActionGroup><Button type="submit" variant="secondary" isLoading={busy} isDisabled={busy || !changed}>Save password sign-in</Button></ActionGroup>
      </Form>
      {dialog}
    </div>
  );
}

const FINDING: Record<ServiceAccountCheck['checks'][number]['result'], { color: 'green' | 'red' | 'orange' | 'grey'; text: string }> = {
  ok: { color: 'green', text: 'ok' },
  missing: { color: 'red', text: 'missing' },
  broad: { color: 'orange', text: 'more than needed' },
  unknown: { color: 'grey', text: 'not known' },
};

/**
 * Checks the service account's own rights: finding people at sign-in, and acting as them for single
 * sign-on (Identity Manager too), on a few people under each container; and whether it has more than it needs.
 */
function ServiceAccountRights({ check }: { check: () => Promise<ServiceAccountCheck> }) {
  const [result, setResult] = useState<ServiceAccountCheck | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const run = () => {
    setBusy(true);
    setError(null);
    check().then(setResult, setError).finally(() => setBusy(false));
  };
  const level = useHeading();
  return (
    <section className="dc-tab-body" aria-label="The service account's rights">
      <p className="dc-subtle">
        Checks what the service account can do, as itself, on a few people under each container: find them at sign-in, and act as
        them for single sign-on. It also says when it has more rights than it needs.
      </p>
      <Button variant="secondary" isLoading={busy} isDisabled={busy} onClick={run}>Check its rights</Button>
      <ProblemAlert error={error} />
      {result && (
        <>
          <Alert component={level} isInline isPlain className="dc-tab-body"
            variant={result.result === 'ok' ? 'success' : result.result === 'warnings' ? 'warning' : 'danger'}
            title={result.result === 'ok' ? `${result.account} has the rights it needs, on the people checked.`
              : result.result === 'warnings' ? `${result.account} has the rights it needs, and more.` : `${result.account} is missing rights.`} />
          <Table variant="compact" aria-label="Service account rights">
            <Thead><Tr><Th>For</Th><Th>Where</Th><Th>Check</Th><Th>Result</Th></Tr></Thead>
            <Tbody>
              {result.checks.map((c, i) => (
                <Tr key={i}>
                  <Td dataLabel="For">{c.purpose}</Td>
                  <Td dataLabel="Where" className="dc-mono">{c.where}</Td>
                  <Td dataLabel="Check">{c.check}<div className="dc-subtle">{c.detail}</div></Td>
                  <Td dataLabel="Result"><Label isCompact color={FINDING[c.result].color}>{FINDING[c.result].text}</Label></Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </>
      )}
    </section>
  );
}
