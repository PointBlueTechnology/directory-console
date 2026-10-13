import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActionGroup, Alert, Button, Checkbox, ClipboardCopy, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, FormSection, HelperText,
  HelperTextItem, Label, LabelGroup, List, ListItem, PageSection, Spinner, Tab, Tabs, TabTitleText, TextArea, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { DownloadIcon, PlusIcon, UploadIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DirectorySettings, type OidcSettings, type Preset, type RoleMappingJson, consoleSettings, settings } from '../api';
import { useSession } from '../session';
import { HeadingLevel, useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { RoleMappings } from '../components/RoleMappings';
import { PresetEditor, presetJson } from '../components/PresetEditor';
import { useStepUp } from '../components/StepUp';

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
  const [tab, setTab] = useState<string | number>('roles');
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
            <Tab eventKey="roles" title={<TabTitleText>Role mappings</TabTitleText>}>
              <RolesSection s={s} etag={etag} save={(v) => api.roles(v, etag)} onSaved={saved} />
            </Tab>
            <Tab eventKey="presets" title={<TabTitleText>Task presets</TabTitleText>}>
              <PresetsSection s={s} etag={etag} save={(v) => api.presets(v, etag)} exportAll={api.exportPresets} onSaved={saved} />
            </Tab>
            <Tab eventKey="sso" title={<TabTitleText>Single sign-on</TabTitleText>}>
              <SsoSection s={s} save={(v) => api.oidc(v, etag)} test={api.testMapping} onSaved={saved} />
            </Tab>
            <Tab eventKey="other" title={<TabTitleText>Other directories</TabTitleText>}>
              <OtherDirectoriesSection />
            </Tab>
          </Tabs>
        </HeadingLevel.Provider>
      )}
    </PageSection>
  );
}

/**
 * Console-wide: whether people may sign in to directories they enter themselves (DESIGN 6.3). They
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
      <p>Members of these eDirectory groups get these grants when they sign in with their name and password. Break-glass accounts ({s.breakGlass.join(', ') || 'none'}) are always admins.</p>
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

function SsoSection({ s, save, test, onSaved }: {
  s: DirectorySettings; save: Saver<OidcSettings | null>; test: (v: string) => Promise<{ matches: string[]; neverProxy: boolean }>;
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
      <Form onSubmit={submit} isWidthLimited>
        <FormSection title="Identity provider" titleElement="h2">
          <FormGroup label="Redirect URI to register at the provider" fieldId="sso-redirect">
            <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" id="sso-redirect" className="dc-mono">{s.redirectUri}</ClipboardCopy>
          </FormGroup>
          <FormGroup label="Issuer" fieldId="sso-issuer" isRequired>
            <TextInput id="sso-issuer" type="url" value={o.issuer} onChange={field('issuer')} placeholder="https://idp.example.com/realms/acme" isRequired />
          </FormGroup>
          <FormGroup label="Client id" fieldId="sso-client" isRequired>
            <TextInput id="sso-client" value={o.clientId} onChange={field('clientId')} isRequired />
          </FormGroup>
          <FormGroup label="Client secret" fieldId="sso-secret">
            <TextInput id="sso-secret" type="password" autoComplete="off" value={secret} onChange={(_e, v) => setSecret(v)} isDisabled={publicClient}
              placeholder={s.oidc?.clientSecretSet ? 'Set — leave empty to keep it' : ''} />
            <Checkbox id="sso-public" label="Public client (PKCE only, no secret)" isChecked={publicClient} onChange={(_e, v) => setPublicClient(v)} />
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
          <FormGroup label="Claim" fieldId="sso-claim" isRequired>
            <TextInput id="sso-claim" value={o.claim ?? ''} onChange={field('claim')} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Matches the attribute" fieldId="sso-attribute" isRequired>
            <TextInput id="sso-attribute" value={o.attribute ?? ''} onChange={field('attribute')} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Under these containers" fieldId="sso-bases">
            <TextArea id="sso-bases" value={bases} onChange={(_e, v) => setBases(v)} className="dc-mono" resizeOrientation="vertical" />
            <FormHelperText><HelperText><HelperTextItem>
              One DN per line; empty uses the sign-in search bases. The service account needs Supervisor over these people (and nobody else).
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Never act as" fieldId="sso-never">
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
