import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, ClipboardCopy, ClipboardCopyVariant, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, HelperText, HelperTextItem,
  Label, Modal, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, Switch, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AgentChange, type AgentKey, type AgentKeyList, type RoleId, ApiError, agentChanges, agentKeys } from '../api';
import { navigate, useLocation } from '../router';
import { useSession } from '../session';
import { ProblemAlert } from '../components/Problem';
import { useStepUp } from '../components/StepUp';
import { useAreYouSure } from '../components/Confirm';
import { useHelpTopic } from '../help/Help';

const STATE_COLOR = { active: 'green', idle: 'orange', expired: 'grey' } as const;
const when = (t: string | null) => (t ? new Date(t).toLocaleString() : 'never');
const CHANGE_COLOR = { pending: 'blue', approved: 'green', declined: 'grey', expired: 'grey', failed: 'red' } as const;

/**
 * Agent keys: a person makes one for their AI agent, which then uses the console's MCP server as them, with their own
 * rights. The key is shown once. Admins may also see and revoke everyone's keys in this directory.
 */
export function AgentKeysPage() {
  useHelpTopic('agent-keys');
  const session = useSession();
  const [all, setAll] = useState(false);
  const [list, setList] = useState<AgentKeyList | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [making, setMaking] = useState(false);
  const [made, setMade] = useState<{ token: string; key: AgentKey; mcpUrl: string; appsProblem?: string } | null>(null);
  const [authorizing, setAuthorizing] = useState<AgentKey | null>(null);
  const sure = useAreYouSure();
  const { query } = useLocation();
  const [changes, setChanges] = useState<AgentChange[]>([]);
  const [deciding, setDeciding] = useState<AgentChange | null>(null);
  const load = useCallback(() => {
    setError(null);
    agentKeys.list(all).then(setList, setError);
    agentChanges.list(all).then(setChanges, setError);
  }, [all]);
  // the link an agent gives (?change=<id>) opens that change
  const linked = query.get('change');
  useEffect(() => {
    const c = linked ? changes.find((x) => x.id === linked) : undefined;
    if (c && c.state === 'pending') {
      setDeciding(c);
    }
  }, [linked, changes]);
  const closeDecision = () => { setDeciding(null); if (linked) { navigate('/agent-keys', true); } load(); };
  useEffect(load, [load]);
  const revoke = (k: AgentKey) => sure.ask(`Revoke ${k.label}?`, 'The agent using this key loses access at once. This cannot be undone; a new key can be made.', 'Revoke',
    () => agentKeys.revoke(k.id).then(load, setError));

  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Agent keys</Title>
      <p className="dc-subtle">An agent key lets an AI agent work in this console as you, through its MCP server, with your own eDirectory rights and
        at most the roles you give the key. The agent can never do more than you can. Its changes wait here for your approval unless an
        administrator turns that off for this directory.</p>
      <ProblemAlert error={error} onRetry={load} />
      {linked && changes.length > 0 && !changes.some((c) => c.id === linked) && (
        <Alert variant="warning" isInline title="That change is not here">It may have expired, or belong to someone else, or the console restarted since the agent asked.</Alert>
      )}
      {changes.length > 0 && (
        <>
          <Title headingLevel="h2" className="dc-tab-body">Changes agents asked for</Title>
          <p className="dc-subtle">A change waits here for {all ? 'its key\'s owner' : 'you'} to approve it, for an hour. Approving makes it then, as the agent&apos;s key.</p>
          <Table aria-label="Changes agents asked for" variant="compact">
            <Thead>
              <Tr>
                <Th>Change</Th>
                {all && <Th>Person</Th>}
                <Th>Key</Th>
                <Th>State</Th>
                <Th>Asked</Th>
                <Th screenReaderText="Actions" />
              </Tr>
            </Thead>
            <Tbody>
              {changes.map((c) => (
                <Tr key={c.id}>
                  <Td dataLabel="Change">{c.summary}</Td>
                  {all && <Td dataLabel="Person" className="dc-mono">{c.dn}</Td>}
                  <Td dataLabel="Key">{c.key.label}</Td>
                  <Td dataLabel="State"><Label color={CHANGE_COLOR[c.state]}>{c.state}</Label></Td>
                  <Td dataLabel="Asked">{when(c.created)}</Td>
                  <Td isActionCell>
                    {c.state === 'pending' && <Button variant="secondary" size="sm" onClick={() => setDeciding(c)}>Review</Button>}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
          <Title headingLevel="h2" className="dc-tab-body">Keys</Title>
        </>
      )}
      {!list && !error && <Spinner aria-label="Loading the agent keys" />}
      {list && !list.settings.enabled && (
        <EmptyState titleText="Agent keys are off for this directory" headingLevel="h2">
          <EmptyStateBody>An administrator turns them on in Settings &gt; Directory.{list.keys.length > 0 && ' Keys made earlier work again when they are turned back on, until they expire.'}</EmptyStateBody>
        </EmptyState>
      )}
      {list && (
        <>
          <Toolbar>
            <ToolbarContent>
              {list.settings.enabled && (
                <ToolbarItem>
                  <Button icon={<PlusIcon />} onClick={() => { setMade(null); setMaking(true); }}>New agent key</Button>
                </ToolbarItem>
              )}
              {session.can('admin') && (
                <ToolbarItem>
                  <Switch id="agent-keys-all" label="Everyone's keys" isChecked={all} onChange={(_e, v) => setAll(v)} />
                </ToolbarItem>
              )}
            </ToolbarContent>
          </Toolbar>
          {list.keys.length === 0 ? (
            <p className="dc-subtle">{all ? 'Nobody has an agent key in this directory.' : 'You have no agent keys here.'}</p>
          ) : (
            <Table aria-label="Agent keys" variant="compact">
              <Thead>
                <Tr>
                  <Th>Label</Th>
                  {all && <Th>Person</Th>}
                  <Th>Roles</Th>
                  <Th>State</Th>
                  <Th>Made</Th>
                  <Th>Expires</Th>
                  <Th>Last used</Th>
                  {list.settings.apps && <Th>Identity Applications</Th>}
                  <Th screenReaderText="Actions" />
                </Tr>
              </Thead>
              <Tbody>
                {list.keys.map((k) => (
                  <Tr key={k.id}>
                    <Td dataLabel="Label">{k.label} <span className="dc-subtle dc-mono">{k.id}</span></Td>
                    {all && <Td dataLabel="Person" className="dc-mono">{k.dn}</Td>}
                    <Td dataLabel="Roles">{k.roles.join(', ')}</Td>
                    <Td dataLabel="State"><Label color={STATE_COLOR[k.state]}>{k.state}</Label></Td>
                    <Td dataLabel="Made">{when(k.created)}</Td>
                    <Td dataLabel="Expires">{when(k.expires)}</Td>
                    <Td dataLabel="Last used">{when(k.lastUsed)}</Td>
                    {list.settings.apps && (
                      <Td dataLabel="Identity Applications">
                        {k.apps === 'authorized' ? <Label color="green">authorized</Label>
                          : k.apps === 'authorize-again' ? <Label color="orange">authorize again</Label> : <span className="dc-subtle">no</span>}
                        {k.apps !== 'authorized' && k.via === 'direct' && session.me.via === 'direct' && k.dn.toLowerCase() === session.me.dn.toLowerCase() && (
                          <> <Button variant="link" isInline onClick={() => setAuthorizing(k)}>Authorize</Button></>
                        )}
                      </Td>
                    )}
                    <Td isActionCell><Button variant="link" isDanger onClick={() => revoke(k)}>Revoke</Button></Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </>
      )}
      {making && list && (
        <NewKey list={list} onCancel={() => setMaking(false)} onMade={(m) => { setMaking(false); setMade(m); load(); }} />
      )}
      {made && <ShowKey made={made} onClose={() => setMade(null)} />}
      {authorizing && <Authorize agentKey={authorizing} onClose={() => { setAuthorizing(null); load(); }} />}
      {deciding && <Decide change={deciding} mine={deciding.dn.toLowerCase() === session.me.dn.toLowerCase()} onClose={closeDecision} />}
      {sure.dialog}
    </PageSection>
  );
}

const ROLE_TEXT: Record<'editor' | 'operator', string> = {
  editor: 'Change directory objects (editor)',
  operator: 'Run Identity Manager operations (operator)',
};

function NewKey({ list, onCancel, onMade }: { list: AgentKeyList; onCancel: () => void; onMade: (m: { token: string; key: AgentKey; mcpUrl: string; appsProblem?: string }) => void }) {
  const { me, can } = useSession();
  const { run, dialog } = useStepUp();
  const sso = me.via === 'oidc';
  const longest = list.settings.longestDays;
  const [label, setLabel] = useState('');
  const [days, setDays] = useState(String(Math.min(30, longest)));
  const [roles, setRoles] = useState<RoleId[]>([]);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const daysOk = /^\d+$/.test(days) && Number(days) >= 1 && Number(days) <= longest;
  const offered = (['editor', 'operator'] as const).filter((r) => can(r));
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    run(() => agentKeys.create({ label: label.trim(), days: Number(days), roles: ['viewer', ...roles], password: sso ? undefined : password }))
      .then(onMade, (x) => { setError(x instanceof ApiError && x.status === 401 ? new Error('The password is incorrect.') : x); setPassword(''); })
      .finally(() => setBusy(false));
  };
  return (
    <Modal variant="medium" isOpen onClose={onCancel} aria-labelledby="new-key-title">
      <ModalHeader title="New agent key" labelId="new-key-title" />
      <ModalBody>
        <Form id="new-key-form" onSubmit={submit}>
          <FormGroup label="Label" fieldId="key-label" isRequired>
            <TextInput id="key-label" value={label} onChange={(_e, v) => setLabel(v)} placeholder="Claude Code on my laptop" isRequired autoFocus />
            <FormHelperText><HelperText><HelperTextItem>Which agent or machine uses it. The audit log names the key by this label.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Expires after this many days" fieldId="key-days" isRequired>
            <TextInput id="key-days" type="number" min={1} max={longest} value={days} onChange={(_e, v) => setDays(v)} validated={daysOk ? 'default' : 'error'} />
            <FormHelperText><HelperText><HelperTextItem variant={daysOk ? 'default' : 'error'}>
              1 to {longest} days{sso ? ' (keys made with single sign-on live at most 14 days)' : ''}. A key unused for 14 days also stops.
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="What it may do" fieldId="key-roles" isStack>
            <Checkbox id="key-role-viewer" label="Read (viewer)" isChecked isDisabled />
            {offered.map((r) => (
              <Checkbox key={r} id={`key-role-${r}`} label={ROLE_TEXT[r]} isChecked={roles.includes(r)}
                onChange={(_e, v) => setRoles(v ? [...roles, r] : roles.filter((x) => x !== r))} />
            ))}
            <FormHelperText><HelperText><HelperTextItem>Never more than your own roles, and never admin.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {!sso && (
            <FormGroup label="Your password" fieldId="key-password" isRequired>
              <TextInput id="key-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} isRequired />
              <FormHelperText><HelperText><HelperTextItem>To confirm it is you. It is checked and not kept.</HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
          )}
          {!sso && list.settings.apps && (
            <p className="dc-subtle">Your password also signs you in to Identity Applications once, for this key: it keeps that sign-in (never the
              password), so its agent can see and act on your approval tasks and requests.</p>
          )}
          {sso && <p className="dc-subtle">Making a key needs a single sign-on sign-in within the last 10 minutes.{list.settings.apps
            && ' Keys made with single sign-on get no Identity Applications tools: there is no password to sign in to them with.'}</p>}
        </Form>
        <ProblemAlert error={error} />
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="new-key-form" isLoading={busy} isDisabled={busy || !label.trim() || !daysOk || (!sso && !password)}>Make the key</Button>
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
      {dialog}
    </Modal>
  );
}

function ShowKey({ made, onClose }: { made: { token: string; key: AgentKey; mcpUrl: string; appsProblem?: string }; onClose: () => void }) {
  const claude = `claude mcp add --transport http directory-console ${made.mcpUrl} --header "Authorization: Bearer ${made.token}"`;
  const json = JSON.stringify({ mcpServers: { 'directory-console': { type: 'http', url: made.mcpUrl, headers: { Authorization: `Bearer ${made.token}` } } } }, null, 2);
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="show-key-title">
      <ModalHeader title={`Agent key ${made.key.label}`} labelId="show-key-title" />
      <ModalBody>
        <Alert variant="warning" isInline title="Copy the key now: it is not shown again">
          Keep it like a password. Anyone with it can act as you, within the key&apos;s roles, until it expires or you revoke it.
        </Alert>
        {made.appsProblem && (
          <Alert variant="info" isInline title="The key has no Identity Applications tools yet">
            {made.appsProblem} Authorize it later from the list of keys.
          </Alert>
        )}
        <Form>
          <FormGroup label="The key" fieldId="show-key-token">
            <ClipboardCopy id="show-key-token" isReadOnly hoverTip="Copy" clickTip="Copied">{made.token}</ClipboardCopy>
          </FormGroup>
          <FormGroup label="MCP server" fieldId="show-key-url">
            <ClipboardCopy id="show-key-url" isReadOnly hoverTip="Copy" clickTip="Copied">{made.mcpUrl}</ClipboardCopy>
          </FormGroup>
          <FormGroup label="Claude Code" fieldId="show-key-claude">
            <ClipboardCopy id="show-key-claude" isReadOnly isCode variant={ClipboardCopyVariant.expansion} hoverTip="Copy" clickTip="Copied">{claude}</ClipboardCopy>
          </FormGroup>
          <FormGroup label="Other MCP clients" fieldId="show-key-json">
            <ClipboardCopy id="show-key-json" isReadOnly isCode variant={ClipboardCopyVariant.expansion} hoverTip="Copy" clickTip="Copied">{json}</ClipboardCopy>
            <FormHelperText><HelperText><HelperTextItem>The agent&apos;s machine must trust the console&apos;s certificate.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button onClick={onClose}>Done</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Approve or decline one change an agent asked for; on a production directory, approving asks for its name. */
function Decide({ change, mine, onClose }: { change: AgentChange; mine: boolean; onClose: () => void }) {
  const { me } = useSession();
  const production = me.tier === 'production';
  const name = me.directoryName ?? me.directory;
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<AgentChange | null>(null);
  const [busy, setBusy] = useState(false);
  const go = (call: () => Promise<AgentChange>) => {
    setBusy(true);
    setError(null);
    call().then(setDone, setError).finally(() => setBusy(false));
  };
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="decide-title">
      <ModalHeader title={done ? `The change is ${done.state}` : 'A change an agent asked for'} labelId="decide-title" />
      <ModalBody>
        <p><strong>{change.summary}</strong></p>
        <p className="dc-subtle">Asked by the agent key {change.key.label} ({change.tool}) at {when(change.created)}; it expires at {when(change.expires)}.
          Approving makes the change now, as that key, with your rights and the key&apos;s roles.</p>
        {!done && mine && production && (
          <Form onSubmit={(e) => e.preventDefault()}>
            <FormGroup label={`Type ${name} to approve a change to this production directory`} fieldId="decide-confirm">
              <TextInput id="decide-confirm" value={typed} onChange={(_e, v) => setTyped(v)} autoComplete="off" />
            </FormGroup>
          </Form>
        )}
        {!mine && <p className="dc-subtle">Only {change.dn} can approve it; you can decline it.</p>}
        {done?.result && (
          <Alert variant={done.result.status < 400 ? 'success' : 'danger'} isInline title={done.result.status < 400 ? 'Done' : 'The change failed'}>
            <pre className="dc-mono">{JSON.stringify(done.result.body, null, 2).slice(0, 2000)}</pre>
          </Alert>
        )}
        <ProblemAlert error={error} />
      </ModalBody>
      <ModalFooter>
        {!done && mine && (
          <Button isLoading={busy} isDisabled={busy || (production && typed.trim().toLowerCase() !== name.toLowerCase())}
            onClick={() => go(() => agentChanges.approve(change.id, production ? typed.trim() : undefined))}>Approve</Button>
        )}
        {!done && <Button variant="secondary" isDanger isDisabled={busy} onClick={() => go(() => agentChanges.decline(change.id))}>Decline</Button>}
        <Button variant="link" onClick={onClose}>{done ? 'Close' : 'Later'}</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Sign the person in to Identity Applications for their own key (again), with their password. */
function Authorize({ agentKey, onClose }: { agentKey: AgentKey; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    agentKeys.authorize(agentKey.id, password).then(onClose, (x) => {
      setPassword('');
      setError(x instanceof ApiError && x.status === 401 && x.code === 'bad-credentials' ? new Error('The password is incorrect.') : x);
    }).finally(() => setBusy(false));
  };
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="authorize-title">
      <ModalHeader title={`Identity Applications for ${agentKey.label}`} labelId="authorize-title" />
      <ModalBody>
        <Form id="authorize-form" onSubmit={submit}>
          <p>Your password signs you in to Identity Applications once; the key keeps that sign-in, never the password.</p>
          <FormGroup label="Your password" fieldId="authorize-password" isRequired>
            <TextInput id="authorize-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} autoFocus isRequired />
          </FormGroup>
        </Form>
        <ProblemAlert error={error} />
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="authorize-form" isLoading={busy} isDisabled={busy || !password}>Authorize</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
