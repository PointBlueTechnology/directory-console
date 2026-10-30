import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, ClipboardCopy, ClipboardCopyVariant, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, HelperText, HelperTextItem,
  Label, Modal, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, Switch, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AgentKey, type AgentKeyList, type RoleId, ApiError, agentKeys } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from '../components/Problem';
import { useStepUp } from '../components/StepUp';
import { useAreYouSure } from '../components/Confirm';
import { useHelpTopic } from '../help/Help';

const STATE_COLOR = { active: 'green', idle: 'orange', expired: 'grey' } as const;
const when = (t: string | null) => (t ? new Date(t).toLocaleString() : 'never');

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
  const [made, setMade] = useState<{ token: string; key: AgentKey; mcpUrl: string } | null>(null);
  const sure = useAreYouSure();
  const load = useCallback(() => {
    setError(null);
    agentKeys.list(all).then(setList, setError);
  }, [all]);
  useEffect(load, [load]);
  const revoke = (k: AgentKey) => sure.ask(`Revoke ${k.label}?`, 'The agent using this key loses access at once. This cannot be undone; a new key can be made.', 'Revoke',
    () => agentKeys.revoke(k.id).then(load, setError));

  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Agent keys</Title>
      <p className="dc-subtle">An agent key lets an AI agent work in this console as you, through its MCP server, with your own eDirectory rights and
        at most the roles you give the key. The agent can never do more than you can. This version&apos;s agent tools only read.</p>
      <ProblemAlert error={error} onRetry={load} />
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
      {sure.dialog}
    </PageSection>
  );
}

const ROLE_TEXT: Record<'editor' | 'operator', string> = {
  editor: 'Change directory objects (editor)',
  operator: 'Run Identity Manager operations (operator)',
};

function NewKey({ list, onCancel, onMade }: { list: AgentKeyList; onCancel: () => void; onMade: (m: { token: string; key: AgentKey; mcpUrl: string }) => void }) {
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
            <FormHelperText><HelperText><HelperTextItem>Never more than your own roles, and never admin. The agent tools of this version only read.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {!sso && (
            <FormGroup label="Your password" fieldId="key-password" isRequired>
              <TextInput id="key-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} isRequired />
              <FormHelperText><HelperText><HelperTextItem>To confirm it is you. It is checked and not kept.</HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
          )}
          {sso && <p className="dc-subtle">Making a key needs a single sign-on sign-in within the last 10 minutes.</p>}
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

function ShowKey({ made, onClose }: { made: { token: string; key: AgentKey; mcpUrl: string }; onClose: () => void }) {
  const claude = `claude mcp add --transport http directory-console ${made.mcpUrl} --header "Authorization: Bearer ${made.token}"`;
  const json = JSON.stringify({ mcpServers: { 'directory-console': { type: 'http', url: made.mcpUrl, headers: { Authorization: `Bearer ${made.token}` } } } }, null, 2);
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="show-key-title">
      <ModalHeader title={`Agent key ${made.key.label}`} labelId="show-key-title" />
      <ModalBody>
        <Alert variant="warning" isInline title="Copy the key now: it is not shown again">
          Keep it like a password. Anyone with it can act as you, within the key&apos;s roles, until it expires or you revoke it.
        </Alert>
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
