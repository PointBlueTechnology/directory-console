import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActionGroup, Alert, Button, Checkbox, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSection, HelperText,
  HelperTextItem, Label, LabelGroup, Spinner, Switch, TextInput,
} from '@patternfly/react-core';
import type { Account, DirObject } from '../api';
import { useSession } from '../session';
import { decode, encode } from '../timemap';
import { ProblemAlert } from './Problem';
import { TimeGrid } from './TimeGrid';
import { useHeading } from '../heading';

type Draft = Partial<Account>;

/** A user's account: status, intruder lockout, login and password restrictions, allowed login times. */
export function AccountTab({ obj, onChanged }: { obj: DirObject; onChanged: () => void }) {
  const { tree, can } = useSession();
  const [account, setAccount] = useState<Account | null>(null);
  const [etag, setEtag] = useState('*');
  const [draft, setDraft] = useState<Draft>({});
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const editor = can('editor');
  const level = useHeading();

  const load = useCallback(() => {
    setError(null);
    tree.account(obj.guid).then((r) => {
      setAccount(r.data);
      setEtag(r.etag ?? '*');
      setDraft({});
    }).catch(setError);
  }, [tree, obj.guid]);
  useEffect(load, [load]);

  const value = <K extends keyof Account>(k: K): Account[K] | undefined => (k in draft ? draft[k] as Account[K] : account?.[k]);
  const put = (d: Draft) => {
    setSaved(false);
    setDraft({ ...draft, ...d });
  };
  const bits = useMemo(() => decode((value('timeMap') ?? null) as string | null), [draft, account]); // eslint-disable-line react-hooks/exhaustive-deps
  const restricted = value('timeMap') !== null && value('timeMap') !== undefined;

  const save = async (change: Draft = draft) => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.updateAccount(obj.guid, etag, change);
      setAccount(r.data);
      setEtag(r.etag ?? '*');
      setDraft({});
      setSaved(true);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.unlock(obj.guid);
      setAccount(r.data);
      setEtag(r.etag ?? '*');
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (!account) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the account" />;
  }
  const changed = Object.keys(draft).length > 0;

  return (
    <div className="dc-tab-body">
      <LabelGroup>
        {account.disabled ? <Label color="red">Disabled</Label> : <Label color="green">Enabled</Label>}
        {account.lockedByIntruder && <Label color="orange">Locked by intruder detection</Label>}
        {account.passwordExpires && new Date(account.passwordExpires) < new Date() && <Label color="orange">Password expired</Label>}
        {account.loginExpires && new Date(account.loginExpires) < new Date() && <Label color="red">Account expired</Label>}
      </LabelGroup>
      {account.lockedByIntruder && (
        <Alert component={level} variant="warning" isInline title="This account is locked by intruder detection" className="dc-tab-body"
          actionLinks={editor ? <Button variant="link" isInline onClick={unlock} isLoading={busy}>Unlock</Button> : undefined}>
          {account.intruderAttempts !== null && <>{account.intruderAttempts} failed attempts. </>}
          {account.intruderResetTime && <>Resets on its own at {new Date(account.intruderResetTime).toLocaleString()}.</>}
        </Alert>
      )}
      {account.lastLogin && <p className="dc-subtle dc-tab-body">Last login {new Date(account.lastLogin).toLocaleString()}</p>}

      <Form onSubmit={(e) => { e.preventDefault(); save(); }} className="dc-tab-body">
        <FormSection title="Login" titleElement={level}>
          <Switch id="disabled" label="Account disabled" isChecked={!!value('disabled')} isDisabled={!editor}
            onChange={(_e, v) => put({ disabled: v })} />
          <When label="Account expires" id="loginExpires" value={value('loginExpires') ?? null} disabled={!editor}
            onChange={(v) => put({ loginExpires: v })} />
          <Num label="Concurrent connections allowed" id="maxConnections" value={value('maxConnections') ?? null} disabled={!editor}
            onChange={(v) => put({ maxConnections: v })} hint="Empty: no limit" />
        </FormSection>
        <FormSection title="Password" titleElement={level}>
          <Checkbox id="passwordRequired" label="Password required" isChecked={!!value('passwordRequired')} isDisabled={!editor}
            onChange={(_e, v) => put({ passwordRequired: v })} />
          <Checkbox id="passwordAllowChange" label="User may change the password" isChecked={!!value('passwordAllowChange')} isDisabled={!editor}
            onChange={(_e, v) => put({ passwordAllowChange: v })} />
          <Checkbox id="passwordUnique" label="Require a password not used before" isChecked={!!value('passwordUnique')} isDisabled={!editor}
            onChange={(_e, v) => put({ passwordUnique: v })} />
          <Num label="Minimum length" id="passwordMinimumLength" value={value('passwordMinimumLength') ?? null} disabled={!editor}
            onChange={(v) => put({ passwordMinimumLength: v })} />
          <Num label="Change the password every (days)" id="passwordExpirationDays" value={value('passwordExpirationDays') ?? null} disabled={!editor}
            onChange={(v) => put({ passwordExpirationDays: v })} hint="Empty: the password never expires" />
          <When label="Password expires" id="passwordExpires" value={value('passwordExpires') ?? null} disabled={!editor}
            onChange={(v) => put({ passwordExpires: v })} />
          <Num label="Grace logins allowed" id="graceLimit" value={value('graceLimit') ?? null} disabled={!editor} onChange={(v) => put({ graceLimit: v })} />
          <Num label="Grace logins remaining" id="graceRemaining" value={value('graceRemaining') ?? null} disabled={!editor} onChange={(v) => put({ graceRemaining: v })} />
        </FormSection>
        <FormSection title="Login times" titleElement={level}>
          <Switch id="restrict" label="Restrict the times this account may log in" isChecked={restricted} isDisabled={!editor}
            onChange={(_e, v) => put({ timeMap: v ? encode(bits) : null })} />
          {restricted && <TimeGrid bits={bits} disabled={!editor} onChange={(b) => put({ timeMap: encode(b) })} />}
          {restricted && (
            <HelperText><HelperTextItem>Half-hour slots as stored in eDirectory (loginAllowedTimeMap), Sunday first. Check one change in iManager before relying on the time zone.</HelperTextItem></HelperText>
          )}
        </FormSection>
        <ProblemAlert error={error} onRetry={load} />
        {saved && <Alert component={level} variant="success" isInline isPlain title="Saved" />}
        {editor && (
          <ActionGroup>
            <Button type="submit" variant="primary" isDisabled={!changed || busy} isLoading={busy}>Save</Button>
            <Button variant="link" isDisabled={!changed} onClick={() => setDraft({})}>Undo changes</Button>
          </ActionGroup>
        )}
      </Form>
    </div>
  );
}

function Num({ label, id, value, onChange, disabled, hint }: { label: string; id: string; value: number | null; onChange: (v: number | null) => void; disabled?: boolean; hint?: string }) {
  return (
    <FormGroup label={label} fieldId={id}>
      <TextInput id={id} type="number" min={0} value={value ?? ''} isDisabled={disabled}
        onChange={(_e, v) => onChange(v.trim() === '' ? null : Math.max(0, Math.floor(Number(v))))} className="dc-narrow" />
      {hint && <FormHelperText><HelperText><HelperTextItem>{hint}</HelperTextItem></HelperText></FormHelperText>}
    </FormGroup>
  );
}

/** A date and time in the person's local time zone, stored as UTC; empty means none. */
function When({ label, id, value, onChange, disabled }: { label: string; id: string; value: string | null; onChange: (v: string | null) => void; disabled?: boolean }) {
  const local = value ? toLocalInput(value) : '';
  return (
    <FormGroup label={label} fieldId={id}>
      <Flex spaceItems={{ default: 'spaceItemsSm' }}>
        <FlexItem>
          <TextInput id={id} type="datetime-local" value={local} isDisabled={disabled}
            onChange={(_e, v) => onChange(v ? new Date(v).toISOString().replace(/\.\d{3}Z$/, 'Z') : null)} />
        </FlexItem>
        {value && !disabled && <FlexItem><Button variant="link" onClick={() => onChange(null)}>Clear</Button></FlexItem>}
      </Flex>
      <FormHelperText><HelperText><HelperTextItem>{value ? `${new Date(value).toUTCString()}` : 'Not set'}</HelperTextItem></HelperText></FormHelperText>
    </FormGroup>
  );
}

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return '';
  }
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
