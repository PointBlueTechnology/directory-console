import { useCallback, useEffect, useMemo, useState } from 'react';
import { ActionGroup, Alert, Button, Checkbox, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Spinner, TextInput } from '@patternfly/react-core';
import { type TraceSettings, idm } from '../api';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

type Key = 'level' | 'xslLevel' | 'javaDebugPort' | 'file' | 'name' | 'encoding' | 'sizeLimitKb';

const FIELDS: Record<'drivers' | 'driversets', { key: Key; label: string; number?: boolean; help: string }[]> = {
  drivers: [
    { key: 'level', label: 'Trace level', number: true, help: '0 to 10. Level 1 shows errors but not their causes; 5 shows password synchronization.' },
    { key: 'file', label: 'Trace file', help: 'Where this driver\'s trace is written, on each server that runs it.' },
    { key: 'name', label: 'Trace name', help: 'The prefix of this driver\'s trace messages.' },
    { key: 'encoding', label: 'Trace file encoding', help: 'The system\'s default unless set, such as UTF-8.' },
    { key: 'sizeLimitKb', label: 'Trace file size limit (KB)', number: true, help: '0 is unlimited. A limit is split across ten files.' },
  ],
  driversets: [
    { key: 'level', label: 'Trace level', number: true, help: '0 to 10, for the engine and every driver that uses the driver set\'s level.' },
    { key: 'xslLevel', label: 'XSL trace level', number: true, help: 'Style sheet events; leave at 0 unless troubleshooting XSL.' },
    { key: 'file', label: 'Trace file', help: 'The Java trace file.' },
    { key: 'encoding', label: 'Trace file encoding', help: 'The system\'s default unless set.' },
    { key: 'sizeLimitKb', label: 'Trace file size limit (KB)', number: true, help: '0 is unlimited. A limit is split across ten files.' },
    { key: 'javaDebugPort', label: 'Java debug port', number: true, help: 'For a developer\'s Java debugger. The Identity Vault must restart to use it.' },
  ],
};

const text = (v: unknown) => (v === null || v === undefined ? '' : String(v));

/**
 * A driver's or driver set's trace settings. A driver's setting can be left to the driver set ("Use the
 * driver set's"), which removes it from the driver; the driver set's value is shown beside it.
 */
export function TracePanel({ kind, guid }: { kind: 'drivers' | 'driversets'; guid: string }) {
  const { me, can } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const { run, dialog } = useConfirmed();
  const [saved, setSaved] = useState<TraceSettings | null>(null);
  const [draft, setDraft] = useState<Record<string, string | null>>({});
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fields = FIELDS[kind];
  const driver = kind === 'drivers';

  const take = (t: TraceSettings) => {
    setSaved(t);
    setDraft(Object.fromEntries(fields.map((f) => [f.key, t[f.key] === null || t[f.key] === undefined ? (driver ? null : '') : text(t[f.key])])));
  };
  const load = useCallback(() => { setError(null); api.trace(kind, guid).then(take, setError); }, [api, kind, guid]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(load, [load]);

  if (!saved) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading trace settings" />}</div>;
  }
  const original = (k: Key) => (saved[k] === null || saved[k] === undefined ? (driver ? null : '') : text(saved[k]));
  const changed = fields.filter((f) => draft[f.key] !== original(f.key));
  const invalid = fields.filter((f) => f.number && draft[f.key] !== null && draft[f.key] !== '' && !/^\d+$/.test(draft[f.key] ?? ''));
  const operator = can('operator');

  const save = () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    const body: Record<string, string | number | null> = {};
    changed.forEach((f) => {
      const v = draft[f.key];
      body[f.key] = v === null || v === '' ? null : f.number ? Number(v) : v;
    });
    run((c) => api.setTrace(kind, guid, body, c)).then((t) => { take(t); setNotice('Saved.'); }, setError).finally(() => setBusy(false));
  };

  return (
    <div className="dc-tab-body">
      <Form onSubmit={(e) => { e.preventDefault(); save(); }} isWidthLimited>
        {fields.map((f) => {
          const inherited = driver && draft[f.key] === null;
          const fromSet = saved.driverSet?.[f.key];
          return (
            <FormGroup key={f.key} label={f.label} fieldId={`trace-${f.key}`}>
              {driver && (
                <Checkbox id={`trace-${f.key}-inherit`} label={`Use the driver set's${fromSet !== null && fromSet !== undefined ? ` (${fromSet})` : ' (not set)'}`}
                  isChecked={inherited} isDisabled={!operator}
                  onChange={(_e, on) => setDraft({ ...draft, [f.key]: on ? null : text(saved[f.key] ?? fromSet ?? '') })} />
              )}
              {!inherited && (
                <TextInput id={`trace-${f.key}`} value={draft[f.key] ?? ''} isDisabled={!operator} className={f.number ? undefined : 'dc-mono'}
                  type={f.number ? 'number' : 'text'} validated={invalid.includes(f) ? 'error' : 'default'}
                  onChange={(_e, v) => setDraft({ ...draft, [f.key]: v })} />
              )}
              <FormHelperText><HelperText><HelperTextItem>{f.help}</HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
          );
        })}
        {operator && (
          <ActionGroup>
            <Button type="submit" isLoading={busy} isDisabled={busy || changed.length === 0 || invalid.length > 0}>Save</Button>
            <Button variant="link" isDisabled={busy || changed.length === 0} onClick={() => take(saved)}>Undo changes</Button>
          </ActionGroup>
        )}
      </Form>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {dialog}
    </div>
  );
}
