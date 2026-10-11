import { useState } from 'react';
import {
  Alert, Button, Checkbox, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader,
  Radio, TextInput,
} from '@patternfly/react-core';
import { type DirObject, type Preset, type PresetRun, presets, isReference } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';

/** The first value of an attribute as text (a reference as its DN). */
function current(obj: DirObject, name: string): string {
  const key = Object.keys(obj.attributes).find((k) => k.toLowerCase() === name.toLowerCase());
  const v = key ? obj.attributes[key][0] : undefined;
  if (v === undefined) {
    return '';
  }
  return typeof v === 'string' ? v : isReference(v) ? v.dn : '';
}

/**
 * Run a task preset on one object: only the preset's actions, and its fields with their rules
 * (required, pattern, read-only, preset value). The server checks everything again.
 */
export function PresetModal({ obj, preset, onClose, onDone }: {
  obj: DirObject; preset: Preset; onClose: () => void; onDone: (changed: string[]) => void;
}) {
  const { me } = useSession();
  const has = (a: Preset['actions'][number]) => preset.actions.includes(a);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [mustChange, setMustChange] = useState(false);
  const [unlock, setUnlock] = useState(has('unlock'));
  const [enabled, setEnabled] = useState<'keep' | 'enable' | 'disable'>('keep');
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(preset.attributes.map((f) => [f.name, current(obj, f.name)])));
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const fieldError = (name: string): string | null => {
    const f = preset.attributes.find((x) => x.name === name)!;
    if (f.readOnly || f.value !== undefined) {
      return null;
    }
    const v = values[name].trim();
    if (!v) {
      return f.required ? `${f.label} is required.` : null;
    }
    if (f.pattern && !new RegExp(`^(?:${f.pattern})$`).test(v)) {
      return `${f.label} does not have the expected form.`;
    }
    return null;
  };
  const passwordError = has('password') && password !== confirm ? 'The passwords do not match.' : null;
  const invalid = !!passwordError || preset.attributes.some((f) => fieldError(f.name));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (invalid) {
      return;
    }
    const body: PresetRun = {};
    if (has('password') && password) {
      body.password = password;
      body.mustChange = mustChange;
    }
    if (has('unlock') && unlock) {
      body.unlock = true;
    }
    if (enabled !== 'keep') {
      body.enabled = enabled === 'enable';
    }
    const attrs: Record<string, string | null> = {};
    for (const f of preset.attributes) {
      if (!f.readOnly && f.value === undefined && values[f.name].trim() !== current(obj, f.name)) {
        attrs[f.name] = values[f.name].trim() || null;
      }
    }
    if (Object.keys(attrs).length > 0) {
      body.attributes = attrs;
    }
    if (Object.keys(body).length === 0) {
      onClose();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await presets(me.directory).run(obj.guid, preset.id, body);
      onDone(r.changed);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="preset-title" aria-describedby="preset-description">
      <ModalHeader title={preset.name} labelId="preset-title" description={preset.description ?? `On ${obj.name}`} descriptorId="preset-description" />
      <ModalBody>
        <Form id="preset-form" onSubmit={submit}>
          {has('password') && (
            <>
              <FormGroup label="New password" fieldId="preset-password">
                <TextInput id="preset-password" type="password" autoComplete="new-password" value={password} onChange={(_e, v) => setPassword(v)} />
              </FormGroup>
              <FormGroup label="Confirm the password" fieldId="preset-confirm">
                <TextInput id="preset-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(_e, v) => setConfirm(v)}
                  validated={touched && passwordError ? 'error' : 'default'} />
                {touched && passwordError && <FormHelperText><HelperText><HelperTextItem variant="error">{passwordError}</HelperTextItem></HelperText></FormHelperText>}
              </FormGroup>
              <Checkbox id="preset-must-change" label="Require a new password at the next login" isChecked={mustChange} onChange={(_e, v) => setMustChange(v)} />
            </>
          )}
          {has('unlock') && <Checkbox id="preset-unlock" label="Clear the intruder lockout" isChecked={unlock} onChange={(_e, v) => setUnlock(v)} />}
          {(has('enable') || has('disable')) && (
            <FormGroup role="radiogroup" label="Login" fieldId="preset-enabled" isInline>
              <Radio id="preset-keep" name="preset-enabled" label="Leave as it is" isChecked={enabled === 'keep'} onChange={() => setEnabled('keep')} />
              {has('enable') && <Radio id="preset-enable" name="preset-enabled" label="Enable" isChecked={enabled === 'enable'} onChange={() => setEnabled('enable')} />}
              {has('disable') && <Radio id="preset-disable" name="preset-enabled" label="Disable" isChecked={enabled === 'disable'} onChange={() => setEnabled('disable')} />}
            </FormGroup>
          )}
          {preset.attributes.map((f) => {
            const fixed = f.readOnly || f.value !== undefined;
            const err = touched ? fieldError(f.name) : null;
            return (
              <FormGroup key={f.name} label={f.label} fieldId={`preset-${f.name}`} isRequired={f.required && !fixed}>
                <TextInput id={`preset-${f.name}`} value={f.value !== undefined ? f.value : values[f.name]} readOnlyVariant={fixed ? 'default' : undefined}
                  onChange={(_e, v) => setValues({ ...values, [f.name]: v })} validated={err ? 'error' : 'default'} />
                {(err || f.value !== undefined) && (
                  <FormHelperText><HelperText>
                    {err ? <HelperTextItem variant="error">{err}</HelperTextItem> : <HelperTextItem>Set to this value whenever this task changes the object.</HelperTextItem>}
                  </HelperText></FormHelperText>
                )}
              </FormGroup>
            );
          })}
          <ProblemAlert error={error} />
          {preset.actions.length === 0 && <Alert variant="info" isInline isPlain title="This task has nothing to do." />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="preset-form" variant="primary" isLoading={busy} isDisabled={busy}>Apply</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
