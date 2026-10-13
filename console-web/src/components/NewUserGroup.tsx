import { useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Label, LabelGroup, Modal, ModalBody,
  ModalFooter, ModalHeader, TextInput,
} from '@patternfly/react-core';
import { type DirObject, type Row, type SchemaClass } from '../api';
import { useSession } from '../session';
import { Target } from './Edit';
import { ObjectPicker } from './ObjectPicker';
import { ProblemAlert } from './Problem';

/**
 * eDirectory's own object classes for a User and a Group, as iManager and Identity Console write them:
 * the structural class and its superiors. eDirectory would add the superiors itself; naming them keeps
 * the entry the same whichever tool made it.
 */
export const STANDARD = {
  user: ['inetOrgPerson', 'organizationalPerson', 'Person', 'ndsLoginProperties', 'Top'],
  group: ['groupOfNames', 'Top'],
} as const;

/** Whether a container may hold a user or group (the structural class's containment). */
export function canHold(cls: SchemaClass | undefined, parent: Pick<Row, 'objectClasses'>): boolean {
  const here = parent.objectClasses.map((c) => c.toLowerCase());
  return !!cls && (cls.containment.length === 0 || cls.containment.some((p) => here.includes(p.toLowerCase())));
}

/** Attributes the form offers, in order; each only when the class allows it. */
const USER_FIELDS: { attr: string; label: string }[] = [
  { attr: 'givenName', label: 'First name' },
  { attr: 'sn', label: 'Last name' },
  { attr: 'fullName', label: 'Full name' },
  { attr: 'uid', label: 'Unique ID' },
  { attr: 'title', label: 'Title' },
  { attr: 'mail', label: 'Email' },
  { attr: 'telephoneNumber', label: 'Phone' },
  { attr: 'description', label: 'Description' },
];
const GROUP_FIELDS = [{ attr: 'description', label: 'Description' }];

/**
 * A new eDirectory User or Group with the standard object classes: the usual fields, then, for a
 * user, the password and groups, and for a group, its first members. Membership is written on both
 * sides, as the Members tab does.
 */
export function NewUserGroupModal({ kind, parent, onClose, onCreated }: {
  kind: 'user' | 'group'; parent: Row; onClose: () => void; onCreated: (o: DirObject) => void;
}) {
  const { tree } = useSession();
  const [cls, setCls] = useState<SchemaClass | null>(null);
  const [name, setName] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [fullNameEdited, setFullNameEdited] = useState(false);
  const [uidEdited, setUidEdited] = useState(false);
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const [mustChange, setMustChange] = useState(true);
  const [related, setRelated] = useState<Row[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [partial, setPartial] = useState<{ obj: DirObject; problems: string[] } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    tree.schemaClass(STANDARD[kind][0]).then(setCls).catch(setError);
  }, [tree, kind]);

  const allowed = new Set([...(cls?.allMust ?? []), ...(cls?.allMay ?? [])].map((a) => a.toLowerCase()));
  const fields = (kind === 'user' ? USER_FIELDS : GROUP_FIELDS).filter((f) => allowed.has(f.attr.toLowerCase()));
  const required = new Set((cls?.allMust ?? []).map((a) => a.toLowerCase()));
  const value = (a: string) => values[a] ?? '';
  // as iManager does: the full name follows first and last name, and the unique ID the user name, until edited
  const shown = (a: string) => a === 'fullName' && !fullNameEdited ? [value('givenName'), value('sn')].filter(Boolean).join(' ')
    : a === 'uid' && !uidEdited ? name : value(a);
  const set = (a: string, v: string) => {
    if (a === 'fullName') {
      setFullNameEdited(true);
    }
    if (a === 'uid') {
      setUidEdited(true);
    }
    setValues({ ...values, [a]: v });
  };
  const missing = fields.filter((f) => required.has(f.attr.toLowerCase()) && !shown(f.attr).trim());
  const mismatch = again.length > 0 && again !== pw;
  const ready = cls && name.trim() && missing.length === 0 && !mismatch && (pw === '' || again === pw);

  const create = async () => {
    if (!cls) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const attributes: Record<string, string[]> = {};
      fields.forEach((f) => {
        const v = shown(f.attr).trim();
        if (v && f.attr.toLowerCase() !== 'cn') {
          attributes[f.attr] = [v];
        }
      });
      const r = await tree.create(parent.guid, [...STANDARD[kind]], { type: 'cn', value: name.trim() }, attributes);
      // the object exists from here on: later failures are reported against it, not as a failed create
      const problems: string[] = [];
      if (kind === 'user' && pw) {
        try {
          await tree.password(r.data.guid, pw, mustChange);
        } catch (e) {
          problems.push(`The password was not set: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      for (const other of related) {
        try {
          const results = kind === 'user' ? await tree.changeMembers(other.guid, [r.data.guid], []) : await tree.changeMembers(r.data.guid, [other.guid], []);
          results.filter((x) => x.status === 'failed').forEach((x) => problems.push(`${x.group.name} / ${x.member.name}: ${x.detail ?? 'failed'}`));
        } catch (e) {
          problems.push(`${other.name}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      if (problems.length) {
        setPartial({ obj: r.data, problems });
      } else {
        onCreated(r.data);
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const title = kind === 'user' ? 'New user' : 'New group';
  if (partial) {
    return (
      <Modal isOpen onClose={() => onCreated(partial.obj)} variant="medium" aria-labelledby="nug-title">
        <ModalHeader title={title} labelId="nug-title" />
        <ModalBody>
          <Alert variant="warning" isInline title={`${partial.obj.name} was created, but not everything was done`}>
            <ul>{partial.problems.map((p, i) => <li key={i}>{p}</li>)}</ul>
          </Alert>
        </ModalBody>
        <ModalFooter><Button onClick={() => onCreated(partial.obj)}>Open {partial.obj.name}</Button></ModalFooter>
      </Modal>
    );
  }
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="nug-title">
      <ModalHeader title={title} labelId="nug-title"
        description={<>Object classes: <span className="dc-mono">{STANDARD[kind].join(', ')}</span></>} />
      <ModalBody>
        <Form id="nug-form" onSubmit={(e) => { e.preventDefault(); create(); }}>
          <Target obj={parent} label="In" />
          <FormGroup label={kind === 'user' ? 'User name' : 'Group name'} fieldId="nug-name" isRequired>
            <TextInput id="nug-name" value={name} onChange={(_e, v) => setName(v)} isDisabled={!cls} />
            <FormHelperText><HelperText><HelperTextItem>Its cn: the name in the tree.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {fields.map((f) => (
            <FormGroup key={f.attr} label={f.label} fieldId={`nug-${f.attr}`} isRequired={required.has(f.attr.toLowerCase())}>
              <TextInput id={`nug-${f.attr}`} value={shown(f.attr)} onChange={(_e, v) => set(f.attr, v)} type={f.attr === 'mail' ? 'email' : 'text'} />
            </FormGroup>
          ))}
          {kind === 'user' && (
            <>
              <FormGroup label="Password" fieldId="nug-pw">
                <TextInput id="nug-pw" type="password" autoComplete="new-password" value={pw} onChange={(_e, v) => setPw(v)} />
                <FormHelperText><HelperText><HelperTextItem>Optional: without one, the user cannot log in until a password is set.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              {pw && (
                <>
                  <FormGroup label="Password again" fieldId="nug-again">
                    <TextInput id="nug-again" type="password" autoComplete="new-password" value={again} onChange={(_e, v) => setAgain(v)}
                      validated={mismatch ? 'error' : 'default'} />
                    {mismatch && <FormHelperText><HelperText><HelperTextItem variant="error">The passwords differ.</HelperTextItem></HelperText></FormHelperText>}
                  </FormGroup>
                  <Checkbox id="nug-must" label="Must change it at the next login" isChecked={mustChange} onChange={(_e, v) => setMustChange(v)} />
                </>
              )}
            </>
          )}
          <FormGroup label={kind === 'user' ? 'Groups' : 'Members'} fieldId="nug-related">
            {related.length > 0 && (
              <LabelGroup className="dc-tab-body">
                {related.map((r) => <Label key={r.guid} onClose={() => setRelated(related.filter((x) => x.guid !== r.guid))}>{r.name}</Label>)}
              </LabelGroup>
            )}
            <ObjectPicker classes={kind === 'user' ? ['groupOfNames'] : ['inetOrgPerson', 'groupOfNames']} label={kind === 'user' ? 'Add to a group' : 'Add a member'}
              exclude={related.map((r) => r.guid)} onPick={(r) => setRelated([...related, r])} />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="nug-form" isLoading={busy} isDisabled={busy || !ready}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
