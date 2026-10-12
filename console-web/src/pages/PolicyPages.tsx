import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActionGroup, Alert, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, CardTitle, Checkbox, Form, FormGroup, FormSection, FormSelect, FormSelectOption,
  Grid, GridItem, PageSection, Spinner, Switch, TextArea, TextInput, Title,
} from '@patternfly/react-core';
import { TrashIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type ChallengeSet, type PasswordPolicy, type PolicyOptions, type PolicyRules, type Question, security } from '../api';
import { useSession } from '../session';
import { linkProps, navigate } from '../router';
import { useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { ObjectPicker } from '../components/ObjectPicker';
import { useAreYouSure, useConfirmed } from '../components/Confirm';

type Kind = 'int' | 'bool' | 'list' | 'text';
const GROUPS: { title: string; fields: [string, string, Kind][] }[] = [
  { title: 'Length', fields: [['minLength', 'Minimum length', 'int'], ['maxLength', 'Maximum length', 'int'], ['minUnique', 'Minimum unique characters', 'int'],
    ['maxRepeated', 'Most repeats of one character', 'int'], ['maxConsecutive', 'Most consecutive identical characters', 'int']] },
  { title: 'Characters', fields: [['caseSensitive', 'Case sensitive', 'bool'], ['minUpper', 'Minimum upper case', 'int'], ['maxUpper', 'Maximum upper case', 'int'],
    ['minLower', 'Minimum lower case', 'int'], ['maxLower', 'Maximum lower case', 'int'],
    ['numericAllowed', 'Digits allowed', 'bool'], ['numericFirst', 'Digit may be first', 'bool'], ['numericLast', 'Digit may be last', 'bool'],
    ['minNumeric', 'Minimum digits', 'int'], ['maxNumeric', 'Maximum digits', 'int'],
    ['specialAllowed', 'Special characters allowed', 'bool'], ['specialFirst', 'Special may be first', 'bool'], ['specialLast', 'Special may be last', 'bool'],
    ['minSpecial', 'Minimum special characters', 'int'], ['maxSpecial', 'Maximum special characters', 'int']] },
  { title: 'Change and expiry', fields: [['allowChange', 'Users may change their password', 'bool'], ['expirationDays', 'Expires after (days)', 'int'],
    ['graceLogins', 'Grace logins', 'int'], ['minLifetimeHours', 'Minimum lifetime (hours)', 'int'], ['adminsDoNotExpire', 'An admin-set password does not expire', 'bool'],
    ['uniqueRequired', 'New passwords must be unique', 'bool'], ['historyLimit', 'Passwords remembered', 'int'], ['historyExpirationDays', 'Remembered for (days)', 'int']] },
  { title: 'Other', fields: [['excludeList', 'Words not allowed (one per line)', 'list'], ['disallowedAttributes', 'Attributes whose values are not allowed (one per line)', 'list'],
    ['changeMessage', 'Message shown when changing', 'text'], ['verifyExisting', 'Check existing passwords against the rules at login', 'bool']] },
];

const OPTION_LABELS: [keyof PolicyOptions, string][] = [
  ['universalPassword', 'Universal Password'], ['advancedRules', 'Advanced password rules'], ['syncNds', 'Synchronize the NDS password'],
  ['syncSimple', 'Synchronize the simple password'], ['syncDistribution', 'Synchronize the distribution password (Identity Manager)'],
  ['removeNds', 'Remove the NDS password'], ['userRetrieve', 'Users may retrieve their password'], ['adminRetrieve', 'Administrators may retrieve passwords'],
];

/** One password policy: options, rules, challenge set, assignments. */
export function PasswordPolicyPage({ guid }: { guid: string }) {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const edit = canAt('editor', '');
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const level = useHeading();
  const [p, setP] = useState<PasswordPolicy | null>(null);
  const [rules, setRules] = useState<PolicyRules>({});
  const [options, setOptions] = useState<PolicyOptions | null>(null);
  const [description, setDescription] = useState('');
  const [challengeSet, setChallengeSet] = useState<string>('');
  const [sets, setSets] = useState<{ guid?: string | null; name: string }[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const show = (x: PasswordPolicy) => {
    setP(x);
    setRules(x.rules);
    setOptions(x.options);
    setDescription(x.description ?? '');
    setChallengeSet(x.challengeSet?.guid ?? '');
  };
  const load = useCallback(() => { api.policy(guid).then(show).catch(setError); }, [api, guid]);
  useEffect(load, [load]);
  useEffect(() => { api.challengeSets().then(setSets).catch(() => setSets([])); }, [api]);

  if (!p || !options) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the policy" />}</PageSection>;
  }
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const changed: PolicyRules = {};
      Object.entries(rules).forEach(([k, v]) => { if (JSON.stringify(v) !== JSON.stringify(p.rules[k])) { changed[k] = v; } });
      show(await run((c) => api.updatePolicy(guid, { description, rules: changed, options, challengeSet: challengeSet || null }, c)));
      setNotice('Saved.');
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  const remove = () => sure.ask(`Delete ${p.name}?`, p.assignments.length
    ? `It is assigned to ${p.assignments.length} object(s); deleting it unassigns them, and they fall back to whatever applies above them.`
    : 'Nothing is assigned this policy.', 'Delete', async () => {
    try {
      await run((c) => api.deletePolicy(guid, p.assignments.length, c));
      navigate('/security/password-policies');
    } catch (x) {
      setError(x);
    }
  });
  const field = ([k, label, kind]: [string, string, Kind]) => {
    const v = rules[k];
    const id = `rule-${k}`;
    if (kind === 'bool') {
      return <Checkbox key={k} id={id} label={label} isChecked={v === true} isDisabled={!edit} onChange={(_e, on) => setRules({ ...rules, [k]: on })} />;
    }
    if (kind === 'list') {
      return (
        <FormGroup key={k} label={label} fieldId={id}>
          <TextArea id={id} value={Array.isArray(v) ? v.join('\n') : ''} isDisabled={!edit} resizeOrientation="vertical"
            onChange={(_e, t) => setRules({ ...rules, [k]: t.split('\n').map((x) => x.trim()).filter(Boolean) })} />
        </FormGroup>
      );
    }
    return (
      <FormGroup key={k} label={label} fieldId={id}>
        <TextInput id={id} type={kind === 'int' ? 'number' : 'text'} value={v === null || v === undefined ? '' : String(v)} isDisabled={!edit}
          onChange={(_e, t) => setRules({ ...rules, [k]: t === '' ? null : kind === 'int' ? Number(t) : t })} />
      </FormGroup>
    );
  };

  return (
    <PageSection isFilled>
      <Breadcrumb>
        <BreadcrumbItem><a {...linkProps('/security/password-policies')}>Password policies</a></BreadcrumbItem>
        <BreadcrumbItem isActive>{p.name}</BreadcrumbItem>
      </Breadcrumb>
      <Title headingLevel="h1" className="dc-tab-body">{p.name}</Title>
      <Form onSubmit={save} className="dc-tab-body">
        <FormGroup label="Description" fieldId="policy-description">
          <TextInput id="policy-description" value={description} onChange={(_e, v) => setDescription(v)} isDisabled={!edit} />
        </FormGroup>
        <FormSection title="Universal Password" titleElement="h2">
          <Grid hasGutter md={6}>
            {OPTION_LABELS.map(([k, label]) => (
              <GridItem key={k}><Switch id={`opt-${k}`} label={label} isChecked={options[k]} isDisabled={!edit || (k !== 'universalPassword' && !options.universalPassword)}
                onChange={(_e, on) => setOptions({ ...options, [k]: on })} /></GridItem>
            ))}
          </Grid>
        </FormSection>
        {GROUPS.map((g) => (
          <FormSection key={g.title} title={g.title} titleElement="h2">
            <Grid hasGutter md={6}>{g.fields.map((f) => <GridItem key={f[0]}>{field(f)}</GridItem>)}</Grid>
          </FormSection>
        ))}
        <FormSection title="Forgotten password" titleElement="h2">
          <FormGroup label="Challenge set" fieldId="policy-challenge">
            <FormSelect id="policy-challenge" value={challengeSet} onChange={(_e, v) => setChallengeSet(v)} isDisabled={!edit}>
              <FormSelectOption value="" label="None" />
              {sets.map((s) => <FormSelectOption key={s.guid ?? s.name} value={s.guid ?? ''} label={s.name} />)}
            </FormSelect>
          </FormGroup>
          <p className="dc-subtle">Forgotten password {p.forgotten.enabled ? `is on${p.forgotten.action ? ` (${p.forgotten.action})` : ''}` : 'is off'}.</p>
        </FormSection>
        {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
        <ProblemAlert error={error} />
        {edit && (
          <ActionGroup>
            <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy}>Save</Button>
            <Button variant="link" onClick={() => show(p)}>Discard changes</Button>
            <Button variant="danger" onClick={remove}>Delete the policy</Button>
          </ActionGroup>
        )}
      </Form>
      <Assignments api={api} p={p} edit={edit} run={run} onChanged={show} />
      {dialog}
      {sure.dialog}
    </PageSection>
  );
}

function Assignments({ api, p, edit, run, onChanged }: {
  api: ReturnType<typeof security>; p: PasswordPolicy; edit: boolean; run: <T>(op: (c?: string) => Promise<T>) => Promise<T>; onChanged: (p: PasswordPolicy) => void;
}) {
  const [error, setError] = useState<unknown>(null);
  const act = async (op: (c?: string) => Promise<PasswordPolicy>) => {
    setError(null);
    try {
      onChanged(await run(op));
    } catch (x) {
      if (!(x instanceof ApiError && x.code === 'cancelled')) {
        setError(x);
      }
    }
  };
  return (
    <Card className="dc-tab-body">
      <CardTitle><Title headingLevel="h2" size="lg">Assigned to</Title></CardTitle>
      <CardBody>
        {p.assignments.length === 0 ? <p>Nothing yet.</p> : (
          <Table aria-label="Assignments" variant="compact">
            <Thead><Tr><Th>Object</Th><Th>DN</Th>{edit && <Th screenReaderText="Remove" />}</Tr></Thead>
            <Tbody>
              {p.assignments.map((a) => (
                <Tr key={a.dn}>
                  <Td dataLabel="Object">{a.guid ? <a {...linkProps(`/objects/${a.guid}`)}>{a.name}</a> : a.name}</Td>
                  <Td dataLabel="DN" className="dc-mono">{a.dn}</Td>
                  {edit && <Td isActionCell>{a.guid && <Button variant="plain" aria-label={`Unassign ${a.name}`} icon={<TrashIcon />}
                    onClick={() => act((c) => api.unassign(p.guid!, a.guid!, c))} />}</Td>}
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
        {edit && (
          <div className="dc-tab-body">
            <ObjectPicker label="Assign to a container or user" onPick={(r) => act((c) => api.assign(p.guid!, r.guid!, c))}
              exclude={p.assignments.map((a) => a.guid ?? '')} />
            <p className="dc-subtle">Assigning writes both sides (the object's policy and this policy's list). An object assigned another policy moves to this one.</p>
          </div>
        )}
        <ProblemAlert error={error} />
      </CardBody>
    </Card>
  );
}

/** One challenge set: required and random questions, administrator-written or user-defined. */
export function ChallengeSetPage({ guid }: { guid: string }) {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const edit = canAt('editor', '');
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const level = useHeading();
  const [s, setS] = useState<ChallengeSet | null>(null);
  const [draft, setDraft] = useState<ChallengeSet | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const load = useCallback(() => { api.challengeSet(guid).then((x) => { setS(x); setDraft(x); }).catch(setError); }, [api, guid]);
  useEffect(load, [load]);
  if (!s || !draft) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading" />}</PageSection>;
  }
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const x = await run((c) => api.updateChallengeSet(guid, { description: draft.description ?? null, required: draft.required, random: draft.random,
        randomCount: Math.min(draft.randomCount, draft.random.length), minResponse: draft.minResponse ?? null, maxResponse: draft.maxResponse ?? null } as Partial<ChallengeSet>, c));
      setS(x);
      setDraft(x);
      setNotice('Saved.');
    } catch (x) {
      setError(x);
    }
  };
  return (
    <PageSection isFilled>
      <Breadcrumb>
        <BreadcrumbItem><a {...linkProps('/security/challenge-sets')}>Challenge sets</a></BreadcrumbItem>
        <BreadcrumbItem isActive>{s.name}</BreadcrumbItem>
      </Breadcrumb>
      <Title headingLevel="h1" className="dc-tab-body">{s.name}</Title>
      <Form onSubmit={save} className="dc-tab-body">
        <FormGroup label="Description" fieldId="set-description">
          <TextInput id="set-description" value={draft.description ?? ''} onChange={(_e, v) => setDraft({ ...draft, description: v })} isDisabled={!edit} />
        </FormGroup>
        <QuestionsEditor title="Required questions" questions={draft.required} edit={edit} onChange={(q) => setDraft({ ...draft, required: q })} />
        <QuestionsEditor title="Random questions" questions={draft.random} edit={edit} onChange={(q) => setDraft({ ...draft, random: q })} />
        <Grid hasGutter md={4}>
          <GridItem><FormGroup label="Random questions asked" fieldId="set-random-count">
            <TextInput id="set-random-count" type="number" value={String(draft.randomCount)} isDisabled={!edit}
              onChange={(_e, v) => setDraft({ ...draft, randomCount: Math.max(0, Number(v) || 0) })} />
          </FormGroup></GridItem>
          <GridItem><FormGroup label="Shortest answer" fieldId="set-min">
            <TextInput id="set-min" type="number" value={draft.minResponse == null ? '' : String(draft.minResponse)} isDisabled={!edit}
              onChange={(_e, v) => setDraft({ ...draft, minResponse: v === '' ? null : Number(v) })} />
          </FormGroup></GridItem>
          <GridItem><FormGroup label="Longest answer" fieldId="set-max">
            <TextInput id="set-max" type="number" value={draft.maxResponse == null ? '' : String(draft.maxResponse)} isDisabled={!edit}
              onChange={(_e, v) => setDraft({ ...draft, maxResponse: v === '' ? null : Number(v) })} />
          </FormGroup></GridItem>
        </Grid>
        {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
        <ProblemAlert error={error} />
        {edit && (
          <ActionGroup>
            <Button type="submit" variant="primary">Save</Button>
            <Button variant="link" onClick={() => setDraft(s)}>Discard changes</Button>
            <Button variant="danger" onClick={() => sure.ask(`Delete ${s.name}?`, 'A challenge set that a password policy uses is not deleted.', 'Delete', async () => {
              try {
                await run((c) => api.deleteChallengeSet(guid, c));
                navigate('/security/challenge-sets');
              } catch (x) {
                setError(x);
              }
            })}>Delete the challenge set</Button>
          </ActionGroup>
        )}
      </Form>
      {dialog}
      {sure.dialog}
    </PageSection>
  );
}

function QuestionsEditor({ title, questions, edit, onChange }: { title: string; questions: Question[]; edit: boolean; onChange: (q: Question[]) => void }) {
  const set = (i: number, q: Partial<Question>) => onChange(questions.map((x, j) => (j === i ? { ...x, ...q } : x)));
  return (
    <FormSection title={title} titleElement="h2">
      {questions.length === 0 ? <p className="dc-subtle">None.</p> : (
        <Table aria-label={title} variant="compact">
          <Thead><Tr><Th>Question</Th><Th>Shortest answer</Th><Th>Longest answer</Th>{edit && <Th screenReaderText="Remove" />}</Tr></Thead>
          <Tbody>
            {questions.map((q, i) => (
              <Tr key={i}>
                <Td dataLabel="Question">
                  {q.kind === 'user' ? <em>The user writes their own question</em>
                    : <TextInput aria-label={`${title} ${i + 1}`} value={q.text ?? ''} isDisabled={!edit} onChange={(_e, v) => set(i, { text: v })} />}
                </Td>
                <Td dataLabel="Shortest answer"><TextInput aria-label={`${title} ${i + 1} shortest answer`} type="number" value={String(q.min ?? '')} isDisabled={!edit}
                  onChange={(_e, v) => set(i, { min: Number(v) || 1 })} /></Td>
                <Td dataLabel="Longest answer"><TextInput aria-label={`${title} ${i + 1} longest answer`} type="number" value={String(q.max ?? '')} isDisabled={!edit}
                  onChange={(_e, v) => set(i, { max: Number(v) || 255 })} /></Td>
                {edit && <Td isActionCell><Button variant="plain" aria-label={`Remove ${title.toLowerCase()} ${i + 1}`} icon={<TrashIcon />}
                  onClick={() => onChange(questions.filter((_x, j) => j !== i))} /></Td>}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {edit && (
        <div>
          <Button variant="link" onClick={() => onChange([...questions, { kind: 'admin', text: '', min: 2, max: 255 }])}>Add a question</Button>{' '}
          <Button variant="link" onClick={() => onChange([...questions, { kind: 'user', min: 2, max: 255 }])}>Add a user-defined question</Button>
        </div>
      )}
    </FormSection>
  );
}
