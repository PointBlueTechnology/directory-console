import { useEffect, useState } from 'react';
import {
  Alert, Button, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Label, NumberInput,
  TextInput, Title, ToggleGroup, ToggleGroupItem,
} from '@patternfly/react-core';
import { PlusIcon, TrashIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Idm, type MigrateResult, type SchemaAttribute, type SchemaClass } from '../api';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

/**
 * Migrate, on this server's copy of the driver: vault objects to the application (find them by
 * container, class and filter, preview the list, then send each with its outcome), or the
 * application's objects into the vault (a class and conditions; the engine queries the application,
 * and what it finds goes through the publisher channel).
 */
export function MigratePanel({ api, guid }: { api: Idm; guid: string }) {
  const [direction, setDirection] = useState<'to-app' | 'from-app'>('to-app');
  const { tree } = useSession();
  const [classes, setClasses] = useState<SchemaClass[]>([]);
  const [attributes, setAttributes] = useState<SchemaAttribute[]>([]);
  useEffect(() => {
    tree.classes().then((c) => setClasses(c.filter((x) => x.kind === 'structural').sort((a, b) => a.name.localeCompare(b.name)))).catch(() => undefined);
    tree.attributes().then((a) => setAttributes(a.filter((x) => !x.binary).sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
  }, [tree]);
  return (
    <div className="dc-tab-body">
      <Title headingLevel="h2" size="md">Migrate</Title>
      <ToggleGroup aria-label="Direction" className="dc-tab-body">
        <ToggleGroupItem text="Vault objects to the application" isSelected={direction === 'to-app'} onChange={() => setDirection('to-app')} />
        <ToggleGroupItem text="Application objects into the vault" isSelected={direction === 'from-app'} onChange={() => setDirection('from-app')} />
      </ToggleGroup>
      {direction === 'to-app'
        ? <ToApp api={api} guid={guid} classes={classes} />
        : <FromApp api={api} guid={guid} classes={classes} attributes={attributes} />}
    </div>
  );
}

function ToApp({ api, guid, classes }: { api: Idm; guid: string; classes: SchemaClass[] }) {
  const { tree } = useSession();
  const { run, dialog } = useConfirmed();
  const [base, setBase] = useState('');
  const [cls, setCls] = useState('inetOrgPerson');
  const [filter, setFilter] = useState('');
  const [max, setMax] = useState(100);
  const [preview, setPreview] = useState<MigrateResult | null>(null);
  const [done, setDone] = useState<MigrateResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const body = async () => ({ base: (await tree.resolve(base.trim())).data.guid, class: cls, filter: filter.trim() || undefined, max });
  const reset = () => { setPreview(null); setDone(null); };

  const look = async () => {
    setBusy(true);
    setError(null);
    reset();
    try {
      setPreview(await api.migrateToApp(guid, { ...(await body()), dryRun: true }));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      const b = await body();
      setDone(await run((c) => api.migrateToApp(guid, b, c)));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Form className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); look(); }}>
      <p className="dc-subtle">Each object found is sent to the driver as if it had just been added, so the driver matches or creates it in the application.</p>
      <FormGroup label="Container" fieldId="mig-base" isRequired>
        <TextInput id="mig-base" className="dc-mono" placeholder="ou=Users,o=acme" value={base} onChange={(_e, v) => { setBase(v); reset(); }} />
        <FormHelperText><HelperText><HelperTextItem>Its whole subtree is searched.</HelperTextItem></HelperText></FormHelperText>
      </FormGroup>
      <Flex>
        <FlexItem>
          <FormGroup label="Class" fieldId="mig-class">
            <FormSelect id="mig-class" value={cls} onChange={(_e, v) => { setCls(v); reset(); }}>
              {classes.map((c) => <FormSelectOption key={c.name} value={c.name} label={c.name} />)}
            </FormSelect>
          </FormGroup>
        </FlexItem>
        <FlexItem grow={{ default: 'grow' }}>
          <FormGroup label="Filter (optional)" fieldId="mig-filter">
            <TextInput id="mig-filter" className="dc-mono" placeholder="(department=Sales)" value={filter} onChange={(_e, v) => { setFilter(v); reset(); }} />
          </FormGroup>
        </FlexItem>
        <FlexItem>
          <FormGroup label="At most" fieldId="mig-max">
            <NumberInput id="mig-max" value={max} min={1} max={1000} onMinus={() => setMax(Math.max(1, max - 10))} onPlus={() => setMax(Math.min(1000, max + 10))}
              onChange={(e) => setMax(Math.min(1000, Math.max(1, Number((e.target as HTMLInputElement).value) || 1)))} />
          </FormGroup>
        </FlexItem>
      </Flex>
      <div><Button type="submit" variant="secondary" isLoading={busy && !preview} isDisabled={busy || !base.trim()}>Find the objects</Button></div>
      {preview && !done && (
        <>
          <Alert variant={preview.count ? 'info' : 'warning'} isInline isPlain
            title={preview.count ? `${preview.count} object${preview.count === 1 ? '' : 's'} would be sent${preview.count === max ? ` (the first ${max})` : ''}.` : 'Nothing matches.'} />
          {(preview.objects ?? []).length > 0 && (
            <ul className="dc-values dc-mono" style={{ maxHeight: '12rem', overflowY: 'auto' }}>{preview.objects!.map((d) => <li key={d}>{d}</li>)}</ul>
          )}
          {!!preview.count && <div><Button onClick={send} isLoading={busy} isDisabled={busy}>Send {preview.count} object{preview.count === 1 ? '' : 's'} to the driver</Button></div>}
        </>
      )}
      {done && (
        <>
          <Alert variant={done.failed ? 'warning' : 'success'} isInline isPlain title={`Sent ${done.sent ?? 0}: ${done.succeeded ?? 0} accepted, ${done.failed ?? 0} failed.`} />
          {(done.results ?? []).some((r) => !r.ok) && (
            <Table aria-label="Failures" variant="compact">
              <Thead><Tr><Th>Object</Th><Th>Status</Th></Tr></Thead>
              <Tbody>
                {done.results!.filter((r) => !r.ok).map((r) => (
                  <Tr key={r.dn}><Td dataLabel="Object" className="dc-mono">{r.dn}</Td><Td dataLabel="Status"><Label color="red" isCompact>{r.status}</Label></Td></Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </>
      )}
      <ProblemAlert error={error} />
      {dialog}
    </Form>
  );
}

function FromApp({ api, guid, classes, attributes }: { api: Idm; guid: string; classes: SchemaClass[]; attributes: SchemaAttribute[] }) {
  const { run, dialog } = useConfirmed();
  const [cls, setCls] = useState('inetOrgPerson');
  const [search, setSearch] = useState<{ attribute: string; value: string }[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const go = () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    run((c) => api.migrateFromApp(guid, { class: cls, search: search.filter((x) => x.attribute && x.value) }, c))
      .then(() => setNotice('Requested. The engine queries the application now; what it finds comes in through the publisher channel. Follow it in the driver\'s trace.'), setError)
      .finally(() => setBusy(false));
  };
  return (
    <Form className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); go(); }}>
      <p className="dc-subtle">The engine asks the application for its objects of this class (those matching every condition, or all of them) and brings each into the vault through the publisher channel's matching, creation and placement policies.</p>
      <FormGroup label="Class" fieldId="mig-from-class">
        <FormSelect id="mig-from-class" value={cls} onChange={(_e, v) => setCls(v)}>
          {classes.map((c) => <FormSelectOption key={c.name} value={c.name} label={c.ndsName && c.ndsName !== c.name ? `${c.name} (${c.ndsName})` : c.name} />)}
        </FormSelect>
      </FormGroup>
      <FormGroup label="Conditions (optional)" fieldId="mig-from-search">
        {search.map((x, i) => (
          <Flex key={i} className="dc-tab-body" flexWrap={{ default: 'nowrap' }}>
            <FlexItem>
              <FormSelect aria-label="Attribute" value={x.attribute} onChange={(_e, v) => setSearch(search.map((y, j) => (j === i ? { ...y, attribute: v } : y)))}>
                <FormSelectOption value="" label="Attribute" isPlaceholder />
                {attributes.map((a) => <FormSelectOption key={a.name} value={a.name} label={a.name} />)}
              </FormSelect>
            </FlexItem>
            <FlexItem>=</FlexItem>
            <FlexItem grow={{ default: 'grow' }}><TextInput aria-label="Value" value={x.value} onChange={(_e, v) => setSearch(search.map((y, j) => (j === i ? { ...y, value: v } : y)))} /></FlexItem>
            <FlexItem><Button variant="plain" aria-label="Remove the condition" onClick={() => setSearch(search.filter((_, j) => j !== i))}><TrashIcon /></Button></FlexItem>
          </Flex>
        ))}
        <Button variant="link" isInline icon={<PlusIcon />} onClick={() => setSearch([...search, { attribute: '', value: '' }])}>Add a condition</Button>
      </FormGroup>
      <div><Button type="submit" variant="secondary" isLoading={busy} isDisabled={busy}>Migrate into the vault</Button></div>
      {notice && <Alert variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {dialog}
    </Form>
  );
}
