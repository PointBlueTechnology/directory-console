import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Button, Card, CardBody, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm,
  Flex, FlexItem, Label, LabelGroup, PageSection, SearchInput, Spinner, Title, ToggleGroup, ToggleGroupItem, Tooltip,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Tr } from '@patternfly/react-table';
import { type Edir, type SchemaAttribute, type SchemaClass, edir } from '../api';
import { AddOptionalModal, NewAttributeModal, NewClassModal } from '../components/SchemaEdit';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { useSession } from '../session';
import { linkProps, navigate } from '../router';
import { ProblemAlert } from '../components/Problem';

const SYNTAXES: Record<string, string> = {
  '1.3.6.1.4.1.1466.115.121.1.15': 'Directory string',
  '1.3.6.1.4.1.1466.115.121.1.12': 'DN (reference)',
  '1.3.6.1.4.1.1466.115.121.1.27': 'Integer',
  '1.3.6.1.4.1.1466.115.121.1.7': 'Boolean',
  '1.3.6.1.4.1.1466.115.121.1.24': 'Generalized time',
  '1.3.6.1.4.1.1466.115.121.1.26': 'IA5 string',
  '1.3.6.1.4.1.1466.115.121.1.40': 'Octet string (binary)',
  '1.3.6.1.4.1.1466.115.121.1.38': 'OID',
  '1.3.6.1.4.1.1466.115.121.1.50': 'Telephone number',
  '2.16.840.1.113719.1.1.5.1.17': 'eDirectory ACL',
};

/** The directory's classes and attribute types; a whole-tree editor can add, extend and delete them. */
export function SchemaPage({ kind = 'classes', name }: { kind?: 'classes' | 'attributes'; name?: string }) {
  const { tree, me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const admin = canAt('editor', '');
  const { run, dialog: confirmDialog } = useConfirmed();
  const sure = useAreYouSure();
  const [creating, setCreating] = useState<null | 'attribute' | 'class'>(null);
  const [version, setVersion] = useState(0);
  const [classes, setClasses] = useState<SchemaClass[] | null>(null);
  const [attributes, setAttributes] = useState<SchemaAttribute[] | null>(null);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    tree.classes().then((c) => setClasses(c.sort((a, b) => a.name.localeCompare(b.name)))).catch(setError);
    tree.attributes().then((a) => setAttributes(a.sort((x, y) => x.name.localeCompare(y.name)))).catch(setError);
  }, [tree, version]);
  const changed = useCallback((to?: string) => { setVersion((v) => v + 1); if (to) { navigate(to); } }, []);
  const remove = (what: 'class' | 'attribute', n: string) => sure.ask(`Delete the ${what} ${n}?`,
    `eDirectory refuses to delete a ${what} that is in use${what === 'class' ? ' by an object' : ' by a class or an object'}.`, 'Delete', async () => {
      setError(null);
      try {
        await run((c) => (what === 'class' ? api.removeClass(n, c) : api.removeAttribute(n, c)));
        changed(what === 'class' ? '/schema' : '/schema/attributes/cn');
      } catch (x) {
        setError(x);
      }
    });

  const f = filter.toLowerCase();
  const shownClasses = useMemo(() => (classes ?? []).filter((c) => c.names.some((n) => n.toLowerCase().includes(f)) || (c.ndsName ?? '').toLowerCase().includes(f)), [classes, f]);
  const shownAttributes = useMemo(() => (attributes ?? []).filter((a) => a.names.some((n) => n.toLowerCase().includes(f)) || (a.ndsName ?? '').toLowerCase().includes(f)), [attributes, f]);

  return (
    <PageSection isFilled>
      <Flex justifyContent={{ default: 'justifyContentSpaceBetween' }} alignItems={{ default: 'alignItemsCenter' }}>
        <FlexItem><Title headingLevel="h1">Schema</Title></FlexItem>
        {admin && (
          <FlexItem>
            <Button variant="secondary" onClick={() => setCreating('attribute')}>New attribute</Button>{' '}
            <Button variant="secondary" onClick={() => setCreating('class')}>New class</Button>
          </FlexItem>
        )}
      </Flex>
      <ProblemAlert error={error} />
      <div className="dc-browser">
        <Card isCompact>
          <CardBody>
            <ToggleGroup aria-label="Show">
              <ToggleGroupItem text={`Classes${classes ? ` (${classes.length})` : ''}`} isSelected={kind === 'classes'} onChange={() => navigate('/schema')} />
              <ToggleGroupItem text={`Attributes${attributes ? ` (${attributes.length})` : ''}`} isSelected={kind === 'attributes'}
                onChange={() => navigate('/schema/attributes/' + encodeURIComponent(attributes?.[0]?.name ?? 'cn'))} />
            </ToggleGroup>
            <SearchInput className="dc-tab-body" placeholder="Filter by name" aria-label="Filter by name" value={filter}
              onChange={(_e, v) => setFilter(v)} onClear={() => setFilter('')} />
            <div className="dc-tree">
              {(kind === 'classes' ? classes : attributes) === null && <Spinner aria-label="Loading the schema" />}
              <Table aria-label={kind === 'classes' ? 'Classes' : 'Attributes'} variant="compact">
                <Tbody>
                  {(kind === 'classes' ? shownClasses : shownAttributes).map((x) => (
                    <Tr key={x.oid} isClickable isRowSelected={x.name === name} onRowClick={() => navigate(`/schema/${kind}/${encodeURIComponent(x.name)}`)}>
                      <Td>{x.name}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </div>
          </CardBody>
        </Card>
        <Card isCompact>
          <CardBody>
            {!name && <Title headingLevel="h2">Choose a {kind === 'classes' ? 'class' : 'attribute'}</Title>}
            {name && kind === 'classes' && <ClassDetails key={`${name}-${version}`} name={name} admin={admin} api={api} run={run} onChanged={() => changed()} onDelete={() => remove('class', name)} />}
            {name && kind === 'attributes' && attributes && <AttributeDetails a={attributes.find((a) => a.names.some((n) => n.toLowerCase() === name.toLowerCase()))}
              classes={classes ?? []} onDelete={admin ? () => remove('attribute', name) : undefined} />}
          </CardBody>
        </Card>
      </div>
      {creating === 'attribute' && <NewAttributeModal api={api} run={run} onClose={() => setCreating(null)} onDone={(n) => { setCreating(null); changed(`/schema/attributes/${encodeURIComponent(n)}`); }} />}
      {creating === 'class' && <NewClassModal api={api} run={run} onClose={() => setCreating(null)} onDone={(n) => { setCreating(null); changed(`/schema/classes/${encodeURIComponent(n)}`); }} />}
      {confirmDialog}
      {sure.dialog}
    </PageSection>
  );
}

function ClassDetails({ name, admin, api, run, onChanged, onDelete }: {
  name: string; admin: boolean; api: Edir; run: (op: (c?: string) => Promise<unknown>) => Promise<unknown>; onChanged: () => void; onDelete: () => void;
}) {
  const { tree } = useSession();
  const [adding, setAdding] = useState(false);
  const [c, setC] = useState<SchemaClass | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    setC(null);
    tree.schemaClass(name).then(setC).catch(setError);
  }, [tree, name]);
  if (error) {
    return <ProblemAlert error={error} />;
  }
  if (!c) {
    return <Spinner aria-label="Loading" />;
  }
  return (
    <>
      <Title headingLevel="h2">{c.name}</Title>
      <LabelGroup>
        <Label color="blue">{c.kind}</Label>
        <Label>{c.container ? 'container' : 'leaf'}</Label>
        <FlagLabels flags={c.ndsFlags} />
      </LabelGroup>
      <DescriptionList isHorizontal className="dc-tab-body">
        <Item term="OID" value={<span className="dc-mono">{c.oid}</span>} />
        {c.names.length > 1 && <Item term="Also called" value={c.names.slice(1).join(', ')} />}
        {c.ndsName && <Item term="eDirectory name" value={c.ndsName} />}
        <Item term="Inherits from" value={<Links kind="classes" names={c.superiors} />} />
        <Item term="Named by" value={c.naming.join(', ') || '—'} />
        <Item term="Can be created in" value={<Links kind="classes" names={c.containment} />} />
        <Item term="Required" value={<Links kind="attributes" names={c.allMust ?? c.must} />} />
        <Item term="Optional" value={<Links kind="attributes" names={c.allMay ?? c.may} />} />
      </DescriptionList>
      {admin && (
        <div className="dc-tab-body">
          <Button variant="secondary" onClick={() => setAdding(true)}>Add optional attributes</Button>{' '}
          <DeleteButton what="class" removable={c.removable !== false} onDelete={onDelete} />
        </div>
      )}
      {adding && <AddOptionalModal api={api} run={run} cls={c.name} onClose={() => setAdding(false)} onDone={() => { setAdding(false); onChanged(); }} />}
    </>
  );
}

/** eDirectory's attribute and class flags, as its tools name them; NOT_CONTAINER and NEVER_SYNC are shown elsewhere. */
const FLAGS: Record<string, string> = {
  'X-NDS_NONREMOVABLE': 'base schema',
  'X-NDS_PUBLIC_READ': 'public read',
  'X-NDS_SERVER_READ': 'server read',
  'X-NDS_PER_REPLICA': 'per replica',
  'X-NDS_HIDDEN': 'hidden',
  'X-NDS_NAME_VALUE_ACCESS': 'write managed',
  'X-NDS_SCHED_SYNC_NEVER': 'never schedules synchronization',
  'X-NDS_NOT_SCHED_SYNC_IMMEDIATE': 'not synchronized immediately',
  'X-NDS_FILTERED_REQUIRED': 'always in filtered replicas',
  'X-NDS_READ_FILTERED': 'read filtered',
  'X-NDS_OPERATIONAL': 'operational',
  'X-NDS_FILTERED_OPERATIONAL': 'filtered operational',
  'X-NDS_AMBIGUOUS_NAMING': 'ambiguous naming',
};
const SHOWN_ELSEWHERE = new Set(['X-NDS_NOT_CONTAINER', 'X-NDS_NEVER_SYNC', 'X-NDS_AMBIGUOUS_CONTAINMENT']);

function FlagLabels({ flags }: { flags?: string[] }) {
  return <>{(flags ?? []).filter((f) => !SHOWN_ELSEWHERE.has(f)).map((f) => (
    <Label key={f} color={f === 'X-NDS_NONREMOVABLE' ? 'grey' : undefined}>{FLAGS[f] ?? f.replace(/^X-NDS_/, '').toLowerCase().replace(/_/g, ' ')}</Label>
  ))}</>;
}

/** eDirectory refuses to delete base schema: say so rather than offer it. */
function DeleteButton({ what, removable, onDelete }: { what: 'class' | 'attribute'; removable: boolean; onDelete: () => void }) {
  if (removable) {
    return <Button variant="link" isDanger onClick={onDelete}>Delete the {what}</Button>;
  }
  return (
    <Tooltip content={`The ${what} is part of eDirectory's base schema, which cannot be deleted.`}>
      <Button variant="link" isDanger isAriaDisabled>Delete the {what}</Button>
    </Tooltip>
  );
}

function AttributeDetails({ a, classes, onDelete }: { a?: SchemaAttribute; classes: SchemaClass[]; onDelete?: () => void }) {
  if (!a) {
    return <Title headingLevel="h2">No such attribute</Title>;
  }
  return (
    <>
      <Title headingLevel="h2">{a.name}</Title>
      <LabelGroup>
        {a.singleValue && <Label>single value</Label>}
        {a.readOnly && <Label color="orange">maintained by the directory</Label>}
        {a.operational && <Label>operational</Label>}
        {a.binary && <Label>binary</Label>}
        {a.perReplica && <Label>never synchronized</Label>}
        <FlagLabels flags={a.ndsFlags} />
      </LabelGroup>
      <DescriptionList isHorizontal className="dc-tab-body">
        <Item term="OID" value={<span className="dc-mono">{a.oid}</span>} />
        {a.names.length > 1 && <Item term="Also called" value={a.names.slice(1).join(', ')} />}
        {a.ndsName && <Item term="eDirectory name" value={a.ndsName} />}
        <Item term="Syntax" value={<>{SYNTAXES[a.syntax] ?? 'Other'} <span className="dc-mono dc-subtle">{a.syntax}</span></>} />
        <Item term="Required by" value={<Links kind="classes" names={usedBy(classes, a, 'must')} />} />
        <Item term="Optional for" value={<Links kind="classes" names={usedBy(classes, a, 'may')} />} />
      </DescriptionList>
      {onDelete && <div className="dc-tab-body"><DeleteButton what="attribute" removable={a.removable !== false} onDelete={onDelete} /></div>}
    </>
  );
}

function Item({ term, value }: { term: string; value: React.ReactNode }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>{value}</DescriptionListDescription>
    </DescriptionListGroup>
  );
}

function Links({ kind, names }: { kind: 'classes' | 'attributes'; names: string[] }) {
  if (names.length === 0) {
    return <>—</>;
  }
  return (
    <>
      {names.map((n, i) => (
        <span key={n}>{i > 0 && ', '}<Button variant="link" isInline component="a" {...linkProps(`/schema/${kind}/${encodeURIComponent(n)}`)}>{n}</Button></span>
      ))}
    </>
  );
}

/** The classes that name this attribute themselves (not through a superior class). */
function usedBy(classes: SchemaClass[], a: SchemaAttribute, list: 'must' | 'may'): string[] {
  const names = new Set(a.names.map((n) => n.toLowerCase()));
  return classes.filter((c) => c[list].some((n) => names.has(n.toLowerCase()))).map((c) => c.name);
}
