import { useEffect, useState } from 'react';
import {
  ActionGroup, Button, Card, CardBody, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, FormSelect,
  FormSelectOption, FormSelectOptionGroup, HelperText, HelperTextItem, PageSection, Pagination, Spinner, Switch, TextArea, TextInput, Title,
  ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { MinusCircleIcon, PlusCircleIcon } from '@patternfly/react-icons';
import type { DirObject, Page, Row, SchemaAttribute, SchemaClass, SearchRequest } from '../api';
import { useSession } from '../session';
import { navigate, useLocation } from '../router';
import { type Condition, OPS, toFilter } from '../filters';
import { ObjectDrawer } from '../components/ObjectDrawer';
import { RowsTable } from '../components/RowsTable';
import { ProblemAlert } from '../components/Problem';

const EMPTY: Condition = { attribute: 'cn', op: 'prefix', value: '' };

/** A structured search: conditions on attributes, never filter text (unless the advanced filter is chosen). */
export function Search() {
  const { tree } = useSession();
  const { query } = useLocation();
  const selected = query.get('object');
  const [classes, setClasses] = useState<SchemaClass[]>([]);
  const [attributes, setAttributes] = useState<SchemaAttribute[]>([]);
  const [base, setBase] = useState('');
  const [scope, setScope] = useState<'subtree' | 'one'>('subtree');
  const [objectClass, setObjectClass] = useState('inetOrgPerson');
  const [conditions, setConditions] = useState<Condition[]>([{ ...EMPTY }]);
  const [join, setJoin] = useState<'and' | 'or'>('and');
  const [advanced, setAdvanced] = useState(false);
  const [ldapFilter, setLdapFilter] = useState('');
  const [sort, setSort] = useState('cn');
  const [request, setRequest] = useState<SearchRequest | null>(null);
  const [pageNo, setPageNo] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [result, setResult] = useState<Page<Row | DirObject> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    tree.classes().then((c) => setClasses(c.filter((x) => x.kind !== 'abstract').sort((a, b) => a.name.localeCompare(b.name)))).catch(() => undefined);
    tree.attributes().then((a) => setAttributes(a.filter((x) => !x.binary).sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
  }, [tree]);

  useEffect(() => {
    if (!request) {
      return;
    }
    setBusy(true);
    setError(null);
    tree.search({ ...request, page: { offset: (pageNo - 1) * perPage + 1, count: perPage } })
      .then(setResult).catch((e) => { setResult(null); setError(e); }).finally(() => setBusy(false));
  }, [tree, request, pageNo, perPage]);

  const run = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const r: SearchRequest = { scope, sort: { attribute: sort.trim() || 'cn' } };
      if (base.trim()) {
        r.base = { dn: base.trim() };
      }
      if (advanced) {
        r.ldapFilter = ldapFilter.trim();
      } else {
        r.filter = toFilter(conditions, join, objectClass || undefined);
      }
      setPageNo(1);
      setRequest(r);
    } catch (x) {
      setError(x);
    }
  };

  const set = (i: number, c: Partial<Condition>) => setConditions(conditions.map((x, j) => (i === j ? { ...x, ...c } : x)));
  const total = result ? (result.total >= 0 ? result.total : result.offset - 1 + result.count + (result.count === perPage ? 1 : 0)) : 0;

  return (
    <PageSection isFilled padding={{ default: 'noPadding' }}>
      <ObjectDrawer guid={selected} onClose={() => navigate('/search')} onChanged={(o) => { if (!o) { navigate('/search'); } if (request) { setRequest({ ...request }); } }}>
      <div className="dc-page">
      <Title headingLevel="h1">Search</Title>
      <Card isCompact>
        <CardBody>
          <Form onSubmit={run} isWidthLimited>
            <datalist id="attribute-names">{attributes.map((a) => <option key={a.name} value={a.name} />)}</datalist>
            <FormGroup label="Search under" fieldId="base">
              <TextInput id="base" value={base} onChange={(_e, v) => setBase(v)} placeholder="the whole tree, or a DN such as ou=users,o=acme" />
            </FormGroup>
            <FormGroup label="Depth" fieldId="scope" role="radiogroup" isInline>
              <ToggleGroup aria-label="Depth">
                <ToggleGroupItem text="Everything below" isSelected={scope === 'subtree'} onChange={() => setScope('subtree')} />
                <ToggleGroupItem text="Directly inside" isSelected={scope === 'one'} onChange={() => setScope('one')} />
              </ToggleGroup>
            </FormGroup>
            <Switch id="advanced" label="Write an LDAP filter instead" isChecked={advanced} onChange={(_e, v) => setAdvanced(v)} />
            {advanced
              ? (
                <FormGroup label="LDAP filter" fieldId="ldap" isRequired>
                  <TextArea id="ldap" value={ldapFilter} onChange={(_e, v) => setLdapFilter(v)} rows={3} className="dc-mono" placeholder="(&(objectClass=inetOrgPerson)(cn=smith*))" />
                  <FormHelperText><HelperText><HelperTextItem>One parenthesized filter. Escape special characters in values yourself (\28 for a parenthesis).</HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
              )
              : (
                <>
                  <FormGroup label="Class" fieldId="class">
                    <FormSelect id="class" value={objectClass} onChange={(_e, v) => setObjectClass(v)}>
                      <FormSelectOption value="" label="Any class" />
                      <FormSelectOptionGroup label="Object classes">
                        {classes.filter((c) => c.kind === 'structural').map((c) => <FormSelectOption key={c.name} value={c.name} label={c.name} />)}
                      </FormSelectOptionGroup>
                      {/* an auxiliary class is in an object's objectClass once added to it, so it can be searched on */}
                      <FormSelectOptionGroup label="Auxiliary classes">
                        {classes.filter((c) => c.kind === 'auxiliary').map((c) => <FormSelectOption key={c.name} value={c.name} label={c.name} />)}
                      </FormSelectOptionGroup>
                    </FormSelect>
                  </FormGroup>
                  <FormGroup label="Where" fieldId="cond-0-attr">
                    <ToggleGroup aria-label="Match" isCompact>
                      <ToggleGroupItem text="All of these" isSelected={join === 'and'} onChange={() => setJoin('and')} />
                      <ToggleGroupItem text="Any of these" isSelected={join === 'or'} onChange={() => setJoin('or')} />
                    </ToggleGroup>
                    {conditions.map((c, i) => {
                      const needs = OPS.find((o) => o.op === c.op)?.needsValue;
                      return (
                        <div key={i} className="dc-filter-row dc-tab-body">
                          <TextInput id={`cond-${i}-attr`} aria-label="Attribute" list="attribute-names" value={c.attribute} onChange={(_e, v) => set(i, { attribute: v })} />
                          <FormSelect aria-label="Test" value={c.op} onChange={(_e, v) => set(i, { op: v as Condition['op'] })}>
                            {OPS.map((o) => <FormSelectOption key={o.op} value={o.op} label={o.label} />)}
                          </FormSelect>
                          <TextInput aria-label="Value" value={c.value} isDisabled={!needs} onChange={(_e, v) => set(i, { value: v })} />
                          <Button variant="plain" aria-label="Remove this condition" icon={<MinusCircleIcon />} isDisabled={conditions.length === 1}
                            onClick={() => setConditions(conditions.filter((_x, j) => j !== i))} />
                        </div>
                      );
                    })}
                    <Button variant="link" icon={<PlusCircleIcon />} onClick={() => setConditions([...conditions, { ...EMPTY, attribute: '' }])}>Add a condition</Button>
                  </FormGroup>
                </>
              )}
            <FormGroup label="Sort by" fieldId="sort">
              <TextInput id="sort" list="attribute-names" value={sort} onChange={(_e, v) => setSort(v)} />
            </FormGroup>
            <ActionGroup>
              <Button type="submit" variant="primary" isLoading={busy}>Search</Button>
            </ActionGroup>
          </Form>
        </CardBody>
      </Card>
      <ProblemAlert error={error} />
      {request && (
        <Card isCompact className="dc-tab-body">
            <CardBody>
              <Toolbar>
                <ToolbarContent>
                  <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
                    <Pagination itemCount={total} page={pageNo} perPage={perPage} isCompact
                      onSetPage={(_e, p) => setPageNo(p)} onPerPageSelect={(_e, pp) => { setPerPage(pp); setPageNo(1); }}
                      toggleTemplate={result && !result.exact ? ({ firstIndex, lastIndex }) => <>{firstIndex}-{lastIndex} of about {total}</> : undefined} />
                  </ToolbarItem>
                </ToolbarContent>
              </Toolbar>
              {busy && !result && <Spinner aria-label="Searching" />}
              {result && result.items.length === 0 && <EmptyState titleText="No matches" headingLevel="h2"><EmptyStateBody>Nothing matched. Check the class and conditions.</EmptyStateBody></EmptyState>}
              {result && result.items.length > 0 && (
                <RowsTable narrow={!!selected} label="Results" rows={result.items} selected={selected}
                  onOpen={(r) => navigate(`/browse/${r.guid}`)} onDetails={(r) => navigate(`/search?object=${r.guid}`)} />
              )}
            </CardBody>
        </Card>
      )}
      </div>
      </ObjectDrawer>
    </PageSection>
  );
}
