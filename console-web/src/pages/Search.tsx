import { useEffect, useRef, useState } from 'react';
import {
  ActionGroup, Button, Card, CardBody, Dropdown, DropdownGroup, DropdownItem, DropdownList, EmptyState, EmptyStateBody, Flex, FlexItem, Form,
  FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Label, MenuToggle, PageSection, Pagination,
  Spinner, Tab, TabTitleText, Tabs, TextArea, TextInput, Title, ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { DownloadIcon, HistoryIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type DirObject, type Filter, type Page, type Row, type SchemaAttribute, type SchemaClass, type SearchRequest } from '../api';
import { useSession } from '../session';
import { navigate, useLocation } from '../router';
import { type FilterNode, attributeAt, checkFilter, classAt, fromText, newGroup, toStructured, toText } from '../filterTree';
import { ObjectDrawer } from '../components/ObjectDrawer';
import { RowsTable } from '../components/RowsTable';
import { ProblemAlert } from '../components/Problem';
import { BrowseContainers } from '../components/ContainerChooser';
import { FilterBuilder } from '../components/FilterBuilder';
import { AttributePicker } from '../components/AttributePicker';
import { ExportModal } from '../components/ExportModal';
import { type NameOption, NameInput, attributeOptions, classOptions, matches } from '../components/NameInput';
import {
  type BasicKind, type SavedSearch, clearHistory, loadHistory, loadSearches, remember, removeSearch, saveSearch,
} from '../savedSearches';
import { columnList, valueText, valuesOf } from '../report';

/** The attributes a basic search matches a name against (the start of any of them). */
export const NAME_ATTRIBUTES = ['cn', 'fullName', 'givenName', 'sn', 'mail', 'uid'];

const KINDS: { kind: BasicKind; label: string; classes: string[] }[] = [
  { kind: 'people', label: 'People', classes: ['inetOrgPerson'] },
  { kind: 'groups', label: 'Groups', classes: ['groupOfNames', 'dynamicGroup'] },
  { kind: 'containers', label: 'Containers', classes: ['organizationalUnit', 'organization', 'locality', 'country', 'domain'] },
  { kind: 'everything', label: 'Everything', classes: [] },
];

/** The basic search's filter: what is typed matched at the start of the name attributes, and the kind's classes. */
export function basicFilter(find: string, kind: BasicKind): Filter | undefined {
  const parts: Filter[] = [];
  const classes = KINDS.find((k) => k.kind === kind)?.classes ?? [];
  if (classes.length) {
    parts.push(classes.length === 1 ? { eq: { objectClass: classes[0] } } : { or: classes.map((c) => ({ eq: { objectClass: c } })) });
  }
  const name = find.trim();
  if (name) {
    parts.push({ or: NAME_ATTRIBUTES.map((a) => ({ prefix: { [a]: name } })) });
  }
  return parts.length === 0 ? undefined : parts.length === 1 ? parts[0] : { and: parts };
}

const DEPTHS: { scope: SavedSearch['scope']; label: string }[] = [
  { scope: 'subtree', label: 'Everything below' },
  { scope: 'one', label: 'Directly inside' },
  { scope: 'base', label: 'Only that object' },
];

/** How a search reads in the recent list. */
function summary(s: SavedSearch): string {
  const where = s.base ? ` under ${s.base}` : '';
  if (s.mode === 'basic') {
    const kind = KINDS.find((k) => k.kind === s.kind)?.label ?? 'Everything';
    return `${kind}${s.find ? ` named ${s.find}…` : ''}${where}`;
  }
  let f = s.ldapFilter;
  if (s.filterMode !== 'write' && s.tree) {
    try {
      f = toText(s.tree);
    } catch {
      f = '(a filter)';
    }
  }
  return `${f.length > 70 ? `${f.slice(0, 67)}…` : f}${where}`;
}

/** Search: a basic search by name and kind, or an advanced one with a filter built from items or written as text. */
export function Search() {
  const { tree, me } = useSession();
  const { query } = useLocation();
  const selected = query.get('object');
  const [attributes, setAttributes] = useState<SchemaAttribute[]>([]);
  const [classes, setClasses] = useState<SchemaClass[]>([]);
  const [mode, setMode] = useState<'basic' | 'advanced'>('basic');
  const [base, setBase] = useState('');
  // basic
  const [find, setFind] = useState('');
  const [kind, setKind] = useState<BasicKind>('people');
  // advanced
  const [scope, setScope] = useState<SavedSearch['scope']>('subtree');
  const [filterMode, setFilterMode] = useState<'build' | 'write'>('build');
  const [filterTree, setFilterTree] = useState<FilterNode>(() => ({ kind: 'and', children: [
    { kind: 'cond', attribute: 'objectClass', op: 'eq', value: 'inetOrgPerson' }, { kind: 'cond', attribute: 'cn', op: 'prefix', value: '' }] }));
  const [ldapFilter, setLdapFilter] = useState('');
  const [switchNote, setSwitchNote] = useState<string | null>(null);
  const [sort, setSort] = useState('cn');
  const [columnsText, setColumnsText] = useState('');
  const [picking, setPicking] = useState(false);
  // results
  const [columns, setColumns] = useState<string[]>([]);
  const [request, setRequest] = useState<SearchRequest | null>(null);
  const [exporting, setExporting] = useState(false);
  const [pageNo, setPageNo] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [result, setResult] = useState<Page<Row | DirObject> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    tree.attributes().then((a) => setAttributes(a.filter((x) => !x.binary).sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
    tree.classes().then((c) => setClasses(c.filter((x) => x.kind !== 'abstract').sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
  }, [tree]);
  const attrOffers = attributeOptions(attributes);
  const classOffers = classOptions(classes);

  useEffect(() => {
    if (!request) {
      return;
    }
    setBusy(true);
    setError(null);
    tree.search({ ...request, page: { offset: (pageNo - 1) * perPage + 1, count: perPage } })
      .then(setResult).catch((e) => { setResult(null); setError(e); }).finally(() => setBusy(false));
  }, [tree, request, pageNo, perPage]);

  // the form as it stands, as a saved or recent search holds it
  const current = (name = ''): SavedSearch => ({
    name, mode, base, savedAt: new Date().toISOString(),
    ...(mode === 'basic'
      ? { scope: 'subtree', find, kind, ldapFilter: '', sort: 'cn', columns: '' }
      : { scope, filterMode, tree: filterMode === 'build' ? filterTree : undefined, ldapFilter: filterMode === 'write' ? ldapFilter : '', sort, columns: columnsText }),
  });

  const [history, setHistory] = useState<SavedSearch[]>(() => loadHistory(me.directory));
  const search = (v: SavedSearch) => {
    setError(null);
    try {
      const r: SearchRequest = { scope: v.scope, sort: { attribute: v.sort.trim() || 'cn' } };
      const cols = columnList(v.columns);
      if (cols.length) {
        r.attributes = cols;
      }
      if (v.base.trim()) {
        r.base = { dn: v.base.trim() };
      }
      if (v.mode === 'basic') {
        r.filter = basicFilter(v.find ?? '', v.kind ?? 'everything');
      } else if (v.filterMode === 'write') {
        const problem = checkFilter(v.ldapFilter);
        if (problem) {
          throw new Error(`The filter is not valid: ${problem.message}.`);
        }
        r.ldapFilter = v.ldapFilter.trim();
      } else {
        r.filter = v.tree ? toStructured(v.tree) : undefined;
      }
      setColumns(cols.filter((c) => c !== '*' && c !== '+'));
      setPageNo(1);
      setRequest(r);
      setHistory(remember(me.directory, { ...v, name: '' }));
    } catch (x) {
      setError(x);
    }
  };
  const run = (e: React.FormEvent) => {
    e.preventDefault();
    search(current());
  };

  // put a saved or recent search back on the form, and run it
  const restore = (v: SavedSearch) => {
    setMode(v.mode);
    setBase(v.base);
    if (v.mode === 'basic') {
      setFind(v.find ?? '');
      setKind(v.kind ?? 'everything');
    } else {
      setScope(v.scope);
      setFilterMode(v.filterMode ?? 'build');
      setFilterTree(v.tree ?? newGroup());
      setLdapFilter(v.ldapFilter);
      setSort(v.sort);
      setColumnsText(v.columns);
    }
    setSwitchNote(null);
    search(v);
  };

  // this browser's saved searches for this directory
  const [saved, setSaved] = useState<SavedSearch[]>(() => loadSearches(me.directory));
  const [chosen, setChosen] = useState('');
  const [naming, setNaming] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const [recentOpen, setRecentOpen] = useState(false);
  const open = (name: string) => {
    setChosen(name);
    const v = saved.find((x) => x.name === name);
    if (v) {
      restore(v);
    }
  };
  const keep = () => {
    const name = (naming ?? '').trim();
    if (!name) {
      return;
    }
    try {
      setSaved(saveSearch(me.directory, current(name)));
      setChosen(name);
      setNaming(null);
      setSavedNote(`Saved as ${name}, in this browser.`);
    } catch {
      setSavedNote('This browser would not keep it (private window or blocked storage).');
    }
  };
  const forget = () => {
    try {
      setSaved(removeSearch(me.directory, chosen));
      setSavedNote(`${chosen} is no longer saved.`);
      setChosen('');
    } catch {
      setSavedNote('This browser would not change its saved searches.');
    }
  };

  // switching between the builder and text: the builder's items become text; text becomes items when it can
  const toBuild = () => {
    if (!ldapFilter.trim()) {
      setFilterMode('build');
      setSwitchNote(null);
      return;
    }
    try {
      setFilterTree(fromText(ldapFilter));
      setFilterMode('build');
      setSwitchNote(null);
    } catch (e) {
      setSwitchNote(`The builder cannot show this filter: ${(e as Error).message}.`);
    }
  };
  const toWrite = () => {
    try {
      setLdapFilter(toText(filterTree));
    } catch {
      // an attribute name that is not one: start from what was typed before
    }
    setFilterMode('write');
    setSwitchNote(null);
  };

  const total = result ? (result.total >= 0 ? result.total : result.offset - 1 + result.count + (result.count === perPage ? 1 : 0)) : 0;

  const savedBar = (
    <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsSm' }} className="dc-saved-searches">
      <FlexItem>
        <FormSelect id="saved" aria-label="Saved searches" value={chosen} onChange={(_e, v) => open(v)} isDisabled={saved.length === 0}>
          <FormSelectOption value="" label={saved.length ? 'Saved searches…' : 'No saved searches yet'} isPlaceholder />
          {saved.map((x) => <FormSelectOption key={x.name} value={x.name} label={x.name} />)}
        </FormSelect>
      </FlexItem>
      <FlexItem>
        <Dropdown isOpen={recentOpen} onOpenChange={setRecentOpen} popperProps={{ appendTo: 'inline' }}
          toggle={(ref) => <MenuToggle ref={ref} icon={<HistoryIcon />} isExpanded={recentOpen} onClick={() => setRecentOpen(!recentOpen)}
            isDisabled={history.length === 0}>Recent</MenuToggle>}>
          <DropdownGroup label="Recent searches in this browser">
            <DropdownList>
              {history.map((h, i) => (
                <DropdownItem key={i} onClick={() => { setRecentOpen(false); setChosen(''); restore(h); }}
                  description={h.mode === 'basic' ? 'Basic' : `Advanced${h.columns ? ` · ${h.columns}` : ''}`}>
                  <span className={h.mode === 'basic' ? undefined : 'dc-mono'}>{summary(h)}</span>
                </DropdownItem>
              ))}
            </DropdownList>
          </DropdownGroup>
          <DropdownList>
            <DropdownItem key="clear" onClick={() => { setRecentOpen(false); clearHistory(me.directory); setHistory([]); }}>Clear recent searches</DropdownItem>
          </DropdownList>
        </Dropdown>
      </FlexItem>
      {naming === null ? (
        <>
          <FlexItem><Button variant="secondary" size="sm" onClick={() => { setNaming(chosen); setSavedNote(null); }}>Save this search</Button></FlexItem>
          {chosen && <FlexItem><Button variant="link" size="sm" isDanger onClick={forget}>Delete {chosen}</Button></FlexItem>}
        </>
      ) : (
        <>
          <FlexItem><TextInput aria-label="Name for the search" placeholder="A name, such as Sales staff" value={naming} autoFocus
            onChange={(_e, v) => setNaming(v)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); keep(); } }} /></FlexItem>
          <FlexItem><Button size="sm" onClick={keep} isDisabled={!naming.trim()}>Save</Button></FlexItem>
          <FlexItem><Button variant="link" size="sm" onClick={() => setNaming(null)}>Cancel</Button></FlexItem>
        </>
      )}
      {savedNote && <FlexItem><span className="dc-subtle">{savedNote}</span></FlexItem>}
    </Flex>
  );

  const baseField = (
    <FormGroup label="Search under" fieldId="base">
      <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsSm' }}>
        <FlexItem grow={{ default: 'grow' }}>
          <TextInput id="base" value={base} onChange={(_e, v) => setBase(v)} placeholder="the whole directory, or a DN such as ou=users,o=acme" />
        </FlexItem>
        <FlexItem><BrowseContainers title="Search under" onChoose={setBase} /></FlexItem>
      </Flex>
    </FormGroup>
  );

  return (
    <PageSection isFilled padding={{ default: 'noPadding' }}>
      <ObjectDrawer guid={selected} onClose={() => navigate('/search')} onChanged={(o) => { if (!o) { navigate('/search'); } if (request) { setRequest({ ...request }); } }}>
      <div className="dc-page">
      <Title headingLevel="h1">Search</Title>
      <Card isCompact>
        <CardBody>
          {savedBar}
          <Tabs activeKey={mode} onSelect={(_e, k) => setMode(k as 'basic' | 'advanced')} aria-label="Kind of search" mountOnEnter>
            <Tab eventKey="basic" title={<TabTitleText>Basic</TabTitleText>}>
              <Form onSubmit={run} isWidthLimited className="dc-tab-body">
                <FormGroup label="Name" fieldId="find">
                  <TextInput id="find" value={find} onChange={(_e, v) => setFind(v)} autoFocus placeholder="the start of a name, such as smi" />
                  <FormHelperText><HelperText><HelperTextItem>
                    Matches the start of {NAME_ATTRIBUTES.join(', ')}. Leave it empty to list everything of the kind chosen.
                  </HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
                <FormGroup label="Find" fieldId="kind" role="radiogroup" isInline>
                  <ToggleGroup aria-label="Find">
                    {KINDS.map((k) => <ToggleGroupItem key={k.kind} text={k.label} isSelected={kind === k.kind} onChange={() => setKind(k.kind)} />)}
                  </ToggleGroup>
                </FormGroup>
                {baseField}
                <ActionGroup>
                  <Button type="submit" variant="primary" isLoading={busy}>Search</Button>
                </ActionGroup>
              </Form>
            </Tab>
            <Tab eventKey="advanced" title={<TabTitleText>Advanced</TabTitleText>}>
              <Form onSubmit={run} className="dc-tab-body">
                {baseField}
                <FormGroup label="Depth" fieldId="scope" role="radiogroup" isInline>
                  <ToggleGroup aria-label="Depth">
                    {DEPTHS.map((d) => <ToggleGroupItem key={d.scope} text={d.label} isSelected={scope === d.scope} onChange={() => setScope(d.scope)} />)}
                  </ToggleGroup>
                </FormGroup>
                <FormGroup label="Filter" fieldId="filter-mode">
                  <ToggleGroup aria-label="How to give the filter" isCompact>
                    <ToggleGroupItem text="Build it" isSelected={filterMode === 'build'} onChange={toBuild} />
                    <ToggleGroupItem text="Write LDAP filter text" isSelected={filterMode === 'write'} onChange={toWrite} />
                  </ToggleGroup>
                  {switchNote && <HelperText><HelperTextItem variant="warning">{switchNote}</HelperTextItem></HelperText>}
                  <div className="dc-tab-body">
                    {filterMode === 'build'
                      ? <FilterBuilder node={filterTree} onChange={setFilterTree} attributes={attrOffers} classes={classOffers} />
                      : <FilterText value={ldapFilter} onChange={setLdapFilter} attributes={attrOffers} classes={classOffers} />}
                  </div>
                </FormGroup>
                <FormGroup label="Sort by" fieldId="sort">
                  <NameInput id="sort" options={attrOffers} value={sort} onChange={setSort} />
                </FormGroup>
                <FormGroup label="Columns" fieldId="columns">
                  <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsSm' }}>
                    <FlexItem grow={{ default: 'grow' }}>
                      <NameInput id="columns" list options={attrOffers} value={columnsText} onChange={setColumnsText} placeholder="optional: mail, title, telephoneNumber" />
                    </FlexItem>
                    <FlexItem><Button variant="secondary" onClick={() => setPicking(true)}>Choose…</Button></FlexItem>
                  </Flex>
                  <FormHelperText><HelperText><HelperTextItem>Attributes to show for each result, and to export, in this order. * is every attribute, + the operational ones.</HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
                <ActionGroup>
                  <Button type="submit" variant="primary" isLoading={busy}>Search</Button>
                </ActionGroup>
              </Form>
            </Tab>
          </Tabs>
        </CardBody>
      </Card>
      {picking && <AttributePicker attributes={attributes} chosen={columnList(columnsText)} onChoose={(c) => setColumnsText(c.join(', '))} onClose={() => setPicking(false)} />}
      {/* a mistake on the form is not a failed request */}
      <ProblemAlert error={error} title={error && !(error instanceof ApiError) ? 'Check the search' : undefined} />
      {request && (
        <Card isCompact className="dc-tab-body">
            <CardBody>
              <Toolbar>
                <ToolbarContent>
                  <ToolbarItem>
                    <Button variant="secondary" size="sm" icon={<DownloadIcon />} isDisabled={!result?.items.length} onClick={() => setExporting(true)}>Export…</Button>
                  </ToolbarItem>
                  <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
                    <Pagination itemCount={total} page={pageNo} perPage={perPage} isCompact
                      onSetPage={(_e, p) => setPageNo(p)} onPerPageSelect={(_e, pp) => { setPerPage(pp); setPageNo(1); }}
                      toggleTemplate={result && !result.exact ? ({ firstIndex, lastIndex }) => <>{firstIndex}-{lastIndex} of about {total}</> : undefined} />
                  </ToolbarItem>
                </ToolbarContent>
              </Toolbar>
              {busy && !result && <Spinner aria-label="Searching" />}
              {result && result.items.length === 0 && <EmptyState titleText="No matches" headingLevel="h2"><EmptyStateBody>Nothing matched. Check the name, the kind and where to search.</EmptyStateBody></EmptyState>}
              {result && result.items.length > 0 && (
                columns.length > 0
                  ? <ColumnsTable rows={result.items} columns={columns} selected={selected} onDetails={(r) => navigate(`/search?object=${r.guid}`)} />
                  : <RowsTable narrow={!!selected} label="Results" rows={result.items} selected={selected}
                    onOpen={(r) => navigate(`/browse/${r.guid}`)} onDetails={(r) => navigate(`/search?object=${r.guid}`)} />
              )}
            </CardBody>
        </Card>
      )}
      {exporting && request && (
        <ExportModal title="Export the results" onClose={() => setExporting(false)}
          query={{ base: request.base, scope: request.scope, filter: request.filter, ldapFilter: request.ldapFilter, attributes: request.attributes }} />
      )}
      </div>
      </ObjectDrawer>
    </PageSection>
  );
}

/** LDAP filter text, checked as it is typed, with attribute names offered at the cursor. */
function FilterText({ value, onChange, attributes, classes }: { value: string; onChange: (v: string) => void; attributes: NameOption[]; classes: NameOption[] }) {
  const [cursor, setCursor] = useState(0);
  const area = useRef<HTMLTextAreaElement>(null);
  const problem = value.trim() ? checkFilter(value) : null;
  // an attribute name where one starts, a class name after objectClass=
  const cls = classAt(value, cursor);
  const at = cls ?? attributeAt(value, cursor);
  const offers = cls ? (cls.token ? matches(classes, cls.token) : []).slice(0, 8) : at ? matches(attributes, at.token).slice(0, 8) : [];
  const take = (name: string) => {
    if (!at) {
      return;
    }
    const next = value.slice(0, at.start) + name + value.slice(cursor);
    onChange(next);
    const pos = at.start + name.length;
    setCursor(pos);
    requestAnimationFrame(() => { area.current?.focus(); area.current?.setSelectionRange(pos, pos); });
  };
  const track = (e: React.SyntheticEvent<HTMLTextAreaElement>) => setCursor(e.currentTarget.selectionStart);
  return (
    <>
      <TextArea id="ldap" ref={area} value={value} rows={3} className="dc-mono" aria-label="LDAP filter" placeholder="(&(objectClass=inetOrgPerson)(cn=smith*))"
        validated={problem ? 'error' : value.trim() ? 'success' : 'default'}
        onChange={(e, v) => { onChange(v); setCursor(e.currentTarget.selectionStart); }} onKeyUp={track} onClick={track} onSelect={track} />
      {offers.length > 0 && (
        <Flex spaceItems={{ default: 'spaceItemsXs' }} className="dc-filter-offers" aria-label={cls ? 'Class names' : 'Attribute names'}>
          {offers.map((a) => <FlexItem key={a.name}><Label isCompact onClick={() => take(a.name)}><span className="dc-mono">{a.name}</span></Label></FlexItem>)}
        </Flex>
      )}
      <HelperText>
        {problem
          ? <HelperTextItem variant="error">At character {problem.at + 1}: {problem.message}.</HelperTextItem>
          : <HelperTextItem>One parenthesized filter (RFC 4515). In values, write \28 for (, \29 for ), \2a for * and \5c for \.</HelperTextItem>}
      </HelperText>
    </>
  );
}

/** Results with the chosen attributes as columns; the name opens the object's details. */
function ColumnsTable({ rows, columns, selected, onDetails }: {
  rows: (Row | DirObject)[]; columns: string[]; selected: string | null; onDetails: (r: Row) => void;
}) {
  return (
    <Table aria-label="Results" variant="compact">
      <Thead><Tr><Th>Name</Th>{columns.map((c) => <Th key={c}><span className="dc-mono">{c}</span></Th>)}</Tr></Thead>
      <Tbody>
        {rows.map((r) => (
          <Tr key={r.guid} isRowSelected={r.guid === selected}>
            <Td dataLabel="Name"><Button variant="link" isInline onClick={() => onDetails(r)}>{r.name}</Button></Td>
            {columns.map((c) => (
              <Td key={c} dataLabel={c} className="dc-mono" modifier="breakWord">{valuesOf(r, c).map(valueText).join('; ')}</Td>
            ))}
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
}
