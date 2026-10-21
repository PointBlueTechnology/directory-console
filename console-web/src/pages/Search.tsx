import { useEffect, useState } from 'react';
import {
  ActionGroup, Button, Card, CardBody, EmptyState, EmptyStateBody, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSelect,
  FormSelectOption, FormSelectOptionGroup, HelperText, HelperTextItem, PageSection, Pagination, Spinner, Switch, TextArea, TextInput, Title,
  ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { DirObject, Page, Row, SchemaAttribute, SchemaClass, SearchRequest } from '../api';
import { useSession } from '../session';
import { navigate, useLocation } from '../router';
import { type Condition, toFilter } from '../filters';
import { ObjectDrawer } from '../components/ObjectDrawer';
import { RowsTable } from '../components/RowsTable';
import { ProblemAlert } from '../components/Problem';
import { BrowseContainers } from '../components/ContainerChooser';
import { ConditionsEditor, EMPTY_CONDITION } from '../components/Conditions';
import { columnList, reportCsv, reportJson, valueText, valuesOf } from '../report';


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
  const [conditions, setConditions] = useState<Condition[]>([{ ...EMPTY_CONDITION }]);
  const [join, setJoin] = useState<'and' | 'or'>('and');
  const [advanced, setAdvanced] = useState(false);
  const [ldapFilter, setLdapFilter] = useState('');
  const [sort, setSort] = useState('cn');
  const [columnsText, setColumnsText] = useState('');
  const [columns, setColumns] = useState<string[]>([]);
  const [exporting, setExporting] = useState(false);
  const [exportNote, setExportNote] = useState<string | null>(null);
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

  // every match, page by page, up to EXPORT_MAX, as CSV or JSON with the chosen columns
  const exportAll = async (format: 'csv' | 'json') => {
    if (!request) {
      return;
    }
    setExporting(true);
    setExportNote(null);
    setError(null);
    try {
      const rows: (Row | DirObject)[] = [];
      for (let offset = 1; rows.length < EXPORT_MAX; offset += EXPORT_PAGE) {
        const p = await tree.search({ ...request, page: { offset, count: EXPORT_PAGE } });
        rows.push(...p.items);
        if (p.items.length < EXPORT_PAGE || (p.total >= 0 && rows.length >= p.total)) {
          break;
        }
      }
      const capped = rows.length >= EXPORT_MAX;
      const kept = rows.slice(0, EXPORT_MAX);
      const text = format === 'csv' ? reportCsv(kept, columns) : reportJson(kept, columns);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json' }));
      a.download = `search-${new Date().toISOString().slice(0, 10)}.${format}`;
      a.click();
      URL.revokeObjectURL(a.href);
      setExportNote(`${kept.length} ${kept.length === 1 ? 'object' : 'objects'} exported${capped ? ` (the first ${EXPORT_MAX}; narrow the search for the rest)` : ''}.`);
    } catch (x) {
      setError(x);
    } finally {
      setExporting(false);
    }
  };

  const run = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const r: SearchRequest = { scope, sort: { attribute: sort.trim() || 'cn' } };
      const cols = columnList(columnsText);
      if (cols.length) {
        r.attributes = cols;
      }
      setColumns(cols);
      setExportNote(null);
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
              <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsSm' }}>
                <FlexItem grow={{ default: 'grow' }}>
                  <TextInput id="base" value={base} onChange={(_e, v) => setBase(v)} placeholder="the whole directory, or a DN such as ou=users,o=acme" />
                </FlexItem>
                <FlexItem><BrowseContainers title="Search under" onChoose={setBase} /></FlexItem>
              </Flex>
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
                  <ConditionsEditor id="cond" conditions={conditions} onChange={setConditions} join={join} onJoin={setJoin} attributes={attributes} />
                </>
              )}
            <FormGroup label="Sort by" fieldId="sort">
              <TextInput id="sort" list="attribute-names" value={sort} onChange={(_e, v) => setSort(v)} />
            </FormGroup>
            <FormGroup label="Columns" fieldId="columns">
              <TextInput id="columns" list="attribute-names" value={columnsText} onChange={(_e, v) => setColumnsText(v)} placeholder="optional: mail, title, telephoneNumber" />
              <FormHelperText><HelperText><HelperTextItem>Attributes to show for each result, and to export; separate them with commas.</HelperTextItem></HelperText></FormHelperText>
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
                  <ToolbarItem>
                    <Button variant="secondary" size="sm" isDisabled={exporting || !result?.items.length} isLoading={exporting} onClick={() => exportAll('csv')}>Export CSV</Button>
                  </ToolbarItem>
                  <ToolbarItem>
                    <Button variant="secondary" size="sm" isDisabled={exporting || !result?.items.length} onClick={() => exportAll('json')}>Export JSON</Button>
                  </ToolbarItem>
                  {exportNote && <ToolbarItem><span className="dc-subtle">{exportNote}</span></ToolbarItem>}
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
                columns.length > 0
                  ? <ColumnsTable rows={result.items} columns={columns} selected={selected} onDetails={(r) => navigate(`/search?object=${r.guid}`)} />
                  : <RowsTable narrow={!!selected} label="Results" rows={result.items} selected={selected}
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

const EXPORT_PAGE = 500;
const EXPORT_MAX = 10000;

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
