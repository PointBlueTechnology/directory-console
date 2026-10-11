import { useCallback, useEffect, useState } from 'react';
import {
  Breadcrumb, BreadcrumbItem, Button, Card, CardBody, CardTitle, EmptyState, EmptyStateBody, PageSection, Pagination,
  SearchInput, Spinner, Title, ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import type { DirObject, Page, Row } from '../api';
import { useSession } from '../session';
import { navigate, useLocation } from '../router';
import { ContainerTree } from '../components/ContainerTree';
import { ObjectDrawer } from '../components/ObjectDrawer';
import { RowsTable } from '../components/RowsTable';
import { ProblemAlert } from '../components/Problem';
import { CreateModal } from '../components/Edit';

type Kind = 'all' | 'containers' | 'leaves';

/** The tree on the left, the open container's contents on the right, an object's details in a drawer. */
export function Browser({ container }: { container?: string }) {
  const { tree, canAt } = useSession();
  const { query } = useLocation();
  const selected = query.get('object');
  const [here, setHere] = useState<DirObject | null>(null);
  const [page, setPage] = useState<Page<Row> | null>(null);
  const [roots, setRoots] = useState<Row[] | null>(null);
  const [kind, setKind] = useState<Kind>('all');
  const [pageNo, setPageNo] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [highlight, setHighlight] = useState<string | null>(null);
  const [goTo, setGoTo] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    setPageNo(1);
    setHighlight(null);
    setHere(null);
    if (container) {
      tree.read(container).then((r) => setHere(r.data)).catch(setError);
    } else {
      tree.roots().then(setRoots).catch(setError);
    }
  }, [tree, container]);

  const load = useCallback(() => {
    if (!container) {
      return;
    }
    setError(null);
    tree.children(container, { kind, offset: (pageNo - 1) * perPage + 1, count: perPage }).then(setPage).catch((e) => {
      setPage(null);
      setError(e);
    });
  }, [tree, container, kind, pageNo, perPage]);

  useEffect(load, [load]);

  const jump = async (startAt: string) => {
    if (!container || !startAt.trim()) {
      return;
    }
    const p = await tree.children(container, { kind, startAt: startAt.trim(), count: 1 });
    setHighlight(p.items[0]?.guid ?? null);
    setPageNo(Math.floor((p.offset - 1) / perPage) + 1);
  };

  const details = (r: Row) => navigate(`${location.pathname}?object=${r.guid}`);
  const openContainer = (r: Row) => navigate(`/browse/${r.guid}`);
  const closeDetails = () => navigate(location.pathname);
  const changed = (o: DirObject | null) => {
    if (!o) {
      closeDetails();
    }
    load();
  };

  const total = page ? (page.total >= 0 ? page.total : page.offset - 1 + page.count + (page.count === perPage ? 1 : 0)) : 0;
  const up = async (dn: string) => {
    try {
      navigate(`/browse/${(await tree.resolve(dn)).data.guid}`);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <PageSection isFilled padding={{ default: 'noPadding' }}>
      <ObjectDrawer guid={selected} onClose={closeDetails} onChanged={changed}>
      <div className="dc-browser dc-page">
        <Card isCompact>
          <CardTitle>Containers</CardTitle>
          <CardBody className="dc-tree">
            <ContainerTree selected={container} onSelect={openContainer} />
          </CardBody>
        </Card>
        <Card isCompact>
            <CardBody>
              {here && (
                <>
                  <Breadcrumb>
                    <BreadcrumbItem render={() => <Button variant="link" isInline onClick={() => navigate('/browse')}>Top</Button>} />
                    {here.ancestors.map((a) => (
                      <BreadcrumbItem key={a.dn} render={() => <Button variant="link" isInline onClick={() => up(a.dn)}>{a.name}</Button>} />
                    ))}
                    <BreadcrumbItem isActive>{here.name}</BreadcrumbItem>
                  </Breadcrumb>
                  <Title headingLevel="h1">{here.name}</Title>
                </>
              )}
              {!container && <Title headingLevel="h1">Top of the tree</Title>}
              <ProblemAlert error={error} onRetry={load} />
              {container && (
                <Toolbar>
                  <ToolbarContent>
                    <ToolbarItem>
                      <ToggleGroup aria-label="Show">
                        {(['all', 'containers', 'leaves'] as Kind[]).map((k) => (
                          <ToggleGroupItem key={k} text={k === 'all' ? 'Everything' : k === 'containers' ? 'Containers' : 'Other objects'}
                            isSelected={kind === k} onChange={() => { setKind(k); setPageNo(1); }} />
                        ))}
                      </ToggleGroup>
                    </ToolbarItem>
                    <ToolbarItem>
                      <SearchInput placeholder="Go to a name" aria-label="Go to the first name at or after" value={goTo}
                        onChange={(_e, v) => setGoTo(v)} onSearch={(_e, v) => jump(v)} onClear={() => { setGoTo(''); setHighlight(null); }} />
                    </ToolbarItem>
                    {here && canAt('editor', here.dn) && (
                      <ToolbarItem>
                        <Button variant="secondary" icon={<PlusIcon />} onClick={() => setCreating(true)}>New object</Button>
                      </ToolbarItem>
                    )}
                    <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
                      <Pagination itemCount={total} page={pageNo} perPage={perPage} isCompact
                        onSetPage={(_e, p) => setPageNo(p)} onPerPageSelect={(_e, pp) => { setPerPage(pp); setPageNo(1); }}
                        toggleTemplate={page && !page.exact ? ({ firstIndex, lastIndex }) => <>{firstIndex}-{lastIndex} of about {total}</> : undefined} />
                    </ToolbarItem>
                  </ToolbarContent>
                </Toolbar>
              )}
              {container && !page && !error && <Spinner aria-label="Loading" />}
              {container && page && page.items.length === 0 && (
                <EmptyState titleText="Nothing here" headingLevel="h2"><EmptyStateBody>This container has no {kind === 'all' ? 'objects' : kind === 'containers' ? 'containers' : 'other objects'}.</EmptyStateBody></EmptyState>
              )}
              {container && page && page.items.length > 0 && (
                <RowsTable narrow={!!selected} label="Contents" rows={page.items} selected={selected} highlight={highlight} onOpen={openContainer} onDetails={details} />
              )}
              {!container && roots && <RowsTable narrow={!!selected} label="Top of the tree" rows={roots} selected={selected} onOpen={openContainer} onDetails={details} />}
            </CardBody>
        </Card>
      </div>
      </ObjectDrawer>
      {creating && here && (
        <CreateModal parent={here} onClose={() => setCreating(false)}
          onCreated={(o) => { setCreating(false); load(); navigate(`${location.pathname}?object=${o.guid}`); }} />
      )}
    </PageSection>
  );
}
