import { useCallback, useEffect, useState } from 'react';
import {
  Bullseye, Button, ClipboardCopy, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm,
  Dropdown, DropdownItem, DropdownList, Flex, FlexItem, Label, LabelGroup, MenuToggle, Spinner, Tab, Tabs, TabTitleText, Title,
} from '@patternfly/react-core';
import { EllipsisVIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type DirObject, type Rights } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { ValueView } from './ValueView';
import { AttributeModal, DeleteModal, MoveModal, RenameModal } from './Edit';

type Dialog = null | { kind: 'attr'; attribute?: string } | { kind: 'rename' } | { kind: 'move' } | { kind: 'delete' };

interface Props {
  guid: string;
  /** Called after a change, with the object as it is now (null when deleted). */
  onChanged?: (obj: DirObject | null) => void;
  headingLevel?: 'h1' | 'h2';
}

/** One object: its attributes, identity and the signed-in person's rights, with the editing actions. */
export function ObjectPanel({ guid, onChanged, headingLevel = 'h2' }: Props) {
  const { tree, can } = useSession();
  const [obj, setObj] = useState<DirObject | null>(null);
  const [etag, setEtag] = useState('');
  const [rights, setRights] = useState<Rights | null>(null);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<string | number>('attributes');
  const [menu, setMenu] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);

  const load = useCallback(() => {
    setError(null);
    tree.read(guid).then((r) => {
      setObj(r.data);
      setEtag(r.etag ?? '*');
      tree.schemaClass(r.data.objectClass).then((c) => setAllowed([...(c.allMust ?? []), ...(c.allMay ?? [])])).catch(() => setAllowed([]));
    }).catch((e) => {
      setObj(null);
      setError(e);
    });
    tree.rights(guid).then(setRights).catch(() => setRights(null));
  }, [tree, guid]);

  useEffect(load, [load]);

  if (error) {
    return <ProblemAlert error={error} onRetry={load} title={error instanceof ApiError && error.status === 404 ? 'Object not found' : undefined} />;
  }
  if (!obj) {
    return <Bullseye><Spinner aria-label="Loading the object" /></Bullseye>;
  }

  const done = (o: DirObject, e?: string) => {
    setObj(o);
    setEtag(e ?? '*');
    setDialog(null);
    onChanged?.(o);
  };
  const editor = can('editor');
  const attrs = Object.entries(obj.attributes).sort(([a], [b]) => a.localeCompare(b));
  const op = Object.fromEntries(Object.entries(obj.operational).map(([k, v]) => [k, scalar(v)]));

  return (
    <>
      <Flex justifyContent={{ default: 'justifyContentSpaceBetween' }} alignItems={{ default: 'alignItemsFlexStart' }} flexWrap={{ default: 'nowrap' }}>
        <FlexItem>
          <Title headingLevel={headingLevel}>{obj.name}</Title>
          <LabelGroup>
            <Label color="blue">{obj.objectClass}</Label>
            {obj.container && <Label>container</Label>}
          </LabelGroup>
        </FlexItem>
        {editor && (
          <FlexItem>
            <Dropdown isOpen={menu} onOpenChange={setMenu} popperProps={{ position: 'right' }}
              toggle={(ref) => <MenuToggle ref={ref} variant="plain" aria-label="Actions" isExpanded={menu} onClick={() => setMenu(!menu)} icon={<EllipsisVIcon />} />}>
              <DropdownList>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'attr' }); }}>Edit an attribute</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'rename' }); }}>Rename</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'move' }); }}>Move</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'delete' }); }} isDanger>Delete</DropdownItem>
              </DropdownList>
            </Dropdown>
          </FlexItem>
        )}
      </Flex>

      <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Object details" mountOnEnter>
        <Tab eventKey="attributes" title={<TabTitleText>Attributes</TabTitleText>}>
          <Table aria-label="Attributes" variant="compact">
            <Thead>
              <Tr>
                <Th width={30}>Attribute</Th>
                <Th>Values</Th>
                {editor && <Th screenReaderText="Edit" />}
              </Tr>
            </Thead>
            <Tbody>
              {attrs.map(([name, values]) => (
                <Tr key={name}>
                  <Td dataLabel="Attribute"><span className="dc-mono">{name}</span></Td>
                  <Td dataLabel="Values">
                    <ul className="dc-values">{values.map((v, i) => <li key={i}><ValueView value={v} /></li>)}</ul>
                  </Td>
                  {editor && (
                    <Td isActionCell>
                      <Button variant="link" isInline onClick={() => setDialog({ kind: 'attr', attribute: name })} aria-label={`Edit ${name}`}>Edit</Button>
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        </Tab>
        <Tab eventKey="identity" title={<TabTitleText>Identity</TabTitleText>}>
          <DescriptionList isHorizontal className="dc-tab-body">
            <Copy term="GUID" value={obj.guid} />
            <Copy term="DN" value={obj.dn} />
            <Copy term="Dot name" value={obj.display.dot} />
            <Copy term="Slash name" value={obj.display.slash} />
            <Plain term="Classes" value={obj.objectClasses.join(', ')} />
            <Plain term="Created" value={when(op.createTimestamp)} />
            <Plain term="Created by" value={op.creatorsName} />
            <Plain term="Modified" value={when(op.modifyTimestamp)} />
            <Plain term="Modified by" value={op.modifiersName} />
            <Plain term="Revision" value={op.revision} />
          </DescriptionList>
        </Tab>
        <Tab eventKey="rights" title={<TabTitleText>Your rights</TabTitleText>}>
          {rights
            ? (
              <DescriptionList isHorizontal className="dc-tab-body">
                <Plain term="On the object" value={rights.entry.join(', ') || 'none'} />
                <Plain term="On all attributes" value={rights.allAttributes.join(', ') || 'none'} />
              </DescriptionList>
            )
            : <Spinner size="md" aria-label="Loading rights" />}
        </Tab>
      </Tabs>

      {dialog?.kind === 'attr' && <AttributeModal obj={obj} etag={etag} allowed={allowed} initial={dialog.attribute} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'rename' && <RenameModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'move' && <MoveModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'delete' && (
        <DeleteModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDeleted={() => { setDialog(null); onChanged?.(null); }} />
      )}
    </>
  );
}

function Copy({ term, value }: { term: string; value: string }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>
        <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" variant="inline-compact" className="dc-mono">{value}</ClipboardCopy>
      </DescriptionListDescription>
    </DescriptionListGroup>
  );
}

function Plain({ term, value }: { term: string; value?: string }) {
  if (!value) {
    return null;
  }
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>{value}</DescriptionListDescription>
    </DescriptionListGroup>
  );
}

/** An operational value as text: the first of a list, a reference's DN. */
function scalar(v: unknown): string | undefined {
  const x = Array.isArray(v) ? v[0] : v;
  if (x === undefined || x === null) {
    return undefined;
  }
  if (typeof x === 'object' && 'dn' in x) {
    return String((x as { dn: string }).dn);
  }
  return String(x);
}

/** 20261009232026Z → a local date and time. */
function when(generalized?: string): string | undefined {
  const m = generalized?.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,]\d+)?Z$/);
  if (!m) {
    return generalized;
  }
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toLocaleString();
}
