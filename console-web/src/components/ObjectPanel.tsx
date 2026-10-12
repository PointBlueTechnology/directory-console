import { useCallback, useEffect, useState } from 'react';
import {
  Alert, AlertActionCloseButton, Bullseye, Button, ClipboardCopy, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm,
  Divider, Dropdown, DropdownGroup, DropdownItem, DropdownList, Flex, FlexItem, Label, LabelGroup, MenuToggle, Spinner, Tab, Tabs, TabTitleText, Title,
} from '@patternfly/react-core';
import { EllipsisVIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type DirObject, type Preset, edir, isGroup, isUser, isWithheld, presets } from '../api';
import { useConfirmed } from './Confirm';
import { PresetModal } from './PresetModal';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { ValueView } from './ValueView';
import { AttributeModal, AuxClassModal, DeleteModal, MoveModal, PasswordModal, RenameModal } from './Edit';
import { AccountTab } from './AccountTab';
import { GroupMembersTab, UserGroupsTab } from './MembershipTab';
import { RightsTab } from './RightsTab';
import { ReplicasTab } from './ReplicasTab';
import { HeadingLevel } from '../heading';

type Dialog = null | { kind: 'attr'; attribute?: string } | { kind: 'rename' } | { kind: 'move' } | { kind: 'delete' }
  | { kind: 'password' } | { kind: 'aux' } | { kind: 'preset'; preset: Preset };

interface Props {
  guid: string;
  /** Called after a change, with the object as it is now (null when deleted). */
  onChanged?: (obj: DirObject | null) => void;
  headingLevel?: 'h1' | 'h2';
}

/** One object: its attributes, identity and the signed-in person's rights, with the editing actions. */
export function ObjectPanel({ guid, onChanged, headingLevel = 'h2' }: Props) {
  const { tree, canAt, me } = useSession();
  const { run: confirmed, dialog: confirmDialog } = useConfirmed();
  const [tasks, setTasks] = useState<Preset[]>([]);
  const [actionError, setActionError] = useState<unknown>(null);
  const [obj, setObj] = useState<DirObject | null>(null);
  const [etag, setEtag] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
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
  }, [tree, guid]);

  useEffect(load, [load]);
  const presetIds = (obj?.allowed?.presets ?? []).join(',');
  useEffect(() => {
    if (!presetIds) {
      setTasks([]);
      return;
    }
    presets(me.directory).list().then((all) => setTasks(all.filter((p) => presetIds.split(',').includes(p.id)))).catch(() => setTasks([]));
  }, [me.directory, presetIds]);

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
  /** Something changed through a tab: read the object again (new ETag, new values). */
  const refreshed = () => {
    tree.read(guid).then((r) => {
      setObj(r.data);
      setEtag(r.etag ?? '*');
      onChanged?.(r.data);
    }).catch(setError);
  };
  const user = isUser(obj);
  const group = isGroup(obj);
  const toggleDisabled = async () => {
    setMenu(false);
    try {
      const a = await tree.account(obj.guid);
      const r = await tree.updateAccount(obj.guid, a.etag ?? '*', { disabled: !a.data.disabled });
      setNotice(r.data.disabled ? 'The account is now disabled.' : 'The account is now enabled.');
      refreshed();
    } catch (x) {
      setError(x);
    }
  };
  const editor = obj.allowed ? obj.allowed.edit : canAt('editor', obj.dn);
  const attrs = Object.entries(obj.attributes).sort(([a], [b]) => a.localeCompare(b));
  const op = Object.fromEntries(Object.entries(obj.operational).map(([k, v]) => [k, scalar(v)]));

  return (
    <HeadingLevel.Provider value={headingLevel === 'h1' ? 'h2' : 'h3'}>
      <Flex justifyContent={{ default: 'justifyContentSpaceBetween' }} alignItems={{ default: 'alignItemsFlexStart' }} flexWrap={{ default: 'nowrap' }}>
        <FlexItem>
          <Title headingLevel={headingLevel}>{obj.name}</Title>
          <LabelGroup>
            <Label color="blue">{obj.objectClass}</Label>
            {obj.container && <Label>container</Label>}
          </LabelGroup>
        </FlexItem>
        {(editor || tasks.length > 0) && (
          <FlexItem>
            <Dropdown isOpen={menu} onOpenChange={setMenu} popperProps={{ position: 'right', appendTo: 'inline' }}
              toggle={(ref) => <MenuToggle ref={ref} variant="plain" aria-label="Actions" isExpanded={menu} onClick={() => setMenu(!menu)} icon={<EllipsisVIcon />} />}>
              {tasks.length > 0 && (
                <DropdownGroup label="Tasks" labelHeadingLevel={headingLevel === 'h1' ? 'h2' : 'h3'}>
                  <DropdownList>
                    {tasks.map((p) => (
                      <DropdownItem key={p.id} description={p.description} onClick={() => { setMenu(false); setDialog({ kind: 'preset', preset: p }); }}>{p.name}</DropdownItem>
                    ))}
                  </DropdownList>
                </DropdownGroup>
              )}
              {tasks.length > 0 && editor && <Divider component="li" />}
              {editor && <DropdownList>
                {user && <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'password' }); }}>Set password</DropdownItem>}
                {user && <DropdownItem onClick={toggleDisabled}>Enable or disable</DropdownItem>}
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'attr' }); }}>Edit an attribute</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'aux' }); }}>Auxiliary classes</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'rename' }); }}>Rename</DropdownItem>
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'move' }); }}>Move</DropdownItem>
                {obj.container && canAt('editor', '') && (
                  <DropdownItem description="Split it from its parent partition" onClick={async () => {
                    setMenu(false);
                    setActionError(null);
                    try {
                      await confirmed((c) => edir(me.directory).split(obj.guid, c));
                      setNotice('Partition started: eDirectory finishes it in the background (see eDirectory → Partitions).');
                    } catch (x) {
                      setActionError(x);
                    }
                  }}>Make this a partition</DropdownItem>
                )}
                <DropdownItem onClick={() => { setMenu(false); setDialog({ kind: 'delete' }); }} isDanger>Delete</DropdownItem>
              </DropdownList>}
            </Dropdown>
          </FlexItem>
        )}
      </Flex>

      <ProblemAlert error={actionError} />
      {notice && <Alert variant="success" isInline isPlain title={notice} actionClose={<AlertActionCloseButton onClose={() => setNotice(null)} />} />}
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
                      {!values.some(isWithheld) && <Button variant="link" isInline onClick={() => setDialog({ kind: 'attr', attribute: name })} aria-label={`Edit ${name}`}>Edit</Button>}
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        </Tab>
        {user && (
          <Tab eventKey="account" title={<TabTitleText>Account</TabTitleText>}>
            <AccountTab obj={obj} onChanged={refreshed} />
          </Tab>
        )}
        {user && (
          <Tab eventKey="groups" title={<TabTitleText>Groups</TabTitleText>}>
            <UserGroupsTab obj={obj} onChanged={refreshed} />
          </Tab>
        )}
        {group && (
          <Tab eventKey="members" title={<TabTitleText>Members</TabTitleText>}>
            <GroupMembersTab obj={obj} etag={etag} onChanged={refreshed} />
          </Tab>
        )}
        <Tab eventKey="rights" title={<TabTitleText>Rights</TabTitleText>}>
          <RightsTab obj={obj} etag={etag} onChanged={refreshed} />
        </Tab>
        <Tab eventKey="replicas" title={<TabTitleText>Replicas</TabTitleText>}>
          <ReplicasTab obj={obj} />
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
            <Plain term="Read from" value={obj.servedBy?.dn} />
          </DescriptionList>
        </Tab>
      </Tabs>

      {dialog?.kind === 'attr' && <AttributeModal obj={obj} etag={etag} allowed={allowed} initial={dialog.attribute} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'rename' && <RenameModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'move' && <MoveModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'password' && <PasswordModal obj={obj} onClose={() => setDialog(null)} onDone={() => { setDialog(null); setNotice('Password set.'); refreshed(); }} />}
      {confirmDialog}
      {dialog?.kind === 'preset' && (
        <PresetModal obj={obj} preset={dialog.preset} onClose={() => setDialog(null)}
          onDone={(changed) => { setDialog(null); setNotice(changed.length ? `${dialog.preset.name}: done.` : `${dialog.preset.name}: nothing to change.`); refreshed(); }} />
      )}
      {dialog?.kind === 'aux' && <AuxClassModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDone={done} />}
      {dialog?.kind === 'delete' && (
        <DeleteModal obj={obj} etag={etag} onClose={() => setDialog(null)} onDeleted={() => { setDialog(null); onChanged?.(null); }} />
      )}
    </HeadingLevel.Provider>
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
