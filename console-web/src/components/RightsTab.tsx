import { useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Flex,
  FlexItem, Form, FormGroup, FormSelect, FormSelectOption, Label, LabelGroup, Modal, ModalBody, ModalFooter, ModalHeader,
  Radio, Spinner, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Acl, type DirObject, type Rights, type Row, isAcl } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { ReferenceLink } from './ValueView';
import { ObjectPicker } from './ObjectPicker';
import { Target } from './Edit';
import { useHeading } from '../heading';

const ENTRY = ['browse', 'add', 'delete', 'rename', 'supervisor'];
const ATTRIBUTE = ['compare', 'read', 'write', 'self', 'supervisor'];
const SPECIAL = ['[Public]', '[Root]', '[Self]', '[Creator]'];
const MASK = '[Inheritance Mask]';

function trusteeOf(a: Acl) {
  return 'special' in a.trustee ? a.trustee.special : a.trustee.dn;
}

/** Trustees of this object, its Inherited Rights Filter, and the effective rights of anyone on it. */
export function RightsTab({ obj, etag, onChanged }: { obj: DirObject; etag: string; onChanged: () => void }) {
  const { can } = useSession();
  const acls = (obj.attributes.ACL ?? []).filter(isAcl);
  const trustees = acls.filter((a) => trusteeOf(a) !== MASK);
  const masks = acls.filter((a) => trusteeOf(a) === MASK);
  const [dialog, setDialog] = useState<null | { mode: 'trustee' | 'irf'; initial?: Acl }>(null);
  const [error, setError] = useState<unknown>(null);
  const { tree } = useSession();
  const editor = can('editor');
  const level = useHeading();

  const remove = async (a: Acl) => {
    setError(null);
    try {
      await tree.modify(obj.guid, etag, [{ op: 'remove', attribute: 'ACL', values: [a] }]);
      onChanged();
    } catch (e) {
      setError(e);
    }
  };

  const rows = (list: Acl[], label: string) => (
    <Table aria-label={label} variant="compact">
      <Thead>
        <Tr>
          <Th>{label === 'Inherited Rights Filter' ? 'Filter' : 'Trustee'}</Th>
          <Th>Applies to</Th>
          <Th>{label === 'Inherited Rights Filter' ? 'Rights allowed to flow down' : 'Rights'}</Th>
          <Th>Inherited below</Th>
          {editor && <Th screenReaderText="Actions" />}
        </Tr>
      </Thead>
      <Tbody>
        {list.map((a, i) => (
          <Tr key={i}>
            <Td dataLabel="Trustee">{'special' in a.trustee ? <code>{a.trustee.special}</code> : <ReferenceLink dn={a.trustee.dn} name={a.trustee.name} />}</Td>
            <Td dataLabel="Applies to">{a.attribute === '[Entry Rights]' ? 'the object' : a.attribute === '[All Attributes Rights]' ? 'all attributes' : <code>{a.attribute}</code>}</Td>
            <Td dataLabel="Rights"><LabelGroup numLabels={6}>{a.privileges.length ? a.privileges.map((p) => <Label key={p} isCompact color={p === 'supervisor' ? 'orange' : 'blue'}>{p}</Label>) : <Label isCompact>none</Label>}</LabelGroup></Td>
            <Td dataLabel="Inherited below">{a.scope === 'subtree' ? 'yes' : 'no'}</Td>
            {editor && (
              <Td isActionCell>
                <Button variant="link" isInline onClick={() => setDialog({ mode: label === 'Inherited Rights Filter' ? 'irf' : 'trustee', initial: a })}>Edit</Button>{' '}
                <Button variant="link" isInline isDanger onClick={() => remove(a)}>Remove</Button>
              </Td>
            )}
          </Tr>
        ))}
      </Tbody>
    </Table>
  );

  return (
    <div className="dc-tab-body">
      <Title headingLevel={level}>Trustees</Title>
      {editor && (
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem><Button variant="secondary" icon={<PlusIcon />} onClick={() => setDialog({ mode: 'trustee' })}>Add a trustee</Button></ToolbarItem>
            <ToolbarItem><Button variant="secondary" onClick={() => setDialog({ mode: 'irf' })}>Add to the Inherited Rights Filter</Button></ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      )}
      <ProblemAlert error={error} />
      {trustees.length === 0 ? <p className="dc-subtle">No trustees assigned here (or you may not read them).</p> : rows(trustees, 'Trustees')}
      <Title headingLevel={level} className="dc-tab-body">Inherited Rights Filter</Title>
      {masks.length === 0 ? <p className="dc-subtle">No filter: inherited rights flow down unchanged.</p> : rows(masks, 'Inherited Rights Filter')}
      <EffectiveRights obj={obj} />
      {dialog && (
        <AclModal obj={obj} etag={etag} mode={dialog.mode} initial={dialog.initial}
          onClose={() => setDialog(null)} onDone={() => { setDialog(null); onChanged(); }} />
      )}
    </div>
  );
}

function AclModal({ obj, etag, mode, initial, onClose, onDone }: {
  obj: DirObject; etag: string; mode: 'trustee' | 'irf'; initial?: Acl; onClose: () => void; onDone: () => void;
}) {
  const { tree } = useSession();
  const [trustee, setTrustee] = useState<{ dn?: string; name?: string; special?: string } | null>(
    mode === 'irf' ? { special: MASK } : initial ? ('special' in initial.trustee ? { special: initial.trustee.special } : { dn: initial.trustee.dn, name: initial.trustee.name }) : null);
  const [appliesTo, setAppliesTo] = useState(initial?.attribute ?? '[Entry Rights]');
  const kind: 'entry' | 'all' | 'one' = appliesTo === '[Entry Rights]' ? 'entry' : appliesTo === '[All Attributes Rights]' ? 'all' : 'one';
  const [attribute, setAttribute] = useState(kind === 'one' ? appliesTo : '');
  const [privileges, setPrivileges] = useState<string[]>(initial?.privileges ?? (mode === 'irf' ? [...ENTRY] : ['browse']));
  const [inherit, setInherit] = useState(initial ? initial.scope === 'subtree' : true);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const names = kind === 'entry' ? ENTRY : ATTRIBUTE;

  const pick = (k: 'entry' | 'all' | 'one') => {
    setAppliesTo(k === 'entry' ? '[Entry Rights]' : k === 'all' ? '[All Attributes Rights]' : attribute || 'description');
    setPrivileges(mode === 'irf' ? (k === 'entry' ? [...ENTRY] : [...ATTRIBUTE]) : k === 'entry' ? ['browse'] : ['compare', 'read']);
  };

  const save = async () => {
    if (!trustee) {
      return;
    }
    setBusy(true);
    setError(null);
    const value = {
      privileges,
      scope: inherit ? 'subtree' : 'entry',
      trustee: trustee.special ? { special: trustee.special } : { dn: trustee.dn },
      attribute: kind === 'one' ? attribute.trim() : appliesTo,
    };
    try {
      const changes = initial
        ? [{ op: 'remove' as const, attribute: 'ACL', values: [initial] }, { op: 'add' as const, attribute: 'ACL', values: [value] }]
        : [{ op: 'add' as const, attribute: 'ACL', values: [value] }];
      await tree.modify(obj.guid, etag, changes);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const blocksSupervisor = mode === 'irf' && kind === 'entry' && !privileges.includes('supervisor');
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="acl-title">
      <ModalHeader title={mode === 'irf' ? 'Inherited Rights Filter' : initial ? 'Change a trustee\'s rights' : 'Add a trustee'} labelId="acl-title" />
      <ModalBody>
        <Form id="acl-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <Target obj={obj} />
          {mode === 'trustee' && (
            <FormGroup label="Trustee" fieldId="trustee" isRequired>
              {trustee
                ? (
                  <Flex spaceItems={{ default: 'spaceItemsSm' }}>
                    <FlexItem>{trustee.special ? <code>{trustee.special}</code> : <><strong>{trustee.name}</strong> <span className="dc-mono dc-subtle">{trustee.dn}</span></>}</FlexItem>
                    {!initial && <FlexItem><Button variant="link" isInline onClick={() => setTrustee(null)}>Change</Button></FlexItem>}
                  </Flex>
                )
                : (
                  <>
                    <ObjectPicker label="Find a user, group or container" onPick={(r: Row) => setTrustee({ dn: r.dn, name: r.name })} />
                    <FormSelect id="special" aria-label="Or a special trustee" value="" className="dc-tab-body"
                      onChange={(_e, v) => v && setTrustee({ special: v })}>
                      <FormSelectOption value="" label="Or a special trustee…" />
                      {SPECIAL.map((s) => <FormSelectOption key={s} value={s} label={s} />)}
                    </FormSelect>
                  </>
                )}
            </FormGroup>
          )}
          <FormGroup role="radiogroup" label="Applies to" fieldId="applies" isInline>
            <Radio id="k-entry" name="applies" label="The object" isChecked={kind === 'entry'} onChange={() => pick('entry')} />
            <Radio id="k-all" name="applies" label="All attributes" isChecked={kind === 'all'} onChange={() => pick('all')} />
            <Radio id="k-one" name="applies" label="One attribute" isChecked={kind === 'one'} onChange={() => pick('one')} />
          </FormGroup>
          {kind === 'one' && (
            <FormGroup label="Attribute" fieldId="attr" isRequired>
              <TextInput id="attr" value={attribute} onChange={(_e, v) => { setAttribute(v); setAppliesTo(v); }} list="attribute-names-acl" />
            </FormGroup>
          )}
          <FormGroup role="group" label={mode === 'irf' ? 'Rights allowed to flow down' : 'Rights'} fieldId="rights" isInline>
            {names.map((n) => (
              <Checkbox key={n} id={`r-${n}`} label={n} isChecked={privileges.includes(n)}
                onChange={(_e, v) => setPrivileges(v ? [...privileges, n] : privileges.filter((p) => p !== n))} />
            ))}
          </FormGroup>
          {mode === 'trustee' && (
            <Checkbox id="inherit" label="Inherited by objects below this one" isChecked={inherit} onChange={(_e, v) => setInherit(v)} />
          )}
          {blocksSupervisor && (
            <Alert variant="warning" isInline title="This filter blocks inherited Supervisor">
              Administrators who get their rights from above lose control of this object and everything below it. The console only
              accepts it when some trustee holds explicit Supervisor on this object.
            </Alert>
          )}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="acl-form" isLoading={busy} isDisabled={busy || !trustee || (kind === 'one' && !attribute.trim())}>Save</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Effective rights of the signed-in person or anyone else on this object, optionally for one attribute. */
function EffectiveRights({ obj }: { obj: DirObject }) {
  const { tree, me } = useSession();
  const level = useHeading();
  const [who, setWho] = useState<{ guid?: string; name: string } | null>(null);
  const [attribute, setAttribute] = useState('');
  const [rights, setRights] = useState<Rights | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [picking, setPicking] = useState(false);
  const [busy, setBusy] = useState(false);

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setRights(await tree.rights(obj.guid, who?.guid, attribute.trim() || undefined));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { check(); }, [who]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="dc-tab-body">
      <Title headingLevel={level}>Effective rights</Title>
      <Flex spaceItems={{ default: 'spaceItemsSm' }} alignItems={{ default: 'alignItemsCenter' }} className="dc-tab-body">
        <FlexItem>Of <strong>{who ? who.name : `${me.name} (you)`}</strong></FlexItem>
        <FlexItem><Button variant="link" isInline onClick={() => setPicking(!picking)}>{picking ? 'Cancel' : 'Someone else'}</Button></FlexItem>
        {who && <FlexItem><Button variant="link" isInline onClick={() => setWho(null)}>Back to you</Button></FlexItem>}
        <FlexItem>
          <TextInput aria-label="Attribute (optional)" placeholder="Attribute (optional)" value={attribute} onChange={(_e, v) => setAttribute(v)} className="dc-narrow" />
        </FlexItem>
        <FlexItem><Button variant="secondary" onClick={check} isLoading={busy}>Check</Button></FlexItem>
      </Flex>
      {picking && <ObjectPicker label="Find a user, group or container" onPick={(r) => { setWho({ guid: r.guid, name: r.name }); setPicking(false); }} />}
      <ProblemAlert error={error} />
      {!rights && !error && <Spinner size="md" aria-label="Loading rights" />}
      {rights && (
        <DescriptionList isHorizontal isCompact className="dc-tab-body">
          <Group term="On the object" values={rights.entry} />
          <Group term="On all attributes" values={rights.allAttributes} />
          {rights.attribute && <Group term={`On ${rights.attribute.name}`} values={rights.attribute.rights} />}
        </DescriptionList>
      )}
    </div>
  );
}

function Group({ term, values }: { term: string; values: string[] }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>
        <LabelGroup numLabels={6}>{values.length ? values.map((v) => <Label key={v} isCompact color={v === 'supervisor' ? 'orange' : 'blue'}>{v}</Label>) : <Label isCompact>none</Label>}</LabelGroup>
      </DescriptionListDescription>
    </DescriptionListGroup>
  );
}
