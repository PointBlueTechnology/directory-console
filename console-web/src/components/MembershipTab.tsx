import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Form, FormGroup, Label, Modal, ModalBody, ModalFooter, ModalHeader, Pagination, Spinner, TextArea,
  Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { DirObject, Members, MembershipResult, Reference, Row } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { ReferenceLink } from './ValueView';
import { ObjectPicker } from './ObjectPicker';
import { Target } from './Edit';
import { useHeading } from '../heading';

const GROUPS = ['groupOfNames', 'dynamicGroup'];
const MEMBERS = ['inetOrgPerson', 'groupOfNames'];

/** What a membership change did, one line per pair; failures say which side and whether it was undone. */
function Results({ results }: { results: MembershipResult[] | null }) {
  const level = useHeading();
  if (!results) {
    return null;
  }
  const failed = results.filter((r) => r.status === 'failed');
  if (failed.length === 0) {
    return <Alert component={level} variant="success" isInline isPlain title={`Done: ${results.filter((r) => r.status === 'ok').length} changed, ${results.filter((r) => r.status === 'unchanged').length} already so`} />;
  }
  return (
    <Alert component={level} variant="danger" isInline title={`${failed.length} change(s) failed`}>
      <ul>{failed.map((r, i) => <li key={i}>{r.group.name} / {r.member.name}: {r.detail}</li>)}</ul>
    </Alert>
  );
}

/** A user's groups: membership is written on the group and the user (member, equivalentToMe, groupMembership, securityEquals). */
export function UserGroupsTab({ obj, onChanged }: { obj: DirObject; onChanged: () => void }) {
  const { tree, canAt } = useSession();
  const [groups, setGroups] = useState<(Reference & { securityEquivalent: boolean })[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [results, setResults] = useState<MembershipResult[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => {
    tree.memberships(obj.guid).then((r) => setGroups(r.items)).catch(setError);
  }, [tree, obj.guid]);
  useEffect(load, [load]);

  const change = async (add: (string | { dn: string })[], remove: (string | { dn: string })[]) => {
    setError(null);
    try {
      setResults(await tree.changeMemberships(obj.guid, add, remove));
      load();
      onChanged();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="dc-tab-body">
      {canAt('editor', obj.dn) && (
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem><Button variant="secondary" icon={<PlusIcon />} onClick={() => setAdding(true)}>Add to a group</Button></ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      )}
      <Results results={results} />
      <ProblemAlert error={error} />
      {!groups && !error && <Spinner aria-label="Loading groups" />}
      {groups && groups.length === 0 && <p className="dc-subtle">Not a member of any group.</p>}
      {groups && groups.length > 0 && (
        <Table aria-label="Groups" variant="compact">
          <Thead><Tr><Th>Group</Th><Th>Security equivalence</Th>{canAt('editor', obj.dn) && <Th screenReaderText="Remove" />}</Tr></Thead>
          <Tbody>
            {groups.map((g) => (
              <Tr key={g.dn}>
                <Td dataLabel="Group"><ReferenceLink dn={g.dn} name={g.name} /></Td>
                <Td dataLabel="Security equivalence">{g.securityEquivalent ? 'yes' : <Label color="orange" isCompact>missing</Label>}</Td>
                {canAt('editor', obj.dn) && <Td isActionCell><Button variant="link" isInline isDanger onClick={() => change([], [{ dn: g.dn }])}>Remove</Button></Td>}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {adding && (
        <PickModal title="Add to a group" target={obj} classes={GROUPS} exclude={[]}
          onClose={() => setAdding(false)} onPick={(r) => { setAdding(false); change([r.guid], []); }} />
      )}
    </div>
  );
}

/** A group's members (computed for a dynamic group, whose query is shown and edited instead). */
export function GroupMembersTab({ obj, etag, onChanged }: { obj: DirObject; etag: string; onChanged: () => void }) {
  const { tree, canAt } = useSession();
  const level = useHeading();
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [members, setMembers] = useState<Members | null>(null);
  const [adding, setAdding] = useState(false);
  const [editingQuery, setEditingQuery] = useState(false);
  const [results, setResults] = useState<MembershipResult[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => {
    tree.members(obj.guid, (page - 1) * perPage + 1, perPage).then(setMembers).catch(setError);
  }, [tree, obj.guid, page, perPage]);
  useEffect(load, [load]);

  const change = async (add: (string | { dn: string })[], remove: (string | { dn: string })[]) => {
    setError(null);
    try {
      setResults(await tree.changeMembers(obj.guid, add, remove));
      load();
      onChanged();
    } catch (e) {
      setError(e);
    }
  };
  const editor = obj.allowed ? obj.allowed.edit : canAt('editor', obj.dn);

  return (
    <div className="dc-tab-body">
      {members?.dynamic && (
        <Alert component={level} variant="info" isInline title="Dynamic group: members come from a query">
          <code className="dc-mono">{members.memberQueryURL ?? '(no query)'}</code>
          {editor && <> <Button variant="link" isInline onClick={() => setEditingQuery(true)}>Change the query</Button></>}
        </Alert>
      )}
      <Toolbar>
        <ToolbarContent>
          {editor && !members?.dynamic && (
            <ToolbarItem><Button variant="secondary" icon={<PlusIcon />} onClick={() => setAdding(true)}>Add a member</Button></ToolbarItem>
          )}
          {members?.nested && <ToolbarItem><Label>Nested group</Label></ToolbarItem>}
          <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
            <Pagination itemCount={members?.total ?? 0} page={page} perPage={perPage} isCompact
              onSetPage={(_e, p) => setPage(p)} onPerPageSelect={(_e, pp) => { setPerPage(pp); setPage(1); }} />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <Results results={results} />
      <ProblemAlert error={error} />
      {!members && !error && <Spinner aria-label="Loading members" />}
      {members && members.total === 0 && <p className="dc-subtle">No members.</p>}
      {members && members.items.length > 0 && (
        <Table aria-label="Members" variant="compact">
          <Thead><Tr><Th>Member</Th>{editor && !members.dynamic && <Th screenReaderText="Remove" />}</Tr></Thead>
          <Tbody>
            {members.items.map((m) => (
              <Tr key={m.dn}>
                <Td dataLabel="Member"><ReferenceLink dn={m.dn} name={m.name} /></Td>
                {editor && !members.dynamic && <Td isActionCell><Button variant="link" isInline isDanger onClick={() => change([], [{ dn: m.dn }])}>Remove</Button></Td>}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {adding && (
        <PickModal title="Add a member" target={obj} classes={MEMBERS} exclude={[obj.guid]}
          onClose={() => setAdding(false)} onPick={(r) => { setAdding(false); change([r.guid], []); }} />
      )}
      {editingQuery && members && (
        <QueryModal obj={obj} etag={etag} query={members.memberQueryURL ?? ''} onClose={() => setEditingQuery(false)}
          onDone={() => { setEditingQuery(false); load(); onChanged(); }} />
      )}
    </div>
  );
}

function PickModal({ title, target, classes, exclude, onClose, onPick }: {
  title: string; target: DirObject; classes: string[]; exclude: string[]; onClose: () => void; onPick: (r: Row) => void;
}) {
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="pick-title">
      <ModalHeader title={title} labelId="pick-title" />
      <ModalBody>
        <Target obj={target} />
        <div className="dc-tab-body"><ObjectPicker classes={classes} exclude={exclude} onPick={onPick} /></div>
      </ModalBody>
      <ModalFooter><Button variant="link" onClick={onClose}>Cancel</Button></ModalFooter>
    </Modal>
  );
}

function QueryModal({ obj, etag, query, onClose, onDone }: { obj: DirObject; etag: string; query: string; onClose: () => void; onDone: () => void }) {
  const { tree } = useSession();
  const [text, setText] = useState(query);
  const [error, setError] = useState<unknown>(null);
  const save = async () => {
    try {
      await tree.modify(obj.guid, etag, [{ op: 'replace', attribute: 'memberQueryURL', values: [text.trim()] }]);
      onDone();
    } catch (e) {
      setError(e);
    }
  };
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="query-title">
      <ModalHeader title="Dynamic group query" labelId="query-title" />
      <ModalBody>
        <Form id="query-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <Target obj={obj} />
          <FormGroup label="Member query (LDAP URL)" fieldId="query" isRequired>
            <TextArea id="query" className="dc-mono" value={text} onChange={(_e, v) => setText(v)} rows={3}
              placeholder="ldap:///ou=staff,o=acme??sub?(objectClass=inetOrgPerson)" />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="query-form" isDisabled={!text.trim().startsWith('ldap:///')}>Save</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
