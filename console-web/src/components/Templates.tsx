import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Flex, FlexItem, Form, FormGroup, FormSelect, FormSelectOption, Label, LabelGroup, Modal, ModalBody, ModalFooter, ModalHeader,
  SearchInput, Spinner, Tab, Tabs, TabTitleText, TextArea, TextInput,
} from '@patternfly/react-core';
import { PlusIcon, TrashIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Template, type TemplateRef, type TemplateToken, idm } from '../api';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

const TOKEN_NAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

/**
 * The e-mail notification templates Identity Manager's senders use (password notices, approvals, workflow mail):
 * each a subject and an XHTML message in which $token$ markers are filled in when it is sent.
 */
export function TemplatesPanel() {
  const { me, can } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const [items, setItems] = useState<TemplateRef[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const load = useCallback(() => { setError(null); api.templates().then(setItems, setError); }, [api]);
  useEffect(load, [load]);

  if (!items) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Reading templates" />}</div>;
  }
  const f = filter.trim().toLowerCase();
  const shown = items.filter((t) => !f || t.name.toLowerCase().includes(f) || (t.subject ?? '').toLowerCase().includes(f) || (t.package ?? '').toLowerCase().includes(f));
  return (
    <div className="dc-tab-body">
      <Flex alignItems={{ default: 'alignItemsCenter' }}>
        <FlexItem><SearchInput placeholder="Filter by name, subject or package" aria-label="Filter templates" value={filter} onChange={(_e, v) => setFilter(v)} onClear={() => setFilter('')} /></FlexItem>
        <FlexItem><span className="dc-subtle">{f ? `${shown.length} of ${items.length}` : items.length} template{items.length === 1 ? '' : 's'}</span></FlexItem>
        {can('operator') && <FlexItem><Button variant="secondary" size="sm" icon={<PlusIcon />} onClick={() => setCreating(true)}>New template</Button></FlexItem>}
      </Flex>
      {shown.length === 0 ? <p className="dc-subtle dc-tab-body">No templates{f ? ' match' : ''}.</p> : (
        <Table aria-label="E-mail templates" variant="compact" className="dc-tab-body">
          <Thead><Tr><Th>Template</Th><Th>Subject</Th><Th>Package</Th></Tr></Thead>
          <Tbody>
            {shown.map((t) => (
              <Tr key={t.dn}>
                <Td dataLabel="Template"><Button variant="link" isInline onClick={() => setOpen(t.guid)}>{t.name}</Button></Td>
                <Td dataLabel="Subject">{t.subject ?? ''}</Td>
                <Td dataLabel="Package">{t.package ?? <span className="dc-subtle">—</span>}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {open && <TemplateEditor guid={open} onClose={() => setOpen(null)} onChanged={load} />}
      {creating && <NewTemplate templates={items} onClose={() => setCreating(false)} onMade={(g) => { setCreating(false); load(); setOpen(g); }} />}
    </div>
  );
}

/** The message as the recipient sees it, with each $token$ marked; in a sandbox, so nothing in it runs or navigates. */
function preview(message: string, text: boolean): string {
  const doc = new DOMParser().parseFromString('<!doctype html><html><body></body></html>', 'text/html');
  if (text) {
    message.split('\n').forEach((line, i) => {
      if (i > 0) {
        doc.body.appendChild(doc.createElement('br'));
      }
      doc.body.appendChild(doc.createTextNode(line));
    });
  } else {
    doc.body.innerHTML = message;
  }
  const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
  const texts: Text[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    texts.push(n as Text);
  }
  for (const t of texts) {
    const parts = (t.nodeValue ?? '').split(/(\$[A-Za-z_][A-Za-z0-9_.-]*\$)/);
    if (parts.length === 1) {
      continue;
    }
    const frag = doc.createDocumentFragment();
    parts.forEach((p, i) => {
      if (i % 2 === 1) {
        const m = doc.createElement('mark');
        m.textContent = p;
        frag.appendChild(m);
      } else if (p) {
        frag.appendChild(doc.createTextNode(p));
      }
    });
    t.replaceWith(frag);
  }
  // no <style>: the console's content security policy covers the frame too; <mark> is highlighted by default
  return `<!doctype html>${doc.documentElement.outerHTML}`;
}

function TemplateEditor({ guid, onClose, onChanged }: { guid: string; onClose: () => void; onChanged: () => void }) {
  const { me, can } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const operator = can('operator');
  const { run, dialog } = useConfirmed();
  const [t, setT] = useState<Template | null>(null);
  const [subject, setSubject] = useState('');
  const [tokens, setTokens] = useState<TemplateToken[]>([]);
  const [body, setBody] = useState('');
  const [xml, setXml] = useState('');
  // which the save sends: the tokens and body, or the whole document once the XML tab has been edited
  const [mode, setMode] = useState<'message' | 'xml'>('message');
  const [tab, setTab] = useState<string | number>('message');
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const take = (x: Template) => {
    setT(x);
    setSubject(x.subject ?? '');
    setTokens(x.tokens);
    setBody(x.format === 'text' ? x.text ?? '' : x.body ?? '');
    setXml(x.xml ?? '');
    setMode(x.readable ? 'message' : 'xml');
    setTab(x.readable ? 'message' : 'xml');
    setDirty(false);
  };
  useEffect(() => { api.template(guid).then(take, setError); }, [api, guid]);
  const edit = (f: () => void) => { f(); setDirty(true); setNotice(null); };

  const plain = t?.format === 'text';
  const used = useMemo(() => {
    const out = new Set<string>();
    for (const s of [subject, mode === 'xml' ? xml : body]) {
      for (const m of s.matchAll(/\$([A-Za-z_][A-Za-z0-9_.-]*)\$/g)) {
        out.add(m[1]);
      }
    }
    return [...out];
  }, [subject, body, xml, mode]);
  const names = tokens.map((x) => x.name.trim());
  const problem = !subject.trim() ? 'A template needs a subject.'
    : mode === 'message' && names.some((n) => !TOKEN_NAME.test(n)) ? 'A token name is letters, digits, _ . and -, as in $name$.'
      : mode === 'message' && new Set(names).size !== names.length ? 'Two tokens have the same name.' : null;

  const save = () => {
    setBusy(true);
    setError(null);
    const payload = mode === 'xml'
      ? { version: t!.version, subject: subject.trim(), xml }
      : plain
        ? { version: t!.version, subject: subject.trim(), tokens: tokens.map((x) => ({ name: x.name.trim(), description: x.description })), text: body }
        : { version: t!.version, subject: subject.trim(), tokens: tokens.map((x) => ({ name: x.name.trim(), description: x.description })), body };
    run((c) => api.saveTemplate(guid, payload, c)).then((x) => { take(x); onChanged(); setNotice('Saved. It is used from the next notice sent.'); }, setError)
      .finally(() => setBusy(false));
  };
  const remove = () => {
    setBusy(true);
    run((c) => api.deleteTemplate(guid, typed, c)).then(() => { onChanged(); onClose(); }, setError).finally(() => setBusy(false));
  };

  return (
    <Modal isOpen onClose={onClose} variant="large" aria-labelledby="tpl-title">
      <ModalHeader title={t?.name ?? 'Template'} labelId="tpl-title" description={t?.package ? `From the package ${t.package}` : undefined} />
      <ModalBody>
        {!t && !error && <Spinner size="md" aria-label="Reading the template" />}
        {t && (
          <>
            {t.package && operator && (
              <Alert variant="warning" isInline isPlain className="dc-tab-body"
                title={`This template came from the package ${t.package}. Changing it here makes it differ from the package; a package upgrade may replace it.`} />
            )}
            {!t.readable && (
              <Alert variant="warning" isInline isPlain className="dc-tab-body" title="Its message is not well-formed XML, so only the XML can be changed: fix it there." />
            )}
            <Form onSubmit={(e) => e.preventDefault()}>
              <FormGroup label="Subject" fieldId="tpl-subject">
                <TextInput id="tpl-subject" value={subject} isDisabled={!operator} onChange={(_e, v) => edit(() => setSubject(v))} />
              </FormGroup>
            </Form>
            <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Template" className="dc-tab-body">
              {t.readable && (
                <Tab eventKey="message" title={<TabTitleText>Message</TabTitleText>} isAriaDisabled={mode === 'xml'}>
                  <div className="dc-tab-body">
                    <TokensTable tokens={tokens} used={used} operator={operator} onChange={(x) => edit(() => setTokens(x))} />
                    <FormGroup label={plain ? 'Message (plain text)' : 'Message (XHTML)'} fieldId="tpl-body" className="dc-tab-body">
                      <TextArea id="tpl-body" className="dc-mono" rows={16} value={body} isDisabled={!operator} resizeOrientation="vertical"
                        onChange={(_e, v) => edit(() => setBody(v))} />
                    </FormGroup>
                    {!plain && <p className="dc-subtle">XHTML: close every element (&lt;br/&gt;, not &lt;br&gt;) and write &amp;amp; for &amp;.</p>}
                  </div>
                </Tab>
              )}
              {t.readable && (
                <Tab eventKey="preview" title={<TabTitleText>Preview</TabTitleText>} isAriaDisabled={mode === 'xml'}>
                  <div className="dc-tab-body">
                    <p className="dc-subtle">Marked: the tokens filled in when it is sent.</p>
                    {/* made while the tab is open: a sandboxed frame does not show a srcdoc changed after it loaded */}
                    {tab === 'preview' && (
                      <iframe title="Message preview" sandbox="" srcDoc={preview(body, plain)} style={{ width: '100%', height: '24rem', border: '1px solid var(--pf-t--global--border--color--default)' }} />
                    )}
                  </div>
                </Tab>
              )}
              <Tab eventKey="xml" title={<TabTitleText>XML</TabTitleText>}>
                <div className="dc-tab-body">
                  {mode === 'message' && dirty && <Alert variant="info" isInline isPlain title="This is the document as saved: save or discard your changes to see them here." />}
                  <TextArea aria-label="The whole document" className="dc-mono" rows={20} value={mode === 'xml' ? xml : t.xml ?? ''} resizeOrientation="vertical"
                    isDisabled={!operator || (mode === 'message' && dirty)}
                    onChange={(_e, v) => edit(() => { setXml(v); setMode('xml'); })} />
                  {mode === 'xml' && t.readable && <p className="dc-subtle">Saving sends this whole document; the Message tab shows it again after the save.</p>}
                </div>
              </Tab>
            </Tabs>
            {problem && dirty && <Alert variant="danger" isInline isPlain className="dc-tab-body" title={problem} />}
            {notice && <Alert variant="success" isInline isPlain className="dc-tab-body" title={notice} />}
            {deleting && (
              <Alert variant="danger" isInline className="dc-tab-body" title={`Delete the template ${t.name}?`}>
                <p>Whatever sends it will fail to find it. Type its name to confirm.</p>
                <TextInput aria-label="The template's name" value={typed} onChange={(_e, v) => setTyped(v)} />
              </Alert>
            )}
          </>
        )}
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        {operator && t && !deleting && <Button onClick={save} isLoading={busy} isDisabled={busy || !dirty || !!problem}>Save</Button>}
        {operator && t && !deleting && <Button variant="link" isDanger onClick={() => setDeleting(true)}>Delete</Button>}
        {deleting && <Button variant="danger" onClick={remove} isLoading={busy} isDisabled={busy || typed !== t?.name}>Delete the template</Button>}
        <Button variant="link" onClick={deleting ? () => { setDeleting(false); setTyped(''); } : onClose}>{deleting ? 'Keep it' : dirty ? 'Close without saving' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}

/** The token descriptions (what each marker means, for whoever edits the template) and the markers used without one. */
function TokensTable({ tokens, used, operator, onChange }: { tokens: TemplateToken[]; used: string[]; operator: boolean; onChange: (t: TemplateToken[]) => void }) {
  const described = new Set(tokens.map((t) => t.name));
  const undescribed = used.filter((u) => !described.has(u));
  return (
    <>
      <Table aria-label="Tokens" variant="compact">
        <Thead><Tr><Th>Token</Th><Th>Description</Th><Th>Used</Th>{operator && <Th screenReaderText="Remove" />}</Tr></Thead>
        <Tbody>
          {tokens.map((t, i) => (
            <Tr key={i}>
              <Td dataLabel="Token">
                {operator ? <TextInput aria-label={`Token ${i + 1} name`} className="dc-mono" value={t.name} onChange={(_e, v) => onChange(tokens.map((x, j) => (j === i ? { ...x, name: v } : x)))} />
                  : <span className="dc-mono">${t.name}$</span>}
              </Td>
              <Td dataLabel="Description">
                {operator ? <TextInput aria-label={`Token ${t.name} description`} value={t.description} onChange={(_e, v) => onChange(tokens.map((x, j) => (j === i ? { ...x, description: v } : x)))} />
                  : t.description}
              </Td>
              <Td dataLabel="Used">{used.includes(t.name.trim()) ? 'yes' : <span className="dc-subtle">no</span>}</Td>
              {operator && <Td isActionCell><Button variant="plain" aria-label={`Remove token ${t.name}`} onClick={() => onChange(tokens.filter((_, j) => j !== i))}><TrashIcon /></Button></Td>}
            </Tr>
          ))}
        </Tbody>
      </Table>
      {operator && <Button variant="link" size="sm" icon={<PlusIcon />} onClick={() => onChange([...tokens, { name: '', description: '' }])}>Token</Button>}
      {undescribed.length > 0 && (
        <div className="dc-tab-body">
          <span className="dc-subtle">Used without a description (the sender fills these in too, such as its reply address): </span>
          <LabelGroup numLabels={12}>{undescribed.map((u) => <Label key={u} isCompact className="dc-mono">${u}$</Label>)}</LabelGroup>
        </div>
      )}
    </>
  );
}

function NewTemplate({ templates, onClose, onMade }: { templates: TemplateRef[]; onClose: () => void; onMade: (guid: string) => void }) {
  const { me } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const { run, dialog } = useConfirmed();
  const [name, setName] = useState('');
  const [subject, setSubject] = useState('');
  const [copyOf, setCopyOf] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const create = () => {
    setBusy(true);
    setError(null);
    run((c) => api.createTemplate({ name: name.trim(), subject: subject.trim(), copyOf: copyOf || undefined }, c))
      .then((t) => onMade(t.guid), setError).finally(() => setBusy(false));
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="tpl-new">
      <ModalHeader title="New template" labelId="tpl-new" />
      <ModalBody>
        <Form onSubmit={(e) => e.preventDefault()}>
          <FormGroup label="Name" isRequired fieldId="tpl-new-name"><TextInput id="tpl-new-name" value={name} onChange={(_e, v) => setName(v)} /></FormGroup>
          <FormGroup label="Subject" isRequired fieldId="tpl-new-subject"><TextInput id="tpl-new-subject" value={subject} onChange={(_e, v) => setSubject(v)} /></FormGroup>
          <FormGroup label="Start from" fieldId="tpl-new-copy">
            <FormSelect id="tpl-new-copy" value={copyOf} onChange={(_e, v) => setCopyOf(v)}>
              <FormSelectOption value="" label="A blank message" />
              {templates.map((t) => <FormSelectOption key={t.guid} value={t.guid} label={`A copy of ${t.name}`} />)}
            </FormSelect>
          </FormGroup>
        </Form>
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        <Button onClick={create} isLoading={busy} isDisabled={busy || !name.trim() || !subject.trim()}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
