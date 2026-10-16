import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, CardBody, CardTitle, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Flex, FlexItem,
  Form, FormGroup, Label, LabelGroup, Modal, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, Tab, Tabs, TabTitleText, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type Certificate, type EbaState, type EdirServer, type SequenceRequest, type LoginPolicy, type PasswordPolicySummary, type Pki, edir, pem, security } from '../api';
import { useSession } from '../session';
import { linkProps, navigate } from '../router';
import { useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { NewCertificateModal } from '../components/NewCertificate';
import { SequenceModal } from '../components/SequenceModal';
import { RevokeModal, revokedNotice } from '../components/RevokeCertificate';
import { ExportKeyModal } from '../components/ExportKey';
import { DefaultCertificatesModal } from '../components/DefaultCertificates';
import { CaConfigurationPanel } from '../components/CaConfiguration';
import { ExpiryLabel, Fingerprint, WARN_DAYS } from '../components/Certificates';
import { Hint, useHelpTopic } from '../help/Help';
import { explain, tip } from '../help/glossary';

const DAY = 86_400_000;
function download(name: string, text: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function fileName(s: string) {
  return s.replace(/[^A-Za-z0-9._-]+/g, '_');
}

/** Security services: the tree's certificates, password policies, challenge sets and login methods. */
export function SecurityPage({ tab = 'certificates' }: { tab?: string }) {
  useHelpTopic(`security.${tab}`);
  const go = (k: string | number) => navigate(k === 'certificates' ? '/security' : `/security/${k}`);
  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Security</Title>
      <Tabs activeKey={tab} onSelect={(_e, k) => go(k)} aria-label="Security" mountOnEnter unmountOnExit className="dc-tab-body">
        <Tab eventKey="certificates" title={<TabTitleText>Certificates</TabTitleText>}><CertificatesView /></Tab>
        <Tab eventKey="password-policies" title={<TabTitleText>Password policies</TabTitleText>}><PoliciesView /></Tab>
        <Tab eventKey="challenge-sets" title={<TabTitleText>Challenge sets</TabTitleText>}><ChallengeSetsView /></Tab>
        <Tab eventKey="login-methods" title={<TabTitleText>Login methods</TabTitleText>}><LoginMethodsView /></Tab>
        <Tab eventKey="eba" title={<TabTitleText>EBA</TabTitleText>}><EbaView /></Tab>
      </Tabs>
    </PageSection>
  );
}

function CertificatesView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [pki, setPki] = useState<Pki | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [servers, setServers] = useState<EdirServer[]>([]);
  const [creating, setCreating] = useState(false);
  const [defaults, setDefaults] = useState(false);
  const [opError, setOpError] = useState<unknown>(null);
  const [revoking, setRevoking] = useState<Pki['serverCertificates'][number] | null>(null);
  const [exporting, setExporting] = useState<Pki['serverCertificates'][number] | null>(null);
  const [opNotice, setOpNotice] = useState<string | null>(null);
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  const level = useHeading();
  // making and deleting certificates changes the whole tree's PKI: an editor of the whole tree
  const editor = canAt('editor', '');
  const load = useCallback(() => { api.pki().then(setPki).catch(setError); }, [api]);
  useEffect(load, [load]);
  useEffect(() => { if (editor) { edir(me.directory).servers().then(setServers).catch(() => setServers([])); } }, [editor, me.directory]);
  const remove = (k: Pki['serverCertificates'][number]) => sure.ask(`Delete ${k.name}?`,
    `The key pair and certificate go with it; nothing can bring them back. Clients that trust it by this certificate (not the directory CA) will stop trusting ${k.server?.name ?? 'the server'}.`,
    'Delete', () => {
      setOpError(null);
      confirmed.run((c) => api.deleteServerCertificate(k.guid!, c)).then(load, setOpError);
    });
  if (!pki) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Reading the directory's certificates" />;
  }
  // everything with an expiry, for the summary
  const all: { what: string; name: string; cert: Certificate }[] = [
    ...(pki.ca?.certificates ?? []).map((c) => ({ what: 'Organizational CA', name: pki.ca!.name, cert: c })),
    ...pki.serverCertificates.filter((k) => k.certificate && !k.certificate.error).map((k) => ({ what: 'Server certificate', name: k.name, cert: k.certificate! })),
    ...pki.trustedRoots.filter((t) => t.certificate && !t.certificate.error).map((t) => ({ what: 'Trusted root', name: t.name, cert: t.certificate! })),
  ];
  const now = Date.now();
  const expired = all.filter((x) => Date.parse(x.cert.notAfter) < now);
  const soon = all.filter((x) => Date.parse(x.cert.notAfter) >= now && Date.parse(x.cert.notAfter) - now <= WARN_DAYS * DAY);
  return (
    <div className="dc-tab-body">
      {expired.length > 0 && (
        <Alert component={level} variant="danger" isInline title={`${expired.length} certificate${expired.length === 1 ? ' has' : 's have'} expired`}>
          {expired.map((x) => <div key={x.what + x.name + x.cert.sha256}>{x.what}: <strong>{x.name}</strong> on {new Date(x.cert.notAfter).toLocaleDateString()}</div>)}
        </Alert>
      )}
      {soon.length > 0 && (
        <Alert component={level} variant="warning" isInline title={`${soon.length} certificate${soon.length === 1 ? ' expires' : 's expire'} within ${WARN_DAYS} days`} className="dc-tab-body">
          {soon.map((x) => <div key={x.what + x.name + x.cert.sha256}>{x.what}: <strong>{x.name}</strong> on {new Date(x.cert.notAfter).toLocaleDateString()}</div>)}
        </Alert>
      )}

      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">Organizational CA</Title></CardTitle>
        <CardBody>
          {!pki.ca ? <p>This directory has no Organizational CA.</p> : (
            <>
              <p><strong>{pki.ca.name}</strong> on <span className="dc-mono">{pki.ca.host}</span> · default key {pki.ca.defaultRsaKeySize} bits, certificates for {pki.ca.defaultLifeYears} years</p>
              <Table aria-label="CA certificates" variant="compact">
                <Thead><Tr><Th>Key</Th><Th>Subject</Th><Th>Valid until</Th><Th>SHA-256</Th><Th screenReaderText="Download" /></Tr></Thead>
                <Tbody>
                  {pki.ca.certificates.map((c) => (
                    <Tr key={c.sha256}>
                      <Td dataLabel="Key">{c.key}</Td>
                      <Td dataLabel="Subject" className="dc-mono">{c.subject}</Td>
                      <Td dataLabel="Valid until"><ExpiryLabel notAfter={c.notAfter} /></Td>
                      <Td dataLabel="SHA-256"><Fingerprint sha256={c.sha256} /></Td>
                      <Td isActionCell><Button variant="link" isInline onClick={() => download(fileName(`${pki.ca!.name}-${c.key}.pem`), pem(c.der))}>Download</Button></Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              {pki.ca.configuration && (
                <>
                  <Title headingLevel="h3" size="md" className="dc-tab-body">Configuration</Title>
                  <CaConfigurationPanel value={pki.ca.configuration} certificates={pki.ca.certificates} editor={editor}
                    save={(change) => confirmed.run((c) => api.caConfiguration(change, c))} />
                </>
              )}
            </>
          )}
        </CardBody>
      </Card>

      <Card className="dc-tab-body">
        <CardTitle><Flex><FlexItem grow={{ default: 'grow' }}><Title headingLevel="h2" size="lg">Server certificates</Title></FlexItem>
          {editor && pki.ca && <FlexItem><Hint text={explain('defaultCertificates')}><Button variant="secondary" onClick={() => setDefaults(true)} isAriaDisabled={servers.length === 0}>Default certificates…</Button></Hint></FlexItem>}
          {editor && pki.ca && <FlexItem><Button variant="secondary" onClick={() => setCreating(true)} isDisabled={servers.length === 0}>New server certificate</Button></FlexItem>}
        </Flex></CardTitle>
        <CardBody>
          <ProblemAlert error={opError} />
          {opNotice && <Alert component={level} variant="success" isInline isPlain title={opNotice} />}
          <Table aria-label="Server certificates" variant="compact">
            <Thead><Tr><Th>Certificate</Th><Th>Server</Th><Th>Used by</Th><Th>Key</Th><Th>Names</Th><Th>Valid until</Th><Th screenReaderText="Download" /></Tr></Thead>
            <Tbody>
              {pki.serverCertificates.map((k) => (
                <Tr key={k.dn}>
                  <Td dataLabel="Certificate">{k.guid ? <a {...linkProps(`/objects/${k.guid}`)}>{k.name}</a> : k.name}</Td>
                  <Td dataLabel="Server">{k.server?.name ?? '—'}</Td>
                  <Td dataLabel="Used by">{k.usedBy.length ? <LabelGroup>{k.usedBy.map((u) => <Label key={u} isCompact>{u}</Label>)}</LabelGroup> : <span className="dc-subtle">nothing found</span>}</Td>
                  <Td dataLabel="Key">{k.certificate?.key ?? '—'}</Td>
                  <Td dataLabel="Names" className="dc-mono">{k.certificate?.subjectAltNames.join(', ') || '—'}</Td>
                  <Td dataLabel="Valid until"><ExpiryLabel notAfter={k.certificate?.notAfter} /></Td>
                  <Td isActionCell>
                    {k.certificate?.der && <Button variant="link" isInline onClick={() => download(fileName(`${k.name}.pem`),
                      [k.certificate!, ...k.chain].map((c) => pem(c.der)).join(''))}>Download</Button>}
                    {editor && k.guid && k.certificate && (
                      <Hint text="A password-protected .pfx file with the private key and chain, if the certificate allows export.">
                        <Button variant="link" isInline className="dc-gap-left" onClick={() => setExporting(k)}>Export with key</Button>
                      </Hint>
                    )}
                    {editor && k.guid && k.certificate && (
                      <Button variant="link" isInline className="dc-gap-left" onClick={() => { setOpNotice(null); setRevoking(k); }}>Revoke</Button>
                    )}
                    {editor && k.guid && (
                      <Hint text={k.usedBy.length > 0 ? `In use by ${k.usedBy.join(', ')}` : undefined}>
                        <Button variant="link" isInline isDanger isAriaDisabled={k.usedBy.length > 0} className="dc-gap-left" onClick={() => remove(k)}>Delete</Button>
                      </Hint>
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
          <p className="dc-subtle">Download gives the public certificate and its chain. Export with key gives a password-protected .pfx file with the private key, for a certificate made with export allowed; it needs a recent sign-in and is audited. A certificate an LDAP server uses cannot be deleted.</p>
          {creating && (
            <NewCertificateModal kind="server" servers={servers.map((x) => ({ guid: x.guid, name: x.name }))}
              onCreate={(body, server) => confirmed.run((c) => api.createServerCertificate(server!, body, c)).then(load)}
              onClose={() => setCreating(false)} />
          )}
          {defaults && <DefaultCertificatesModal servers={servers} onClose={() => setDefaults(false)} onChanged={load} />}
          {exporting && (
            <ExportKeyModal name={exporting.name} onClose={() => setExporting(null)}
              onExport={(body) => api.exportServerCertificate(exporting.guid!, body)} />
          )}
          {revoking && (
            <RevokeModal name={revoking.name} onClose={() => setRevoking(null)}
              onRevoke={(r) => confirmed.run((c) => api.revokeServerCertificate(revoking.guid!, r, c))}
              onDone={(r) => setOpNotice(revokedNotice(revoking.name, r))} />
          )}
          {confirmed.dialog}
          {sure.dialog}
        </CardBody>
      </Card>

      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">Trusted roots</Title></CardTitle>
        <CardBody>
          {pki.trustedRoots.length === 0 ? <p>None.</p> : (
            <Table aria-label="Trusted roots" variant="compact">
              <Thead><Tr><Th>Root</Th><Th>Container</Th><Th>Subject</Th><Th>Valid until</Th></Tr></Thead>
              <Tbody>
                {pki.trustedRoots.map((t) => (
                  <Tr key={t.dn}>
                    <Td dataLabel="Root">{t.name}</Td>
                    <Td dataLabel="Container" className="dc-mono">{t.container}</Td>
                    <Td dataLabel="Subject" className="dc-mono">{t.certificate?.subject ?? '—'}</Td>
                    <Td dataLabel="Valid until"><ExpiryLabel notAfter={t.certificate?.notAfter} /></Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">Certificate revocation lists</Title></CardTitle>
        <CardBody>
          {pki.crls.length === 0 ? <p>None configured.</p> : (
            <Table aria-label="CRLs" variant="compact">
              <Thead><Tr><Th>Configuration</Th><Th>Type</Th><Th>Number</Th><Th>Issued</Th><Th>Next</Th><Th>Revoked</Th><Th>Published at</Th></Tr></Thead>
              <Tbody>
                {pki.crls.map((c) => (
                  <Tr key={c.dn}>
                    <Td dataLabel="Configuration">{c.name}</Td>
                    <Td dataLabel="Type">{c.type.toUpperCase()}</Td>
                    <Td dataLabel="Number">{c.number ?? '—'}</Td>
                    <Td dataLabel="Issued">{c.issued ? new Date(c.issued).toLocaleString() : '—'}</Td>
                    <Td dataLabel="Next">{c.nextIssue ? new Date(c.nextIssue).toLocaleString() : '—'}</Td>
                    <Td dataLabel="Revoked">{c.revoked ?? '—'}</Td>
                    <Td dataLabel="Published at">{c.distributionPoints.map((d) => <div key={d} className="dc-mono">{d}</div>)}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function PoliciesView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [list, setList] = useState<PasswordPolicySummary[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => { api.policies().then(setList).catch(setError); }, [api]);
  if (!list) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Loading" />;
  }
  return (
    <div className="dc-tab-body">
      {canAt('editor', '') && <Button variant="secondary" onClick={() => setCreating(true)}>New password policy</Button>}
      <Table aria-label="Password policies" variant="compact" className="dc-tab-body">
        <Thead><Tr><Th>Policy</Th><Th info={tip('universalPassword')}>Universal Password</Th><Th>Length</Th><Th>Assigned to</Th></Tr></Thead>
        <Tbody>
          {list.map((p) => (
            <Tr key={p.dn}>
              <Td dataLabel="Policy"><a {...linkProps(`/security/password-policies/${p.guid}`)}>{p.name}</a>{p.description && <div className="dc-subtle">{p.description}</div>}</Td>
              <Td dataLabel="Universal Password">{p.universalPassword ? <Label isCompact color="green">on</Label> : <Label isCompact>off</Label>}</Td>
              <Td dataLabel="Length">{p.minLength ?? '—'}–{p.maxLength ?? '—'}</Td>
              <Td dataLabel="Assigned to">{p.assignments} object{p.assignments === 1 ? '' : 's'}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      {creating && <NameModal title="New password policy" onClose={() => setCreating(false)}
        onCreate={(name, c) => api.createPolicy({ name }, c).then((p) => navigate(`/security/password-policies/${p.guid}`))} />}
    </div>
  );
}

function ChallengeSetsView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [list, setList] = useState<Awaited<ReturnType<typeof api.challengeSets>> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => { api.challengeSets().then(setList).catch(setError); }, [api]);
  if (!list) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Loading" />;
  }
  return (
    <div className="dc-tab-body">
      {canAt('editor', '') && <Button variant="secondary" onClick={() => setCreating(true)}>New challenge set</Button>}
      <Table aria-label="Challenge sets" variant="compact" className="dc-tab-body">
        <Thead><Tr><Th>Challenge set</Th><Th>Required questions</Th><Th>Random questions</Th></Tr></Thead>
        <Tbody>
          {list.map((c) => (
            <Tr key={c.dn}>
              <Td dataLabel="Challenge set"><a {...linkProps(`/security/challenge-sets/${c.guid}`)}>{c.name}</a>{c.description && <div className="dc-subtle">{c.description}</div>}</Td>
              <Td dataLabel="Required questions">{c.required}</Td>
              <Td dataLabel="Random questions">{c.randomCount} of {c.random}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      {creating && <NameModal title="New challenge set" onClose={() => setCreating(false)}
        onCreate={(name, c) => api.createChallengeSet({ name, required: [], random: [], randomCount: 0 }, c).then((s) => navigate(`/security/challenge-sets/${s.guid}`))} />}
    </div>
  );
}

function NameModal({ title, onClose, onCreate }: { title: string; onClose: () => void; onCreate: (name: string, confirm?: string) => Promise<unknown> }) {
  const { run, dialog } = useConfirmed();
  const [name, setName] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="name-modal-title">
      <ModalHeader title={title} labelId="name-modal-title" />
      <ModalBody>
        <Form id="name-modal-form" onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await run((c) => onCreate(name.trim(), c));
          } catch (x) {
            setError(x);
          } finally {
            setBusy(false);
          }
        }}>
          <FormGroup label="Name" fieldId="name-modal-name" isRequired>
            <TextInput id="name-modal-name" value={name} onChange={(_e, v) => setName(v)} autoFocus isRequired />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="name-modal-form" variant="primary" isLoading={busy} isDisabled={busy || !name.trim()}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
      {dialog}
    </Modal>
  );
}

function LoginMethodsView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [lp, setLp] = useState<LoginPolicy | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [opError, setOpError] = useState<unknown>(null);
  const [editing, setEditing] = useState<null | { sequence?: LoginPolicy['sequences'][number] }>(null);
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  const editor = canAt('editor', '');
  const load = useCallback(() => { api.loginPolicy().then(setLp).catch(setError); }, [api]);
  useEffect(load, [load]);
  /**
   * Run a change; when objects name the sequence the console says how many, and the change goes ahead
   * only once that count is confirmed.
   */
  const withCount = (name: string, op: (confirm: string | undefined, count?: number) => Promise<LoginPolicy>) =>
    confirmed.run((c) => op(c)).catch((x) => {
      if (x instanceof ApiError && x.code === 'confirm-count') {
        const count = Number(x.problem.count);
        return new Promise<LoginPolicy>((resolve, reject) => sure.ask(`${count} ${count === 1 ? 'object uses' : 'objects use'} ${name}`,
          `They name ${name} as their login sequence. Changing it changes how they log in.`, 'Go ahead',
          () => confirmed.run((c) => op(c, count)).then(resolve, reject)));
      }
      throw x;
    });
  const save = (body: SequenceRequest) => {
    const seq = editing?.sequence;
    return (seq ? withCount(seq.name, (c, n) => api.updateSequence(seq.name, body, c, n)) : confirmed.run((c) => api.createSequence(body, c))).then(setLp);
  };
  const remove = (name: string) => sure.ask(`Delete ${name}?`, 'People can no longer log in with it.', 'Delete', () => {
    setOpError(null);
    withCount(name, (c, n) => api.deleteSequence(name, c, n)).then(setLp, setOpError);
  });
  if (!lp) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Loading" />;
  }
  return (
    <div className="dc-tab-body">
      <DescriptionList isHorizontal isCompact>
        <DescriptionListGroup><DescriptionListTerm>Default login sequence</DescriptionListTerm><DescriptionListDescription>{lp.defaultSequence ?? 'none'}</DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Directory-wide password policy</DescriptionListTerm>
          <DescriptionListDescription>{lp.passwordPolicy?.guid ? <a {...linkProps(`/security/password-policies/${lp.passwordPolicy.guid}`)}>{lp.passwordPolicy.name}</a> : 'none'}</DescriptionListDescription></DescriptionListGroup>
      </DescriptionList>
      <Flex className="dc-tab-body" direction={{ default: 'column' }}>
        <FlexItem>
          <Flex><FlexItem grow={{ default: 'grow' }}><Title headingLevel="h2" size="md">Login sequences</Title></FlexItem>
            {editor && <FlexItem><Button variant="secondary" onClick={() => setEditing({})}>New sequence</Button></FlexItem>}</Flex>
          <ProblemAlert error={opError} />
          <Table aria-label="Login sequences" variant="compact">
            <Thead><Tr><Th>Sequence</Th><Th info={tip('grade')}>Grade</Th><Th>Methods</Th><Th screenReaderText="Actions" /></Tr></Thead>
            <Tbody>
              {lp.sequences.map((q) => (
                <Tr key={q.name}>
                  <Td dataLabel="Sequence">{q.name}{q.name === lp.defaultSequence && <Label isCompact className="dc-gap-left">default</Label>}
                    {lp.authorized && !lp.authorized.includes(q.name) && <Hint text={explain('notAuthorized')}><Label isCompact color="grey" className="dc-gap-left">not authorized</Label></Hint>}</Td>
                  <Td dataLabel="Grade">{q.grade ?? '—'}</Td>
                  <Td dataLabel="Methods">{q.methods.join(q.any ? ' or ' : ' → ')}</Td>
                  <Td isActionCell>
                    {editor && <>
                      <Button variant="link" isInline onClick={() => setEditing({ sequence: q })}>Change</Button>
                      <Hint text={q.name === lp.defaultSequence ? 'The default sequence: choose another default first.' : undefined}>
                        <Button variant="link" isInline isDanger className="dc-gap-left" isAriaDisabled={q.name === lp.defaultSequence} onClick={() => remove(q.name)}>Delete</Button>
                      </Hint>
                    </>}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </FlexItem>
        <FlexItem>
          <Title headingLevel="h2" size="md">Installed methods</Title>
          <Table aria-label="Login methods" variant="compact">
            <Thead><Tr><Th>Method</Th><Th>Vendor</Th><Th>Kind</Th></Tr></Thead>
            <Tbody>
              {lp.methods.map((m) => <Tr key={m.dn}><Td dataLabel="Method">{m.name}</Td><Td dataLabel="Vendor">{m.vendor ?? '—'}</Td><Td dataLabel="Kind">{m.postLogin ? 'post-login' : 'login'}</Td></Tr>)}
            </Tbody>
          </Table>
        </FlexItem>
      </Flex>
      {editing && <SequenceModal policy={lp} editing={editing.sequence} onSave={save} onClose={() => setEditing(null)} />}
      {confirmed.dialog}
      {sure.dialog}
    </div>
  );
}

/**
 * EBA (enhanced background authentication): the tree's EBA CA, which issues each server an NCP
 * certificate for server-to-server and client authentication, and the requests awaiting approval.
 */
function EbaView() {
  const { me } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [eba, setEba] = useState<EbaState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => { setError(null); api.eba().then(setEba).catch(setError); }, [api]);
  useEffect(load, [load]);
  if (!eba) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Looking for the EBA CA" />;
  }
  if (!eba.available) {
    return <div className="dc-tab-body"><p>EBA is not set up in this directory: {eba.problem}.</p></div>;
  }
  return (
    <div className="dc-tab-body">
      <p className="dc-subtle">{explain('eba')}</p>
      <DescriptionList isHorizontal isCompact>
        <DescriptionListGroup><DescriptionListTerm>EBA CA</DescriptionListTerm><DescriptionListDescription><span className="dc-mono">{eba.ca?.subject}</span> on <span className="dc-mono">{eba.caAddress}</span></DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Valid until</DescriptionListTerm><DescriptionListDescription><ExpiryLabel notAfter={eba.ca?.notAfter ?? undefined} /></DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Signature</DescriptionListTerm><DescriptionListDescription>{eba.ca?.signatureAlgorithm}</DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Serial</DescriptionListTerm><DescriptionListDescription className="dc-mono">{eba.ca?.serial}</DescriptionListDescription></DescriptionListGroup>
      </DescriptionList>
      <Title headingLevel="h2" size="md" className="dc-tab-body">Servers' NCP certificates</Title>
      <p className="dc-subtle">{explain('ncpCertificates')}</p>
      <Table aria-label="NCP certificates" variant="compact">
        <Thead><Tr><Th>Server</Th><Th>Address</Th><Th>Serial</Th><Th>Valid until</Th></Tr></Thead>
        <Tbody>
          {(eba.ncpCertificates ?? []).map((c) => (
            <Tr key={c.serial}>
              <Td dataLabel="Server">{c.server ? <a {...linkProps(`/edir/servers/${c.server.guid}`)}>{c.server.name}</a> : <span className="dc-mono">{c.subject}</span>}</Td>
              <Td dataLabel="Address"><span className="dc-mono">{c.address}</span></Td>
              <Td dataLabel="Serial"><span className="dc-mono">{c.serial}</span></Td>
              <Td dataLabel="Valid until"><ExpiryLabel notAfter={c.notAfter ?? undefined} /></Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      <Title headingLevel="h2" size="md" className="dc-tab-body">Requests awaiting approval</Title>
      {(eba.pendingRequests ?? []).length === 0 ? <p>None.</p> : <pre className="dc-mono">{JSON.stringify(eba.pendingRequests, null, 2)}</pre>}
    </div>
  );
}
