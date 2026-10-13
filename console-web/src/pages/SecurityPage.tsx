import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, CardBody, CardTitle, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Flex, FlexItem,
  Form, FormGroup, Label, LabelGroup, Modal, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, Tab, Tabs, TabTitleText, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Certificate, type EdirServer, type LoginPolicy, type PasswordPolicySummary, type Pki, edir, pem, security } from '../api';
import { useSession } from '../session';
import { linkProps, navigate } from '../router';
import { useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { NewCertificateModal } from '../components/NewCertificate';

const DAY = 86_400_000;
export const WARN_DAYS = 60;

/** How a certificate's expiry reads: expired, expiring within WARN_DAYS, or fine. */
export function ExpiryLabel({ notAfter }: { notAfter?: string }) {
  if (!notAfter) {
    return <>—</>;
  }
  const days = Math.floor((Date.parse(notAfter) - Date.now()) / DAY);
  const date = new Date(notAfter).toLocaleDateString();
  if (days < 0) {
    return <Label isCompact color="red">expired {date}</Label>;
  }
  if (days <= WARN_DAYS) {
    return <Label isCompact color="orange">{date} ({days} days)</Label>;
  }
  return <span>{date}</span>;
}

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

/** Security services: the tree's certificates, password policies, challenge sets and login methods (DESIGN Phase 6). */
export function SecurityPage({ tab = 'certificates' }: { tab?: string }) {
  const go = (k: string | number) => navigate(k === 'certificates' ? '/security' : `/security/${k}`);
  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Security</Title>
      <Tabs activeKey={tab} onSelect={(_e, k) => go(k)} aria-label="Security" mountOnEnter unmountOnExit className="dc-tab-body">
        <Tab eventKey="certificates" title={<TabTitleText>Certificates</TabTitleText>}><CertificatesView /></Tab>
        <Tab eventKey="password-policies" title={<TabTitleText>Password policies</TabTitleText>}><PoliciesView /></Tab>
        <Tab eventKey="challenge-sets" title={<TabTitleText>Challenge sets</TabTitleText>}><ChallengeSetsView /></Tab>
        <Tab eventKey="login-methods" title={<TabTitleText>Login methods</TabTitleText>}><LoginMethodsView /></Tab>
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
  const [opError, setOpError] = useState<unknown>(null);
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  const level = useHeading();
  // making and deleting certificates changes the whole tree's PKI: an editor of the whole tree
  const editor = canAt('editor', '');
  const load = useCallback(() => { api.pki().then(setPki).catch(setError); }, [api]);
  useEffect(load, [load]);
  useEffect(() => { if (editor) { edir(me.directory).servers().then(setServers).catch(() => setServers([])); } }, [editor, me.directory]);
  const remove = (k: Pki['serverCertificates'][number]) => sure.ask(`Delete ${k.name}?`,
    `The key pair and certificate go with it; nothing can bring them back. Clients that trust it by this certificate (not the tree CA) will stop trusting ${k.server?.name ?? 'the server'}.`,
    'Delete', () => {
      setOpError(null);
      confirmed.run((c) => api.deleteServerCertificate(k.guid!, c)).then(load, setOpError);
    });
  if (!pki) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Reading the tree's certificates" />;
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
          {!pki.ca ? <p>This tree has no Organizational CA.</p> : (
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
                      <Td dataLabel="SHA-256" className="dc-mono dc-subtle">{c.sha256.slice(0, 23)}…</Td>
                      <Td isActionCell><Button variant="link" isInline onClick={() => download(fileName(`${pki.ca!.name}-${c.key}.pem`), pem(c.der))}>Download</Button></Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </>
          )}
        </CardBody>
      </Card>

      <Card className="dc-tab-body">
        <CardTitle><Flex><FlexItem grow={{ default: 'grow' }}><Title headingLevel="h2" size="lg">Server certificates</Title></FlexItem>
          {editor && pki.ca && <FlexItem><Button variant="secondary" onClick={() => setCreating(true)} isDisabled={servers.length === 0}>New server certificate</Button></FlexItem>}
        </Flex></CardTitle>
        <CardBody>
          <ProblemAlert error={opError} />
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
                    {editor && k.guid && (
                      <Button variant="link" isInline isDanger isAriaDisabled={k.usedBy.length > 0} className="dc-gap-left"
                        title={k.usedBy.length > 0 ? `In use by ${k.usedBy.join(', ')}` : undefined} onClick={() => remove(k)}>Delete</Button>
                    )}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
          <p className="dc-subtle">Downloads hold the public certificate and its chain. Private keys never leave the directory. A certificate an LDAP server or SAS service uses cannot be deleted.</p>
          {creating && (
            <NewCertificateModal kind="server" servers={servers.map((x) => ({ guid: x.guid, name: x.name }))}
              onCreate={(body, server) => confirmed.run((c) => api.createServerCertificate(server!, body, c)).then(load)}
              onClose={() => setCreating(false)} />
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
        <Thead><Tr><Th>Policy</Th><Th>Universal Password</Th><Th>Length</Th><Th>Assigned to</Th></Tr></Thead>
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
  const { me } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [lp, setLp] = useState<LoginPolicy | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => { api.loginPolicy().then(setLp).catch(setError); }, [api]);
  useEffect(load, [load]);
  if (!lp) {
    return error ? <ProblemAlert error={error} /> : <Spinner aria-label="Loading" />;
  }
  return (
    <div className="dc-tab-body">
      <DescriptionList isHorizontal isCompact>
        <DescriptionListGroup><DescriptionListTerm>Default login sequence</DescriptionListTerm><DescriptionListDescription>{lp.defaultSequence ?? 'none'}</DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Tree-wide password policy</DescriptionListTerm>
          <DescriptionListDescription>{lp.passwordPolicy?.guid ? <a {...linkProps(`/security/password-policies/${lp.passwordPolicy.guid}`)}>{lp.passwordPolicy.name}</a> : 'none'}</DescriptionListDescription></DescriptionListGroup>
      </DescriptionList>
      <Flex className="dc-tab-body" direction={{ default: 'column' }}>
        <FlexItem>
          <Title headingLevel="h2" size="md">Login sequences</Title>
          <Table aria-label="Login sequences" variant="compact">
            <Thead><Tr><Th>Sequence</Th><Th>Grade</Th><Th>Methods, in order</Th></Tr></Thead>
            <Tbody>
              {lp.sequences.map((q) => <Tr key={q.name}><Td dataLabel="Sequence">{q.name}</Td><Td dataLabel="Grade">{q.grade ?? '—'}</Td><Td dataLabel="Methods">{q.methods.join(' → ')}</Td></Tr>)}
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
    </div>
  );
}
