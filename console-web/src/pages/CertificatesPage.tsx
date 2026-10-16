import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, ClipboardCopy, EmptyState, EmptyStateBody, FileUpload, Form, FormGroup, FormHelperText, HelperText, HelperTextItem,
  Modal, ModalBody, ModalFooter, ModalHeader, PageSection, Spinner, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon, SyncIcon, UploadIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Directory, type HostExceptionInfo, type Probe, type TrustAlert, type TrustState, type TrustedCertificate, daysUntil, session, trust } from '../api';
import { useSession } from '../session';
import { HeadingLevel, useHeading } from '../heading';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure } from '../components/Confirm';
import { useStepUp } from '../components/StepUp';
import { CertificateDetails, ExpiryLabel, ScopeSelect, TrustCertificateModal, TrustStatus, scopeText } from '../components/Certificates';
import { explain } from '../help/glossary';
import { Hint } from '../help/Help';

type Live = { directory: Directory; probe?: Probe; error?: string };

/**
 * The certificates the console trusts for its directory connections: each
 * directory's live certificate, the trusted certificates with their expiry, and the host exceptions.
 * Administrators only; every change needs a sign-in within the last 10 minutes and is audited.
 */
export function CertificatesPage() {
  const { me } = useSession();
  const [directories, setDirectories] = useState<Directory[]>([]);
  const [live, setLive] = useState<Live[] | null>(null);
  const [store, setStore] = useState<TrustState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [reviewing, setReviewing] = useState<Live | null>(null);
  const [alertProbe, setAlertProbe] = useState<{ probe: Probe; directory: string; name: string } | null>(null);
  const [adding, setAdding] = useState<'probe' | 'upload' | null>(null);

  const loadStore = useCallback(() => trust.list().then(setStore).catch(setError), []);
  const check = useCallback(async () => {
    setError(null);
    try {
      const dirs = await session.directories();
      setDirectories(dirs);
      setLive(dirs.map((d) => ({ directory: d })));
      setLive(await Promise.all(dirs.map((d) => trust.probeDirectory(d.id)
        .then((probe) => ({ directory: d, probe }))
        .catch((x: unknown) => ({ directory: d, error: x instanceof Error ? x.message : String(x) })))));
    } catch (x) {
      setError(x);
    }
  }, []);
  useEffect(() => { void loadStore(); void check(); }, [loadStore, check]);
  const changed = () => { void loadStore(); void check(); };
  // the address is trusted now (its new certificate, a CA, a host exception): its alert is done with
  const resolved = () => {
    const p = alertProbe?.probe;
    setAlertProbe(null);
    (p ? trust.dismissAlert(p.host, p.port).catch(() => undefined) : Promise.resolve()).then(changed);
  };

  // which directories' live chains include a certificate: removing it would cut them off
  const usedBy = (sha256: string) => (live ?? []).filter((l) => l.probe?.chain.some((c) => c.sha256 === sha256)).map((l) => l.directory.name);

  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Certificates</Title>
      <p className="dc-subtle">The certificates the console trusts when it connects to eDirectory. The JDK's own store is never changed.</p>
      <ProblemAlert error={error} onRetry={changed} />
      <HeadingLevel.Provider value="h2">
        {store && store.alerts.length > 0 && (
          <AlertsSection alerts={store.alerts} directories={directories} onReview={(a) => {
            const dir = a.directory ?? me.directory;
            trust.probe(a.host, a.port, dir).then((probe) => setAlertProbe({ probe, directory: dir, name: `${a.host}:${a.port}` }), setError);
          }} onChanged={changed} />
        )}
        <DirectoriesSection live={live} me={me.directory} onReview={setReviewing} onCheck={() => void check()} />
        <CertificatesSection store={store} directories={directories} usedBy={usedBy} onAdd={setAdding} onChanged={changed} />
        <HostExceptionsSection store={store} onChanged={changed} />
      </HeadingLevel.Provider>
      {reviewing?.probe && (
        <TrustCertificateModal probe={reviewing.probe} directory={reviewing.directory.id} name={reviewing.directory.name}
          onDone={() => { setReviewing(null); changed(); }} onCancel={() => { setReviewing(null); changed(); }} />
      )}
      {alertProbe && (
        alertProbe.probe.status === 'trusted'
          ? <AlreadyTrusted probe={alertProbe.probe} onClose={resolved} />
          : <TrustCertificateModal probe={alertProbe.probe} directory={alertProbe.directory} name={alertProbe.name}
            onDone={resolved} onCancel={() => { setAlertProbe(null); changed(); }} />
      )}
      {adding === 'probe' && <ProbeModal directories={directories} initial={me.directory} onClose={() => { setAdding(null); changed(); }} />}
      {adding === 'upload' && <UploadModal directories={directories} initial={me.directory} onClose={(done) => { setAdding(null); if (done) changed(); }} />}
    </PageSection>
  );
}

function DirectoriesSection({ live, me, onReview, onCheck }: { live: Live[] | null; me: string; onReview: (l: Live) => void; onCheck: () => void }) {
  const H = useHeading();
  return (
    <section className="dc-tab-body" aria-labelledby="certs-directories">
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem><H id="certs-directories" className="pf-v6-c-title pf-m-lg">Directories</H></ToolbarItem>
          <ToolbarItem align={{ default: 'alignEnd' }}><Button variant="secondary" icon={<SyncIcon />} onClick={onCheck}>Check again</Button></ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      {!live && <Spinner size="md" aria-label="Checking the directories" />}
      {live && (
        <Table aria-label="Directories' certificates" variant="compact">
          <Thead><Tr><Th>Directory</Th><Th>Address</Th><Th>Certificate</Th><Th modifier="wrap">Server's expires</Th><Th modifier="wrap">CA's expires</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {live.map((l) => {
              const leaf = l.probe?.chain[0];
              const root = l.probe ? l.probe.chain[l.probe.recommended] : undefined;
              return (
                <Tr key={l.directory.id}>
                  <Td dataLabel="Directory">{l.directory.name}{l.directory.id === me && <span className="dc-subtle"> (this session)</span>}</Td>
                  <Td dataLabel="Address"><span className="dc-mono">{l.probe ? `${l.probe.host}:${l.probe.port}` : ''}</span></Td>
                  <Td dataLabel="Certificate">
                    {l.probe ? <TrustStatus status={l.probe.status} /> : l.error ? <span className="dc-subtle">{l.error}</span> : <Spinner size="sm" aria-label="Checking" />}
                  </Td>
                  <Td dataLabel="Server's expires">{leaf && <ExpiryLabel notAfter={leaf.notAfter} />}</Td>
                  <Td dataLabel="CA's expires">{root && root !== leaf && <ExpiryLabel notAfter={root.notAfter} />}</Td>
                  <Td isActionCell>{l.probe && l.probe.status !== 'trusted' && <Button variant="secondary" size="sm" onClick={() => onReview(l)}>Review</Button>}</Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      )}
    </section>
  );
}

function CertificatesSection({ store, directories, usedBy, onAdd, onChanged }: {
  store: { certificates: TrustedCertificate[] } | null; directories: Directory[]; usedBy: (sha256: string) => string[];
  onAdd: (how: 'probe' | 'upload') => void; onChanged: () => void;
}) {
  const H = useHeading();
  const sure = useAreYouSure();
  const stepUp = useStepUp();
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);
  const remove = (c: TrustedCertificate) => {
    const users = usedBy(c.sha256);
    sure.ask('Stop trusting this certificate?',
      users.length
        ? `${users.join(', ')} ${users.length === 1 ? 'connects' : 'connect'} through ${c.subject} now. Their connections, including sign-in, fail until another certificate is trusted for them.`
        : `${c.subject} is no longer trusted for ${scopeText(c.scope, directories).toLowerCase()}.`,
      'Stop trusting',
      () => { setError(null); stepUp.run(() => trust.remove(c.key ?? c.id)).then(onChanged, setError); });
  };
  return (
    <section className="dc-tab-body" aria-labelledby="certs-trusted">
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem><H id="certs-trusted" className="pf-v6-c-title pf-m-lg">Trusted certificates</H></ToolbarItem>
          <ToolbarItem align={{ default: 'alignEnd' }}><Button variant="secondary" icon={<PlusIcon />} onClick={() => onAdd('probe')}>Probe a server</Button></ToolbarItem>
          <ToolbarItem><Button variant="secondary" icon={<UploadIcon />} onClick={() => onAdd('upload')}>Upload a certificate</Button></ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <ProblemAlert error={error} />
      {!store && <Spinner size="md" aria-label="Loading the trusted certificates" />}
      {store && store.certificates.length === 0 && (
        <EmptyState titleText="No certificates of the console's own" headingLevel="h3" variant="sm">
          <EmptyStateBody>Connections rely on the JDK's certificate authorities only.</EmptyStateBody>
        </EmptyState>
      )}
      {store && store.certificates.length > 0 && (
        <Table aria-label="Trusted certificates" variant="compact">
          <Thead><Tr><Th screenReaderText="Details" /><Th>Certificate</Th><Th>Trusted as</Th><Th>For</Th><Th>Expires</Th><Th modifier="wrap">In use by</Th><Th>Added</Th><Th screenReaderText="Actions" /></Tr></Thead>
          {sortByExpiry(store.certificates).map((c, i) => {
            const users = usedBy(c.sha256);
            return (
              <Tbody key={c.key ?? c.id} isExpanded={open === (c.key ?? c.id)}>
                <Tr>
                  <Td expand={{ rowIndex: i, isExpanded: open === (c.key ?? c.id), onToggle: () => setOpen(open === (c.key ?? c.id) ? null : (c.key ?? c.id)) }} />
                  <Td dataLabel="Certificate">{c.subject}</Td>
                  <Td dataLabel="Trusted as"><Hint text={explain(c.kind === 'ca' ? 'trustedAsCa' : 'trustedAsPinned')}><span tabIndex={0}>{c.kind === 'ca' ? 'Certificate authority' : 'This server only'}</span></Hint></Td>
                  <Td dataLabel="For">{scopeText(c.scope, directories)}</Td>
                  <Td dataLabel="Expires"><ExpiryLabel notAfter={c.notAfter} /></Td>
                  <Td dataLabel="In use by">{users.join(', ') || <span className="dc-subtle">none now</span>}</Td>
                  <Td dataLabel="Added">{new Date(c.addedAt).toLocaleDateString()} <span className="dc-subtle">by {shortName(c.addedBy)}, {HOW[c.how] ?? c.how}</span></Td>
                  <Td isActionCell><Button variant="link" isDanger size="sm" onClick={() => remove(c)}>Remove</Button></Td>
                </Tr>
                <Tr isExpanded={open === (c.key ?? c.id)}>
                  <Td colSpan={8}>
                    <div className="dc-tab-body">
                      <CertificateDetails cert={c} />
                      <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" variant="inline-compact" className="dc-mono">{c.sha256}</ClipboardCopy>
                    </div>
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
        </Table>
      )}
      {sure.dialog}
      {stepUp.dialog}
    </section>
  );
}

function HostExceptionsSection({ store, onChanged }: { store: { hostExceptions: HostExceptionInfo[] } | null; onChanged: () => void }) {
  const H = useHeading();
  const sure = useAreYouSure();
  const stepUp = useStepUp();
  const [error, setError] = useState<unknown>(null);
  const remove = (h: HostExceptionInfo) => sure.ask('Remove this host exception?',
    `Connections to ${h.host}:${h.port} fail again until its certificate names that address, or the exception is added again.`, 'Remove',
    () => { setError(null); stepUp.run(() => trust.removeHostException(h.host, h.port)).then(onChanged, setError); });
  return (
    <section className="dc-tab-body" aria-labelledby="certs-exceptions">
      <H id="certs-exceptions" className="pf-v6-c-title pf-m-lg">Host exceptions</H>
      <p className="dc-subtle">Addresses whose certificate names others, as behind NAT or a tunnel: each accepts exactly one certificate at exactly one address, and stops matching when that certificate is renewed. Add one by reviewing the directory above, or when signing in to another server.</p>
      <ProblemAlert error={error} />
      {store && store.hostExceptions.length === 0 && <p>None.</p>}
      {store && store.hostExceptions.length > 0 && (
        <Table aria-label="Host exceptions" variant="compact">
          <Thead><Tr><Th>Address</Th><Th>Certificate (SHA-256)</Th><Th>Added</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {store.hostExceptions.map((h) => (
              <Tr key={`${h.host}:${h.port}:${h.scope ?? 'global'}`}>
                <Td dataLabel="Address"><span className="dc-mono">{h.host}:{h.port}</span>{h.scope && h.scope !== 'global' && <><br /><span className="dc-subtle">{scopeText(h.scope, [])}</span></>}</Td>
                <Td dataLabel="Certificate (SHA-256)" modifier="breakWord"><span className="dc-mono">{h.sha256}</span></Td>
                <Td dataLabel="Added">{new Date(h.addedAt).toLocaleDateString()} <span className="dc-subtle">by {shortName(h.addedBy)}</span></Td>
                <Td isActionCell><Button variant="link" isDanger size="sm" onClick={() => remove(h)}>Remove</Button></Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {sure.dialog}
      {stepUp.dialog}
    </section>
  );
}

/**
 * Pinned addresses that presented another certificate on a real connection: renewed, or not the
 * expected server. Review probes the address again and shows what it presents now.
 */
function AlertsSection({ alerts, directories, onReview, onChanged }: {
  alerts: TrustAlert[]; directories: Directory[]; onReview: (a: TrustAlert) => void; onChanged: () => void;
}) {
  const H = useHeading();
  const sure = useAreYouSure();
  const [error, setError] = useState<unknown>(null);
  const dismiss = (a: TrustAlert) => sure.ask('Dismiss this alert?',
    `Connections to ${a.host}:${a.port} stay refused until its new certificate is trusted. Dismiss only once you know why it changed.`, 'Dismiss',
    () => { setError(null); trust.dismissAlert(a.host, a.port).then(onChanged, setError); });
  return (
    <section className="dc-tab-body" aria-labelledby="certs-alerts">
      <H id="certs-alerts" className="pf-v6-c-title pf-m-lg">Changed certificates</H>
      <Alert variant="danger" isInline component="h3" title="A pinned server presented a different certificate">
        Connections to these addresses are refused. If the server's certificate was renewed, review it and trust the new one; if you do not know why it changed, find out before you do.
      </Alert>
      <ProblemAlert error={error} />
      <Table aria-label="Changed certificates" variant="compact">
        <Thead><Tr><Th>Address</Th><Th>Directory</Th><Th>Now presents</Th><Th>Seen</Th><Th screenReaderText="Actions" /></Tr></Thead>
        <Tbody>
          {alerts.map((a) => (
            <Tr key={`${a.host}:${a.port}:${a.presentedId}`}>
              <Td dataLabel="Address"><span className="dc-mono">{a.host}:{a.port}</span></Td>
              <Td dataLabel="Directory">{directories.find((d) => d.id === a.directory)?.name ?? a.directory ?? ''}</Td>
              <Td dataLabel="Now presents" modifier="breakWord">{a.presentedSubject}<br /><span className="dc-mono dc-subtle">{a.presentedSha256}</span></Td>
              <Td dataLabel="Seen">{a.count} {a.count === 1 ? 'time' : 'times'}, last {new Date(a.lastSeen).toLocaleString()}</Td>
              <Td isActionCell>
                <Button variant="secondary" size="sm" onClick={() => onReview(a)}>Review</Button>{' '}
                <Button variant="link" size="sm" onClick={() => dismiss(a)}>Dismiss</Button>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      {sure.dialog}
    </section>
  );
}

function AlreadyTrusted({ probe, onClose }: { probe: Probe; onClose: () => void }) {
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="probe-ok-title">
      <ModalHeader title={`${probe.host}:${probe.port} is trusted already`} labelId="probe-ok-title" />
      <ModalBody><CertificateDetails cert={probe.chain[0]} /></ModalBody>
      <ModalFooter><Button variant="primary" onClick={onClose}>Close</Button></ModalFooter>
    </Modal>
  );
}

/** Probe any LDAPS address and trust what it presents, for one directory or every directory. */
function ProbeModal({ directories, initial, onClose }: { directories: Directory[]; initial: string; onClose: () => void }) {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('636');
  const [directory, setDirectory] = useState(initial);
  const [probe, setProbe] = useState<Probe | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const portNumber = Number(port);
  if (probe) {
    if (probe.status === 'trusted') {
      return <AlreadyTrusted probe={probe} onClose={onClose} />;
    }
    return <TrustCertificateModal probe={probe} directory={directory} name="the server" onDone={onClose} onCancel={onClose} />;
  }
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="probe-title">
      <ModalHeader title="Probe a server" labelId="probe-title"
        description="The console opens a TLS connection, records the certificates the server presents, and closes it. Nothing is sent over LDAP." />
      <ModalBody>
        <Form id="probe-form" onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          trust.probe(host.trim(), portNumber, directory).then(setProbe, setError).finally(() => setBusy(false));
        }}>
          <FormGroup label="Host" fieldId="probe-host" isRequired>
            <TextInput id="probe-host" value={host} onChange={(_e, v) => setHost(v)} autoFocus isRequired />
          </FormGroup>
          <FormGroup label="Port" fieldId="probe-port" isRequired>
            <TextInput id="probe-port" type="number" value={port} onChange={(_e, v) => setPort(v)} isRequired />
          </FormGroup>
          <FormGroup label="Trust it for" fieldId="probe-directory">
            <ScopeSelect id="probe-directory" value={`directory:${directory}`} onChange={(v) => setDirectory(v.slice('directory:'.length))}
              directories={directories} onlyDirectories />
            <FormHelperText><HelperText><HelperTextItem>Judged as this directory's connections are, with the certificates already trusted for it.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="probe-form" variant="primary" isLoading={busy} isDisabled={busy || !host.trim() || !(portNumber > 0 && portNumber < 65536)}>Probe</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Trust a certificate from a PEM file: a CA certificate exported from iManager, say. */
function UploadModal({ directories, initial, onClose }: { directories: Directory[]; initial: string; onClose: (done: boolean) => void }) {
  const stepUp = useStepUp();
  const [pem, setPem] = useState('');
  const [file, setFile] = useState('');
  const [scope, setScope] = useState(`directory:${initial}`);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [added, setAdded] = useState<TrustedCertificate | null>(null);
  const valid = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(pem);
  if (added) {
    return (
      <Modal variant="small" isOpen onClose={() => onClose(true)} aria-labelledby="upload-done-title">
        <ModalHeader title="Certificate trusted" labelId="upload-done-title" />
        <ModalBody><CertificateDetails cert={added} /></ModalBody>
        <ModalFooter><Button variant="primary" onClick={() => onClose(true)}>Close</Button></ModalFooter>
      </Modal>
    );
  }
  return (
    <Modal variant="medium" isOpen onClose={() => onClose(false)} aria-labelledby="upload-title">
      <ModalHeader title="Upload a certificate" labelId="upload-title"
        description="A PEM file holding a certificate authority's certificate, such as the tree CA exported from iManager. With a chain in the file, the last certificate is trusted." />
      <ModalBody>
        <Form id="upload-form" onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          stepUp.run(() => trust.upload(pem, scope)).then(setAdded, setError).finally(() => setBusy(false));
        }}>
          <FormGroup label="Certificate (PEM)" fieldId="upload-pem" isRequired>
            <FileUpload id="upload-pem" type="text" value={pem} filename={file} filenamePlaceholder="Drop a .pem or .crt file, or paste it"
              browseButtonText="Choose a file" allowEditingUploadedText isReadOnly={false}
              onFileInputChange={(_e, f) => setFile(f.name)} onDataChange={(_e, v) => setPem(v)}
              onTextChange={(_e, v) => setPem(v)} onClearClick={() => { setPem(''); setFile(''); }}
              dropzoneProps={{ accept: { 'application/x-pem-file': ['.pem', '.crt', '.cer'] } }} />
            {pem && !valid && <FormHelperText><HelperText><HelperTextItem variant="error">That is not a PEM certificate (-----BEGIN CERTIFICATE----- …).</HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
          <FormGroup label="Trust it for" fieldId="upload-scope">
            <ScopeSelect id="upload-scope" value={scope} onChange={setScope} directories={directories} />
          </FormGroup>
          <Alert variant="info" isInline isPlain component="h3" title="Check the certificate's fingerprint against the server before you trust a file from elsewhere." />
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="upload-form" variant="primary" isLoading={busy} isDisabled={busy || !valid}>Trust</Button>
        <Button variant="link" onClick={() => onClose(false)}>Cancel</Button>
      </ModalFooter>
      {stepUp.dialog}
    </Modal>
  );
}

const HOW: Record<string, string> = { probe: 'from a probe', upload: 'uploaded', bootstrap: 'at setup', 'bootstrap-probe': 'at setup' };

const shortName = (dn: string) => (dn === 'bootstrap' ? 'setup' : dn.split(',')[0].replace(/^[a-z]+=/i, ''));

const sortByExpiry = (certs: TrustedCertificate[]) => [...certs].sort((a, b) => daysUntil(a.notAfter) - daysUntil(b.notAfter));
