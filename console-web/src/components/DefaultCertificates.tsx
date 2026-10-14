import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Checkbox, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Label, List, ListItem, Modal, ModalBody,
  ModalFooter, ModalHeader, NumberInput, Radio, Spinner, TextArea,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import {
  type DefaultCertificateKind, type DefaultCertificateResult, type DefaultCertificates, type DefaultCertificatesRequest, type EdirServer,
  edir, security,
} from '../api';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

type Step = 'servers' | 'options' | 'review' | 'running' | 'done';
const KINDS: DefaultCertificateKind[] = ['dns', 'ec', 'ip'];
const NAMES: Record<DefaultCertificateKind, string> = { dns: 'SSL CertificateDNS', ec: 'SSL EC CertificateDNS', ip: 'SSL CertificateIP' };
const lines = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function StateCell({ c }: { c?: DefaultCertificates['certificates'][number] }) {
  if (!c || !c.applicable) {
    return <span className="dc-subtle">not used</span>;
  }
  if (c.problems.length === 0) {
    return <Label color="green" isCompact>OK until {new Date(c.certificate!.notAfter).toLocaleDateString()}</Label>;
  }
  return <Label color={c.problems[0] === 'missing' ? 'grey' : 'red'} isCompact>{c.problems.join('; ')}</Label>;
}

/**
 * Check and repair eDirectory's default server certificates (SSL CertificateDNS, SSL EC CertificateDNS
 * when the tree CA has an EC key, and optionally SSL CertificateIP), server by server: choose servers,
 * choose what to replace, review, then each server in turn. A replaced certificate is deleted and made
 * again under the same name, so an LDAP server that names it keeps it, once refreshed.
 */
export function DefaultCertificatesModal({ servers, onClose, onChanged }: { servers: EdirServer[]; onClose: () => void; onChanged: () => void }) {
  const { me } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const confirmed = useConfirmed();
  const [states, setStates] = useState<Record<string, DefaultCertificates | Error>>({});
  const [selected, setSelected] = useState<string[] | null>(null);
  const [step, setStep] = useState<Step>('servers');
  const [replace, setReplace] = useState<'invalid' | 'all'>('invalid');
  const [withIp, setWithIp] = useState(false);
  const [years, setYears] = useState(2);
  const [dnsText, setDnsText] = useState('');
  const [ipText, setIpText] = useState('');
  const [results, setResults] = useState<Record<string, DefaultCertificateResult[] | Error>>({});
  const [current, setCurrent] = useState<string | null>(null);
  const [refreshed, setRefreshed] = useState<'no' | 'busy' | 'yes' | Error>('no');

  useEffect(() => {
    servers.forEach((s) => {
      api.defaultCertificates(s.guid).then((st) => setStates((old) => ({ ...old, [s.guid]: st })),
        (e) => setStates((old) => ({ ...old, [s.guid]: e instanceof Error ? e : new Error(String(e)) })));
    });
  }, [api, servers]);

  const loaded = servers.every((s) => states[s.guid]);
  // to start with: the servers with something wrong, and SSL CertificateIP when any of them has one
  useEffect(() => {
    if (loaded && selected === null) {
      const ok = (s: EdirServer) => states[s.guid] && !(states[s.guid] instanceof Error);
      const st = (s: EdirServer) => states[s.guid] as DefaultCertificates;
      setSelected(servers.filter((s) => ok(s) && st(s).certificates.some((c) => c.applicable && c.kind !== 'ip' && c.problems.length > 0)).map((s) => s.guid));
      setWithIp(servers.some((s) => ok(s) && st(s).certificates.some((c) => c.kind === 'ip' && c.guid)));
    }
  }, [loaded, selected, servers, states]);

  const chosen = servers.filter((s) => (selected ?? []).includes(s.guid) && states[s.guid] && !(states[s.guid] instanceof Error));
  const single = chosen.length === 1 ? states[chosen[0].guid] as DefaultCertificates : null;
  const kinds = KINDS.filter((k) => k !== 'ip' || withIp);
  const request = (st: DefaultCertificates): DefaultCertificatesRequest => ({
    replace, kinds, validityYears: years, ...(single && st === single ? { dnsNames: lines(dnsText), ips: lines(ipText) } : {}),
  });
  // what will happen to each certificate of a server, as the server will decide it
  const plan = (st: DefaultCertificates) => st.certificates.filter((c) => c.applicable && kinds.includes(c.kind))
    .map((c) => ({ c, action: replace === 'invalid' && c.problems.length === 0 ? 'keep' : c.guid ? 'replace' : 'create' }));
  const changes = chosen.reduce((n, s) => n + plan(states[s.guid] as DefaultCertificates).filter((p) => p.action !== 'keep').length, 0);
  const ldapUsers = chosen.flatMap((s) => (states[s.guid] as DefaultCertificates).certificates
    .filter((c) => c.usedBy.length > 0 && plan(states[s.guid] as DefaultCertificates).some((p) => p.c === c && p.action !== 'keep')).flatMap((c) => c.usedBy));
  const connected = chosen.find((s) => (states[s.guid] as DefaultCertificates).connected);

  const toOptions = () => {
    if (single) {
      setDnsText(single.dnsNames.join('\n'));
      setIpText(single.ips.join('\n'));
    }
    setStep('options');
  };

  // one server at a time, in order; the directory's name, if typed once, serves for all of them
  const run = async () => {
    setStep('running');
    let typed: string | undefined;
    for (const s of chosen) {
      setCurrent(s.guid);
      try {
        const r = await confirmed.run((c) => {
          typed = c ?? typed;
          return api.repairDefaultCertificates(s.guid, request(states[s.guid] as DefaultCertificates), typed);
        });
        setResults((old) => ({ ...old, [s.guid]: r }));
      } catch (e) {
        setResults((old) => ({ ...old, [s.guid]: e instanceof Error ? e : new Error(String(e)) }));
        if (e instanceof Error && e.message === 'Not confirmed.') {
          break;
        }
      }
    }
    setCurrent(null);
    setStep('done');
    onChanged();
  };

  const refreshLdap = () => {
    setRefreshed('busy');
    confirmed.run((c) => edir(me.directory).ldapRefresh(c)).then(() => setRefreshed('yes'), (e) => setRefreshed(e instanceof Error ? e : new Error(String(e))));
  };

  const ipValid = !withIp || !single || lines(ipText).length > 0;
  return (
    <Modal isOpen onClose={step === 'running' ? undefined : onClose} variant="large" aria-labelledby="defcert-title">
      <ModalHeader title="Default server certificates" labelId="defcert-title"
        description={{ servers: 'Choose the servers to repair.', options: 'Choose what to replace.', review: 'Check what will happen.', running: 'Working…', done: 'Done.' }[step]} />
      <ModalBody>
        {step === 'servers' && (
          <>
            {!loaded && <Spinner size="md" aria-label="Checking each server's certificates" />}
            <Table aria-label="Servers and their default certificates" variant="compact">
              <Thead><Tr><Th screenReaderText="Choose" /><Th>Server</Th>{KINDS.map((k) => <Th key={k}>{NAMES[k]}</Th>)}</Tr></Thead>
              <Tbody>
                {servers.map((s) => {
                  const st = states[s.guid];
                  return (
                    <Tr key={s.guid}>
                      <Td select={st && !(st instanceof Error) ? {
                        rowIndex: 0, isSelected: (selected ?? []).includes(s.guid),
                        onSelect: (_e, on) => setSelected((old) => on ? [...(old ?? []), s.guid] : (old ?? []).filter((g) => g !== s.guid)),
                      } : undefined} />
                      <Td dataLabel="Server">{s.name}{s.connected && <> <Label isCompact color="blue">the console's connection</Label></>}</Td>
                      {st instanceof Error ? <Td colSpan={3}><span className="dc-subtle">{st.message}</span></Td>
                        : KINDS.map((k) => <Td key={k} dataLabel={NAMES[k]}>{st ? <StateCell c={st.certificates.find((c) => c.kind === k)} /> : <Spinner size="sm" aria-label="Checking" />}</Td>)}
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
            <p className="dc-subtle dc-tab-body">A certificate needs replacing when it is missing, expired or expiring within 30 days, not issued by the tree's CA, or does not name one of the server's addresses.</p>
          </>
        )}

        {step === 'options' && (
          <Form onSubmit={(e) => e.preventDefault()}>
            <FormGroup role="radiogroup" label="Replace" fieldId="replace" isStack>
              <Radio id="replace-invalid" name="replace" label="Only certificates with a problem, or missing" isChecked={replace === 'invalid'} onChange={() => setReplace('invalid')} />
              <Radio id="replace-all" name="replace" label="All of them" description="Every default certificate is made again, valid or not." isChecked={replace === 'all'} onChange={() => setReplace('all')} />
            </FormGroup>
            <Checkbox id="with-ip" label="Include SSL CertificateIP" description="A certificate whose subject is the server's IP address. eDirectory does not create it by default."
              isChecked={withIp} onChange={(_e, v) => setWithIp(v)} />
            <FormGroup label="Valid for (years)" fieldId="years">
              <NumberInput id="years" value={years} min={1} max={10} onMinus={() => setYears(Math.max(1, years - 1))} onPlus={() => setYears(Math.min(10, years + 1))}
                onChange={(e) => setYears(Math.min(10, Math.max(1, Number((e.target as HTMLInputElement).value) || 1)))} />
              <FormHelperText><HelperText><HelperTextItem>The CA does not issue past its own expiry.</HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
            {single ? (
              <>
                <FormGroup label="DNS names" fieldId="dns-names">
                  <TextArea id="dns-names" className="dc-mono" rows={3} value={dnsText} onChange={(_e, v) => setDnsText(v)} />
                  <FormHelperText><HelperText><HelperTextItem>One per line. The first is the certificates' subject; all are alternative names.</HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
                <FormGroup label="IP addresses" fieldId="ips">
                  <TextArea id="ips" className="dc-mono" rows={2} value={ipText} onChange={(_e, v) => setIpText(v)} validated={ipValid ? 'default' : 'error'} />
                  <FormHelperText><HelperText><HelperTextItem variant={ipValid ? 'default' : 'error'}>
                    {ipValid ? 'From the server\'s network addresses. All are alternative names; the first is SSL CertificateIP\'s subject.' : 'SSL CertificateIP needs an address.'}
                  </HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
              </>
            ) : <p>Each server's certificates name that server's own DNS names and addresses, shown on the next page.</p>}
          </Form>
        )}

        {(step === 'review' || step === 'running' || step === 'done') && (
          <>
            {step === 'review' && connected && (
              <Alert variant="warning" isInline title={`The console reaches the directory through ${connected.name}`} className="dc-tab-body">
                If the console trusts that server by its own certificate rather than the tree's CA, it will report the certificate as changed once the LDAP server serves the new one; check it on the Certificates page.
              </Alert>
            )}
            {step === 'review' && ldapUsers.length > 0 && (
              <Alert variant="info" isInline title="LDAP servers keep serving the old certificates until refreshed" className="dc-tab-body">
                {[...new Set(ldapUsers)].join(', ')} name{ldapUsers.length === 1 ? 's' : ''} a certificate that will be replaced. They keep it, by name; you can refresh them when this is done.
              </Alert>
            )}
            <Table aria-label="What happens on each server" variant="compact">
              <Thead><Tr><Th>Server</Th><Th>Certificate</Th><Th>Action</Th><Th>Names</Th><Th>Outcome</Th></Tr></Thead>
              <Tbody>
                {chosen.map((s) => {
                  const st = states[s.guid] as DefaultCertificates;
                  const req = request(st);
                  const res = results[s.guid];
                  const rows = plan(st);
                  return (
                    <Fragment key={s.guid}>
                      {rows.map(({ c, action }, i) => {
                        const r = Array.isArray(res) ? res.find((x) => x.kind === c.kind) : undefined;
                        const names = c.kind === 'ip' ? (req.ips ?? st.ips) : [...(req.dnsNames ?? st.dnsNames), ...(req.ips ?? st.ips)];
                        return (
                          <Tr key={c.kind}>
                            <Td dataLabel="Server">{i === 0 ? s.name : ''}</Td>
                            <Td dataLabel="Certificate">{c.name}</Td>
                            <Td dataLabel="Action">{action === 'keep' ? <span className="dc-subtle">keep</span> : <>{action}{c.problems.length > 0 && c.problems[0] !== 'missing' && <span className="dc-subtle"> ({c.problems.join('; ')})</span>}</>}</Td>
                            <Td dataLabel="Names" className="dc-mono">{action === 'keep' ? '' : names.join(', ')}</Td>
                            <Td dataLabel="Outcome">
                              {current === s.guid && !res && <Spinner size="sm" aria-label="Working" />}
                              {r && (r.status === 'ok' ? <Label color="green" isCompact>{r.action}</Label> : <Label color="red" isCompact>{r.detail ?? 'failed'}</Label>)}
                              {i === 0 && res instanceof Error && <Label color="red" isCompact>{res.message}</Label>}
                            </Td>
                          </Tr>
                        );
                      })}
                    </Fragment>
                  );
                })}
              </Tbody>
            </Table>
            {step === 'review' && changes === 0 && <p className="dc-tab-body">Nothing needs replacing on the chosen servers.</p>}
            {step === 'done' && (
              <div className="dc-tab-body">
                <List>
                  <ListItem>LDAP servers serve the new certificates once refreshed (or restarted).</ListItem>
                  <ListItem>Clients that trust these servers by their certificate, not the tree's CA, must trust the new ones.</ListItem>
                </List>
                {refreshed === 'yes' ? <Alert variant="success" isInline isPlain title="The LDAP servers were refreshed." />
                  : <Button variant="secondary" isLoading={refreshed === 'busy'} isDisabled={refreshed === 'busy'} onClick={refreshLdap}>Refresh the LDAP servers now</Button>}
                {refreshed instanceof Error && <ProblemAlert error={refreshed} />}
              </div>
            )}
          </>
        )}
        {confirmed.dialog}
      </ModalBody>
      <ModalFooter>
        {step === 'servers' && <Button onClick={toOptions} isDisabled={chosen.length === 0}>Next</Button>}
        {step === 'options' && <><Button onClick={() => setStep('review')} isDisabled={!ipValid || (single !== null && lines(dnsText).length === 0)}>Next</Button>
          <Button variant="secondary" onClick={() => setStep('servers')}>Back</Button></>}
        {step === 'review' && <><Button variant="danger" onClick={run} isDisabled={changes === 0}>Replace {changes} certificate{changes === 1 ? '' : 's'}</Button>
          <Button variant="secondary" onClick={() => setStep('options')}>Back</Button></>}
        {step !== 'running' && <Button variant="link" onClick={onClose}>{step === 'done' ? 'Close' : 'Cancel'}</Button>}
      </ModalFooter>
    </Modal>
  );
}
