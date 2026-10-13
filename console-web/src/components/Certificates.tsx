import { useState } from 'react';
import {
  Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form, FormGroup, FormSelect,
  FormSelectOption, Label, Modal, ModalBody, ModalFooter, ModalHeader, Radio, TextInput,
} from '@patternfly/react-core';
import { ApiError, type Directory, type Probe, type ProbedCertificate, daysUntil, trust } from '../api';
import { useStepUp } from './StepUp';

/** Expiry as a label: red once expired or within 7 days, orange within 30, gold within 60 (section 6.5). */
export function ExpiryLabel({ notAfter }: { notAfter: string }) {
  const days = daysUntil(notAfter);
  const date = new Date(notAfter).toLocaleDateString();
  if (days < 0) {
    return <>{date} <Label color="red" isCompact>expired</Label></>;
  }
  if (days <= 60) {
    return <>{date} <Label color={days <= 7 ? 'red' : days <= 30 ? 'orange' : 'yellow'} isCompact>{days} {days === 1 ? 'day' : 'days'}</Label></>;
  }
  return <>{date}</>;
}

const STATUS: Record<string, { text: string; color: 'green' | 'red' | 'orange' }> = {
  trusted: { text: 'Trusted', color: 'green' },
  untrusted: { text: 'Not trusted', color: 'red' },
  hostname: { text: 'Name mismatch', color: 'orange' },
  'pin-changed': { text: 'Certificate changed', color: 'red' },
  expired: { text: 'Expired', color: 'red' },
};

export function TrustStatus({ status }: { status: string }) {
  const s = STATUS[status] ?? { text: status, color: 'orange' as const };
  return <Label color={s.color} isCompact>{s.text}</Label>;
}

export function CertificateDetails({ cert }: { cert: Pick<ProbedCertificate, 'subject' | 'names' | 'issuer' | 'notBefore' | 'notAfter' | 'sha256'> }) {
  return (
    <DescriptionList isHorizontal isCompact>
      <DescriptionListGroup><DescriptionListTerm>Subject</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.subject}</DescriptionListDescription></DescriptionListGroup>
      <DescriptionListGroup><DescriptionListTerm>Names</DescriptionListTerm><DescriptionListDescription>{cert.names.join(', ') || 'none'}</DescriptionListDescription></DescriptionListGroup>
      <DescriptionListGroup><DescriptionListTerm>Issuer</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.issuer}</DescriptionListDescription></DescriptionListGroup>
      <DescriptionListGroup>
        <DescriptionListTerm>Valid</DescriptionListTerm>
        <DescriptionListDescription>{new Date(cert.notBefore).toLocaleDateString()} to <ExpiryLabel notAfter={cert.notAfter} /></DescriptionListDescription>
      </DescriptionListGroup>
      <DescriptionListGroup><DescriptionListTerm>SHA-256</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.sha256}</DescriptionListDescription></DescriptionListGroup>
    </DescriptionList>
  );
}

/** "directory:acme" → "Acme only"; "global" → "Every directory". */
export function scopeText(scope: string, directories: Directory[]): string {
  if (scope === 'global') {
    return 'Every directory';
  }
  if (scope.startsWith('directory:')) {
    const id = scope.slice('directory:'.length);
    return `${directories.find((d) => d.id === id)?.name ?? id} only`;
  }
  if (scope.startsWith('user:')) {
    // user:<url-encoded DN>@host:port, for a directory the person entered themselves
    const subject = scope.slice('user:'.length);
    const at = subject.lastIndexOf('@');
    let who = subject;
    try {
      who = decodeURIComponent(subject.slice(0, at < 0 ? undefined : at).replace(/\+/g, ' '));
    } catch {
      // shown as kept
    }
    return at < 0 ? `Personal: ${who}` : `Personal: ${who} at ${subject.slice(at + 1)}`;
  }
  return scope;
}

/**
 * Accept the certificate a probe found, as setup does: show it, have the administrator type the last
 * 8 digits of its fingerprint (read independently first), then either trust a certificate of the chain
 * (a CA, or exactly this server's certificate) or, when only the name differs, add a host exception for
 * exactly this address. After a change the address is probed again: trusting a CA can leave a name
 * mismatch, which is then the next step. {@code onDone} runs once the address is trusted.
 */
export function TrustCertificateModal({ probe: first, directory, name, onDone, onCancel }: {
  probe: Probe; directory: string; name: string; onDone: () => void; onCancel: () => void;
}) {
  const stepUp = useStepUp();
  const [probe, setProbe] = useState(first);
  const hostname = probe.status === 'hostname';
  const pinChanged = probe.status === 'pin-changed';
  const [index, setIndex] = useState(pinChanged ? 0 : probe.recommended);
  const cert = probe.chain[hostname ? 0 : index] ?? probe.chain[0];
  // a certificate authority trusts what it signed; a server's own certificate is trusted exactly
  const kind = cert.selfSigned || cert.index > 0 ? 'ca' : 'pinned-server';
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const choose = (i: number) => {
    setIndex(i);
    setConfirm('');
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await stepUp.run(() => hostname
        ? trust.hostException(probe.probeId, confirm.trim())
        : trust.add(probe.probeId, cert.index, confirm.trim(), directory, kind));
      const again = await trust.probe(probe.host, probe.port, directory);
      if (again.status === 'trusted') {
        onDone();
        return;
      }
      setProbe(again);
      setIndex(again.status === 'pin-changed' ? 0 : again.recommended);
      setConfirm('');
    } catch (x) {
      setError(x instanceof ApiError && x.code === 'confirmation-mismatch' ? 'Those are not the last 8 digits of the fingerprint.' : x instanceof Error ? x.message : 'Failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal variant="medium" isOpen onClose={onCancel} aria-labelledby="trust-cert-title">
      <ModalHeader title={hostname ? `Accept ${name}'s certificate at ${probe.host}:${probe.port}?` : `Trust ${name}'s certificate?`} labelId="trust-cert-title" />
      <ModalBody>
        <Form id="trust-cert-form" onSubmit={submit}>
          <Alert component="h3" variant={hostname ? 'warning' : 'danger'} isInline isPlain title={probe.message} />
          {hostname
            ? <p>The console reaches {name} at {probe.host}:{probe.port}, which its certificate does not name; this is usual behind NAT or a tunnel. Accepting adds a host exception: this certificate, at exactly this address, is trusted though it names others. It stops matching when the certificate is renewed.</p>
            : pinChanged
              ? <p>{name}'s certificate is not the one the console was told to trust. If it was renewed, trust the new one; if you do not know why it changed, stop and find out first.</p>
              : <p>Choose the certificate to trust. The tree's certificate authority (usually the last one) trusts every server certificate it signs; trusting only the server's certificate needs repeating when it is renewed.</p>}
          {!hostname && probe.chain.length > 1 && (
            <FormGroup role="radiogroup" label="Certificate" fieldId="trust-cert-index" isStack>
              {probe.chain.map((c) => (
                <Radio key={c.index} id={`trust-cert-${c.index}`} name="trust-cert-index" isChecked={index === c.index} onChange={() => choose(c.index)}
                  label={`${c.subject}${c.index === probe.recommended ? ' (recommended)' : ''}`}
                  description={c.index === 0 ? "the server's certificate" : c.selfSigned ? 'a root certificate authority' : 'an intermediate certificate authority'} />
              ))}
            </FormGroup>
          )}
          <CertificateDetails cert={cert} />
          <p className="dc-subtle">{probe.confirm}</p>
          <FormGroup label="Last 8 digits of the fingerprint" fieldId="trust-cert-confirm" isRequired>
            <TextInput id="trust-cert-confirm" className="dc-mono" value={confirm} onChange={(_e, v) => setConfirm(v)} autoFocus isRequired />
          </FormGroup>
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="trust-cert-form" variant="primary" isLoading={busy} isDisabled={busy || confirm.replace(/[^0-9a-fA-F]/g, '').length !== 8}>
          {hostname ? 'Accept at this address' : 'Trust'}
        </Button>
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
      {stepUp.dialog}
    </Modal>
  );
}

/** Scope choice for a certificate: one directory, or (unless {@code onlyDirectories}) every directory. */
export function ScopeSelect({ id, value, onChange, directories, onlyDirectories }: {
  id: string; value: string; onChange: (v: string) => void; directories: Directory[]; onlyDirectories?: boolean;
}) {
  return (
    <FormSelect id={id} value={value} onChange={(_e, v) => onChange(v)}>
      {directories.map((d) => <FormSelectOption key={d.id} value={`directory:${d.id}`} label={`${d.name} only`} />)}
      {!onlyDirectories && <FormSelectOption value="global" label="Every directory" />}
    </FormSelect>
  );
}
