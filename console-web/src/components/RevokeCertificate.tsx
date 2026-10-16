import { useState } from 'react';
import { Alert, Button, Form, FormGroup, FormSelect, FormSelectOption, Modal, ModalBody, ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { type Revocation, type RevocationResult } from '../api';

/** RFC 5280 reasons, as the CA takes them (7 is unused; 8 removes from a CRL and is not a revocation). */
const REASONS: [number, string][] = [
  [0, 'Unspecified'], [1, 'Key compromise'], [4, 'Superseded'], [5, 'Cessation of operation'], [3, 'Affiliation changed'],
  [6, 'Certificate on hold'], [9, 'Privilege withdrawn'], [2, 'CA compromise'], [10, 'Attribute authority compromise'],
];

/** Revoke a certificate: the CA lists it on its CRL from the next issue; it cannot be taken back. */
export function RevokeModal({ name, onRevoke, onDone, onClose }: {
  name: string;
  onRevoke: (r: Revocation) => Promise<RevocationResult>;
  onDone: (r: RevocationResult) => void;
  onClose: () => void;
}) {
  const [reason, setReason] = useState(4);
  const [comment, setComment] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await onRevoke({ reason, comment: comment.trim() || undefined }));
      onClose();
    } catch (x) {
      setError(x instanceof Error ? x.message : 'Not revoked.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="revoke-title">
      <ModalHeader title={`Revoke ${name}?`} labelId="revoke-title" titleIconVariant="warning" />
      <ModalBody>
        <Form id="revoke-form" onSubmit={submit}>
          <p>The directory's CA lists the certificate as revoked on its CRL from the CRL's next issue. A revocation cannot be undone (except "Certificate on hold").</p>
          <FormGroup label="Reason" fieldId="revoke-reason">
            <FormSelect id="revoke-reason" value={String(reason)} onChange={(_e, v) => setReason(Number(v))}>
              {REASONS.map(([code, label]) => <FormSelectOption key={code} value={String(code)} label={label} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup label="Comment" fieldId="revoke-comment">
            <TextInput id="revoke-comment" value={comment} maxLength={256} onChange={(_e, v) => setComment(v)} />
          </FormGroup>
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="revoke-form" variant="danger" isLoading={busy} isDisabled={busy}>Revoke</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** "Revoked: listed on the CRL from 24 Oct 2026." */
export function revokedNotice(name: string, r: RevocationResult): string {
  return `${name} revoked: the CRL lists it from its next issue${r.listedFrom ? ` (${new Date(r.listedFrom).toLocaleString()})` : ''}.`;
}
