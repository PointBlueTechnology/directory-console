import { Alert, FormGroup, TextInput } from '@patternfly/react-core';
import type { Probe } from '../api';
import { CertificateDetails } from './Certificates';

/** What the person types to trust an offered certificate: its fingerprint's last 8 hex digits. */
export const confirmed = (s: string) => s.replace(/[^0-9a-fA-F]/g, '').length === 8;

/**
 * A tree's certificate the console does not trust yet, offered to the person setting the tree up: the
 * certificate to check (the CA, or the server's own when only its name differs) and the field for the
 * last 8 digits of its fingerprint.
 */
export function CertificateOffer({ offer, confirm, onConfirm, id }: { offer: Probe; confirm: string; onConfirm: (v: string) => void; id: string }) {
  const shown = offer.chain[offer.status === 'hostname' ? 0 : offer.recommended];
  return (
    <section aria-labelledby={`${id}-title`} className="dc-tab-body">
      <Alert id={`${id}-title`} component="h3" variant="warning" isInline title="Check the directory's certificate">
        The console does not trust this directory's certificate yet. If it is the one you expect (compare its fingerprint with
        the directory's certificate authority, in iManager or Identity Console), type the last 8 digits to trust it.
        {!offer.hostnameMatches && ` It names ${offer.chain[0].names.join(', ') || 'no host'}, not ${offer.host}; that is accepted too.`}
      </Alert>
      <CertificateDetails cert={shown} />
      <FormGroup label="Last 8 digits of the fingerprint" fieldId={`${id}-confirm`} isRequired>
        <TextInput id={`${id}-confirm`} className="dc-mono" value={confirm} onChange={(_e, v) => onConfirm(v)} isRequired />
      </FormGroup>
    </section>
  );
}
