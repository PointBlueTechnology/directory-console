import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, EmptyState, EmptyStateBody, Flex, FlexItem, Spinner } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DirObject, type UserCertificate, security } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { useConfirmed } from './Confirm';
import { ExpiryLabel } from './Certificates';
import { NewCertificateModal } from './NewCertificate';
import { RevokeModal, revokedNotice } from './RevokeCertificate';

/** The certificates eDirectory's PKI holds for a user, and a new one from the tree CA. */
export function UserCertificatesTab({ obj }: { obj: DirObject }) {
  const { me, canAt } = useSession();
  const api = useMemo(() => security(me.directory), [me.directory]);
  const [items, setItems] = useState<UserCertificate[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<UserCertificate | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const confirmed = useConfirmed();
  const load = useCallback(() => { setError(null); api.userCertificates(obj.guid).then(setItems, setError); }, [api, obj.guid]);
  useEffect(load, [load]);
  const editor = canAt('editor', '');

  const download = (c: UserCertificate) => {
    const body = `-----BEGIN CERTIFICATE-----\n${(c.certificate ?? '').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([body], { type: 'application/x-pem-file' }));
    a.download = `${c.name.replace(/[^A-Za-z0-9._-]/g, '_')}.pem`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="dc-tab-body">
      <Flex>
        <FlexItem grow={{ default: 'grow' }}><p className="dc-subtle">Issued by the tree's Organizational CA; the private keys stay in the directory.</p></FlexItem>
        {editor && <FlexItem><Button variant="secondary" onClick={() => setCreating(true)}>New certificate</Button></FlexItem>}
      </Flex>
      <ProblemAlert error={error} onRetry={load} />
      {notice && <Alert component="h3" variant="success" isInline isPlain title={notice} />}
      {!items && !error && <Spinner size="md" aria-label="Reading the certificates" />}
      {items && items.length === 0 && (
        <EmptyState titleText="No certificates" headingLevel="h3" variant="sm"><EmptyStateBody>eDirectory holds no certificates for {obj.name}.</EmptyStateBody></EmptyState>
      )}
      {items && items.length > 0 && (
        <Table aria-label="User certificates" variant="compact">
          <Thead><Tr><Th>Name</Th><Th>Subject</Th><Th>Issuer</Th><Th>Valid until</Th><Th screenReaderText="Download" /></Tr></Thead>
          <Tbody>
            {items.map((c) => (
              <Tr key={c.name}>
                <Td dataLabel="Name">{c.name}</Td>
                <Td dataLabel="Subject"><span className="dc-mono">{c.subject}</span></Td>
                <Td dataLabel="Issuer"><span className="dc-mono">{c.issuer}</span></Td>
                <Td dataLabel="Valid until"><ExpiryLabel notAfter={c.notAfter} /></Td>
                <Td isActionCell>
                  {c.certificate && <Button variant="link" isInline onClick={() => download(c)}>Download</Button>}
                  {editor && <Button variant="link" isInline className="dc-gap-left" onClick={() => { setNotice(null); setRevoking(c); }}>Revoke</Button>}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {creating && (
        <NewCertificateModal kind="user" defaultName={obj.name}
          onCreate={(body) => confirmed.run((c) => api.createUserCertificate(obj.guid, body, c)).then(setItems)}
          onClose={() => setCreating(false)} />
      )}
      {revoking && (
        <RevokeModal name={revoking.name} onClose={() => setRevoking(null)}
          onRevoke={(r) => confirmed.run((c) => api.revokeUserCertificate(obj.guid, revoking.name, r, c))}
          onDone={(r) => setNotice(revokedNotice(revoking.name, r))} />
      )}
      {confirmed.dialog}
    </div>
  );
}
