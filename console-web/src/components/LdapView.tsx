import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, CardBody, CardTitle, Label, Spinner, Title } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type LdapConfigs, edir } from '../api';
import { useSession } from '../session';
import { linkProps } from '../router';
import { ProblemAlert } from './Problem';
import { useServerSignIn } from './ServerSignIn';
import { Hint } from '../help/Help';

/**
 * The LDAP Server objects (one per eDirectory server) and the LDAP Groups they belong to. A change to either
 * takes effect when the LDAP server is refreshed, which eDirectory also does on its own every 30 minutes.
 */
export function LdapView() {
  const { me, canAt } = useSession();
  const api = useMemo(() => edir(me.directory), [me.directory]);
  const [c, setC] = useState<LdapConfigs | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const signIn = useServerSignIn();
  const admin = canAt('editor', '');
  const load = useCallback(() => { setError(null); api.ldap().then(setC, setError); }, [api]);
  useEffect(load, [load]);

  const refresh = (guid: string, name: string) => {
    setBusy(guid);
    setNotice(null);
    setError(null);
    signIn.run(() => api.refreshLdapServer(guid))
      .then(() => setNotice(`${name} re-read its configuration.`), setError)
      .finally(() => setBusy(null));
  };

  if (!c) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading the LDAP configuration" />;
  }
  return (
    <div className="dc-tab-body">
      <p className="dc-subtle">
        Each eDirectory server has an LDAP Server object (its ports, TLS and limits) in an LDAP Group (how LDAP names map to eDirectory
        names, and referrals). A change takes effect when the LDAP server is refreshed; eDirectory also refreshes on its own every 30 minutes.
      </p>
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">LDAP servers</Title></CardTitle>
        <CardBody>
          <Table aria-label="LDAP servers" variant="compact">
            <Thead><Tr><Th>LDAP server</Th><Th>On</Th><Th>Listens on</Th><Th>Certificate</Th><Th>Group</Th>{admin && <Th screenReaderText="Actions" />}</Tr></Thead>
            <Tbody>
              {c.servers.map((s) => (
                <Tr key={s.guid}>
                  <Td dataLabel="LDAP server"><a {...linkProps(`/edir/ldap-servers/${s.guid}`)}>{s.name}</a>
                    {s.tlsRequired && <> <Label isCompact color="blue">TLS required</Label></>}</Td>
                  <Td dataLabel="On">{s.host?.guid ? <a {...linkProps(`/edir/servers/${s.host.guid}`)}>{s.host.name}</a> : s.host?.name ?? '—'}</Td>
                  <Td dataLabel="Listens on" className="dc-mono">{s.interfaces.join(', ') || '—'}</Td>
                  <Td dataLabel="Certificate">{s.certificate ?? '—'}</Td>
                  <Td dataLabel="Group">{s.group?.guid ? <a {...linkProps(`/edir/ldap-groups/${s.group.guid}`)}>{s.group.name}</a> : s.group?.name ?? '—'}</Td>
                  {admin && (
                    <Td isActionCell>
                      <Hint text="The LDAP server re-reads its LDAP Server and LDAP Group objects now. Connections stay open.">
                        <Button variant="link" isInline isLoading={busy === s.guid} isDisabled={busy !== null} onClick={() => refresh(s.guid, s.name)}>Refresh</Button>
                      </Hint>
                    </Td>
                  )}
                </Tr>
              ))}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      <Card className="dc-tab-body">
        <CardTitle><Title headingLevel="h2" size="lg">LDAP groups</Title></CardTitle>
        <CardBody>
          <Table aria-label="LDAP groups" variant="compact">
            <Thead><Tr><Th>LDAP group</Th><Th>Its servers</Th></Tr></Thead>
            <Tbody>
              {c.groups.map((g) => (
                <Tr key={g.guid}>
                  <Td dataLabel="LDAP group"><a {...linkProps(`/edir/ldap-groups/${g.guid}`)}>{g.name}</a></Td>
                  <Td dataLabel="Its servers">{g.servers.map((s) => s.name).join(', ') || '—'}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      {signIn.dialog}
    </div>
  );
}
