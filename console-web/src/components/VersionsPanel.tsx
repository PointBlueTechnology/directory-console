import { useEffect, useState } from 'react';
import { Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Spinner } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Idm, type Versions } from '../api';
import { ProblemAlert } from './Problem';

function Item({ term, children }: { term: string; children: React.ReactNode }) {
  return <DescriptionListGroup><DescriptionListTerm>{term}</DescriptionListTerm><DescriptionListDescription>{children}</DescriptionListDescription></DescriptionListGroup>;
}

/** Plain text for a support ticket: the same facts, one per line. */
export function versionsText(v: Versions): string {
  const c = v.collected;
  const lines = [
    `Server: ${v.server.name} (${v.server.dn})`,
    `Engine: ${v.engineVersion ?? 'not answering'}`,
  ];
  if (c) {
    lines.push(`Identity Manager: ${[c.product, c.version, c.edition].filter(Boolean).join(' ')}`, `Host: ${[c.host, c.hostIp, c.os, c.hostType].filter(Boolean).join(', ')}`,
      `Collected: ${c.whenText ?? c.when ?? '?'} by ${c.job.name}`, '', 'Driver shims:');
    c.drivers.forEach((d) => lines.push(`  ${d.name}: ${d.version ?? '(no version)'}${d.driverId ? ` [${d.driverId}]` : ''}`));
  }
  lines.push('', 'Base packages:');
  v.packages.filter((p) => p.package).forEach((p) => lines.push(`  ${p.driver}: ${p.package} ${p.packageVersion ?? ''}`.trimEnd()));
  return lines.join('\n') + '\n';
}

/**
 * Version discovery on the chosen server: the engine's version now; Identity Manager's version, the host
 * and each driver shim's version from the driver set's statistics job (collected on its schedule); each
 * driver's base package. "Copy as text" for a support ticket.
 */
export function VersionsPanel({ api, guid }: { api: Idm; guid: string }) {
  const [v, setV] = useState<Versions | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => { setV(null); api.setPart<Versions>(guid, 'versions').then(setV, setError); }, [api, guid]);
  if (!v) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Reading versions" />}</div>;
  }
  const c = v.collected;
  const packages = new Map(v.packages.map((p) => [p.driver.toLowerCase(), p]));
  const copy = () => navigator.clipboard.writeText(versionsText(v)).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }, setError);
  return (
    <div className="dc-tab-body">
      <Button variant="secondary" size="sm" onClick={copy}>{copied ? 'Copied' : 'Copy as text'}</Button>
      <DescriptionList isHorizontal isCompact className="dc-tab-body">
        <Item term="Server">{v.server.name}</Item>
        <Item term="Engine">{v.engineVersion ?? <span className="dc-subtle">not answering</span>}</Item>
        {c && <Item term="Identity Manager">{[c.product, c.version, c.edition].filter(Boolean).join(' ')}{c.patch ? ` · patch ${c.patch}` : ''}</Item>}
        {c && <Item term="Host">{[c.host, c.hostIp].filter(Boolean).join(' · ')}<div className="dc-subtle">{[c.os, c.hostType].filter(Boolean).join(', ')}</div></Item>}
      </DescriptionList>
      {!c && (
        <Alert variant="info" isInline isPlain className="dc-tab-body"
          title={v.statisticsJobFound ? 'The statistics job has not collected anything on this server yet.' : 'This driver set has no statistics job, so driver shim versions are not known.'}>
          {v.statisticsJobFound ? 'Driver shim versions come from the statistics job, which collects them on its schedule; run it from the Jobs tab to collect them now.'
            : 'Driver shim versions come from the driver set\'s statistics job (StatisticsJob), which Identity Manager creates with the driver set.'}
        </Alert>
      )}
      {c && <p className="dc-subtle dc-tab-body">Driver versions as {c.job.name} collected them {c.when ? new Date(c.when).toLocaleString() : c.whenText}; run it from the Jobs tab to collect them again.</p>}
      <Table aria-label="Driver versions" variant="compact" className="dc-tab-body">
        <Thead><Tr><Th>Driver</Th><Th>Shim version</Th><Th>Driver ID</Th><Th>Base package</Th><Th>Objects associated</Th></Tr></Thead>
        <Tbody>
          {(c?.drivers ?? v.packages.map((p) => ({ name: p.driver, version: null, driverId: null, usage: undefined }))).map((d) => {
            const p = packages.get((d.name ?? '').toLowerCase());
            return (
              <Tr key={d.name ?? ''}>
                <Td dataLabel="Driver">{d.name}</Td>
                <Td dataLabel="Shim version" className="dc-mono">{d.version ?? <span className="dc-subtle">—</span>}</Td>
                <Td dataLabel="Driver ID" className="dc-mono">{d.driverId ?? <span className="dc-subtle">—</span>}</Td>
                <Td dataLabel="Base package">{p?.package ? <>{p.package} <span className="dc-mono dc-subtle">{p.packageVersion}</span></> : <span className="dc-subtle">—</span>}</Td>
                <Td dataLabel="Objects associated">{d.usage ? `${d.usage.active ?? 0} active${d.usage.inactive ? `, ${d.usage.inactive} inactive` : ''}${d.usage.system ? `, ${d.usage.system} system` : ''}` : <span className="dc-subtle">—</span>}</Td>
              </Tr>
            );
          })}
        </Tbody>
      </Table>
    </div>
  );
}
