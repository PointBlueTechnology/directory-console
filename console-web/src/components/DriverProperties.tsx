import { useEffect, useMemo, useState } from 'react';
import {
  DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, ExpandableSection, Label, Spinner, Switch, Title, Tooltip,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type ConfigItem, type DriverProperties, idm } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';

function Item({ term, children }: { term: string; children: React.ReactNode }) {
  return <DescriptionListGroup><DescriptionListTerm>{term}</DescriptionListTerm><DescriptionListDescription>{children}</DescriptionListDescription></DescriptionListGroup>;
}

/** A configuration-values document as a two-column list; values under an unchosen option are hidden unless asked for. */
function ConfigTable({ items, label, showInactive }: { items: ConfigItem[]; label: string; showInactive: boolean }) {
  const shown = items.filter((i) => showInactive || !i.inactive);
  if (shown.length === 0) {
    return <p className="dc-subtle">None.</p>;
  }
  return (
    <Table aria-label={label} variant="compact">
      <Tbody>
        {shown.map((i, n) => i.kind === 'header' ? (
          <Tr key={n}><Td colSpan={2}><strong style={{ paddingLeft: `${i.depth * 1.25}rem` }}>{i.label}</strong></Td></Tr>
        ) : (
          <Tr key={n} className={i.inactive ? 'dc-subtle' : undefined}>
            <Td width={50} dataLabel="Setting">
              <span style={{ paddingLeft: `${i.depth * 1.25}rem` }}>
                {i.description ? <Tooltip content={i.description}><span>{i.label || i.name}</span></Tooltip> : (i.label || i.name)}
              </span>
            </Td>
            <Td dataLabel="Value" className="dc-mono">{i.value === null || i.value === undefined || i.value === '' ? <span className="dc-subtle">—</span> : i.value}</Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
}

const CHANNEL_COLOR: Record<string, 'green' | 'blue' | 'orange' | 'grey'> = { sync: 'green', notify: 'blue', reset: 'orange', ignore: 'grey' };
const Channel = ({ v }: { v: string }) => (v ? <Label isCompact color={CHANNEL_COLOR[v] ?? 'grey'}>{v}</Label> : <span className="dc-subtle">—</span>);

/**
 * A driver's properties, read-only: what it runs and how it authenticates, its driver parameters, global
 * configuration values (its own and its packages'), engine control values, filter and policies. Only
 * the trace level is changed in the console, on the Trace tab.
 */
export function DriverPropertiesTab({ guid }: { guid: string }) {
  const { me } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const [p, setP] = useState<DriverProperties | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [inactive, setInactive] = useState(false);
  useEffect(() => { api.driverProperties(guid).then(setP, setError); }, [api, guid]);
  if (!p) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Reading the driver's properties" />}</div>;
  }
  const sets = [...new Set(p.policies.map((x) => x.set))];
  const rl = p.authentication.remoteLoader;
  return (
    <div className="dc-tab-body">
      <p className="dc-subtle">Shown as configured; they are changed in Designer. The trace level is changed on the Trace tab.</p>
      <Switch id="show-inactive" label="Show settings under options that are not chosen" isChecked={inactive} onChange={(_e, v) => setInactive(v)} className="dc-tab-body" />
      <DescriptionList isHorizontal isCompact className="dc-tab-body">
        <Item term="Shim">{p.general.javaModule ?? p.general.nativeModule ?? '—'}</Item>
        {p.general.package && <Item term="Package">{p.general.package}</Item>}
        <Item term="Authentication ID">{p.authentication.id ?? '—'}</Item>
        <Item term="Connects to">{p.authentication.server ?? '—'}</Item>
        {rl && <Item term="Remote Loader">{rl.hostname ?? '?'}:{rl.port ?? '?'}{rl.kmo ? <span className="dc-subtle"> · certificate {rl.kmo}</span> : null}</Item>}
        <Item term="Password">{p.authentication.passwordSet ? 'set' : <span className="dc-subtle">not set</span>}</Item>
        {p.general.securityEquals.length > 0 && <Item term="Security equals">{p.general.securityEquals.map((d) => <div key={d} className="dc-mono">{d}</div>)}</Item>}
        {p.general.cacheLimit && p.general.cacheLimit !== '0' && <Item term="Cache limit">{p.general.cacheLimit} KB</Item>}
      </DescriptionList>

      <ExpandableSection toggleText="Driver parameters" isIndented className="dc-tab-body">
        {p.parameters.length === 0 ? <p className="dc-subtle">None.</p> : p.parameters.map((s) => (
          <div key={s.section} className="dc-tab-body"><Title headingLevel="h3" size="md">{s.section}</Title><ConfigTable items={s.items} label={`${s.section} parameters`} showInactive={inactive} /></div>
        ))}
      </ExpandableSection>
      <ExpandableSection toggleText="Global configuration values" isIndented>
        {p.gcvs.filter((g) => g.items.length > 0).length === 0 ? <p className="dc-subtle">None.</p> : p.gcvs.filter((g) => g.items.length > 0).map((g) => (
          <div key={g.source} className="dc-tab-body"><Title headingLevel="h3" size="md">From {g.source}</Title><ConfigTable items={g.items} label={`GCVs from ${g.source}`} showInactive={inactive} /></div>
        ))}
      </ExpandableSection>
      <ExpandableSection toggleText="Engine control values" isIndented>
        <ConfigTable items={p.engineControlValues} label="Engine control values" showInactive={inactive} />
      </ExpandableSection>
      <ExpandableSection toggleText={`Filter (${p.filter.length} class${p.filter.length === 1 ? '' : 'es'})`} isIndented>
        {p.filter.length === 0 ? <p className="dc-subtle">Nothing is synchronized.</p> : (
          <Table aria-label="Filter" variant="compact">
            <Thead><Tr><Th>Class or attribute</Th><Th>Subscriber</Th><Th>Publisher</Th></Tr></Thead>
            <Tbody>
              {p.filter.flatMap((c) => [
                <Tr key={c.name}><Td><strong>{c.name}</strong></Td><Td><Channel v={c.subscriber} /></Td><Td><Channel v={c.publisher} /></Td></Tr>,
                ...c.attributes.map((a) => (
                  <Tr key={`${c.name}/${a.name}`}><Td><span style={{ paddingLeft: '1.25rem' }}>{a.name}</span></Td><Td><Channel v={a.subscriber} /></Td><Td><Channel v={a.publisher} /></Td></Tr>
                )),
              ])}
            </Tbody>
          </Table>
        )}
      </ExpandableSection>
      <ExpandableSection toggleText={`Policies (${p.policies.length})`} isIndented>
        {sets.map((set) => (
          <div key={set} className="dc-tab-body">
            <Title headingLevel="h3" size="md">{set}</Title>
            <ol className="dc-values">{p.policies.filter((x) => x.set === set).map((x) => <li key={x.dn}><span className="dc-mono">{x.name}</span></li>)}</ol>
          </div>
        ))}
      </ExpandableSection>
    </div>
  );
}
