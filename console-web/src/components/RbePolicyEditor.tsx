import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Checkbox, Form, FormGroup, FormHelperText, FormSection, FormSelect, FormSelectOption, HelperText, HelperTextItem, Label,
  Modal, ModalBody, ModalFooter, ModalHeader, Radio, Spinner, TextArea, TextInput, ToggleGroup, ToggleGroupItem,
} from '@patternfly/react-core';
import { TimesIcon } from '@patternfly/react-icons';
import {
  type RbeDefinition, type RbeGrantSpec, type RbePolicyDetail, type RbePolicySpec, type RbeRef, type SchemaAttribute, type SchemaClass, idm,
} from '../api';
import { type FilterNode, checkFilter, fromText, newGroup, toText } from '../filterTree';
import { toCriteria } from '../rbeCriteria';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { BrowseContainers } from './ContainerChooser';
import { FilterBuilder } from './FilterBuilder';
import { attributeOptions, classOptions } from './NameInput';
import { ObjectPicker } from './ObjectPicker';
import { ProblemAlert } from './Problem';

type Idm = ReturnType<typeof idm>;
type Identity = 'service' | 'other' | 'none';

/**
 * Create or change a role-based entitlement policy: who it covers (a query, its search identity, static members and
 * exclusions) and what it grants (entitlements the set's drivers define, with values where they take them).
 */
export function RbePolicyEditor({ api, setGuid, serviceDriver, policy, onClose, onSaved }: {
  api: Idm;
  setGuid: string;
  /** The set's Entitlements Service driver: a new policy's search identity unless another is chosen. */
  serviceDriver: { dn: string; name: string } | null;
  /** The policy to change; none to create one. */
  policy?: RbePolicyDetail;
  onClose: () => void;
  onSaved: (name: string) => void;
}) {
  const { tree } = useSession();
  const { run, dialog } = useConfirmed();
  const [name, setName] = useState(policy?.name ?? '');
  const [description, setDescription] = useState(policy?.description ?? '');
  const [byQuery, setByQuery] = useState(policy ? !!policy.membership : true);
  const [base, setBase] = useState(policy?.membership?.base ?? '');
  const [scope, setScope] = useState<'base' | 'one' | 'sub'>(policy?.membership?.scope ?? 'sub');
  const initialFilter = policy?.membership?.filter ?? '(objectClass=inetOrgPerson)';
  const [asText, setAsText] = useState(() => { try { fromText(initialFilter); return false; } catch { return true; } });
  const [text, setText] = useState(initialFilter);
  const [node, setNode] = useState<FilterNode>(() => { try { return fromText(initialFilter); } catch { return newGroup(); } });
  const [identity, setIdentity] = useState<Identity>(() => {
    if (!policy) {
      return serviceDriver ? 'service' : 'none';
    }
    if (!policy.identityDn) {
      return 'none';
    }
    return serviceDriver && policy.identityDn.toLowerCase() === serviceDriver.dn.toLowerCase() ? 'service' : 'other';
  });
  const [otherIdentity, setOtherIdentity] = useState(policy?.identityDn && identity === 'other' ? policy.identityDn : '');
  const [members, setMembers] = useState<string[]>(policy?.staticMembers ?? []);
  const [excluded, setExcluded] = useState<string[]>(policy?.excludedMembers.map((m) => m.dn) ?? []);
  const [grants, setGrants] = useState<RbeGrantSpec[]>(policy?.grantValues ?? []);
  const [catalog, setCatalog] = useState<{ driver: { dn: string; name: string }; entitlements: RbeDefinition[] }[] | null>(null);
  const [attributes, setAttributes] = useState<SchemaAttribute[]>([]);
  const [classes, setClasses] = useState<SchemaClass[]>([]);
  const [tested, setTested] = useState<{ items: RbeRef[]; more: boolean } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.rbeEntitlements(setGuid).then(setCatalog, setError); }, [api, setGuid]);
  useEffect(() => {
    tree.attributes().then((a) => setAttributes(a.filter((x) => !x.binary).sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
    tree.classes().then((c) => setClasses(c.filter((x) => x.kind !== 'abstract').sort((x, y) => x.name.localeCompare(y.name)))).catch(() => undefined);
  }, [tree]);

  const filter = asText ? text.trim() : toText(node);
  const filterProblem = byQuery ? (filter ? checkFilter(filter) : { message: 'a query needs a filter', at: 0 }) : null;
  const switchMode = (toText_: boolean) => {
    if (toText_) {
      setText(toText(node));
      setAsText(true);
      return;
    }
    try {
      setNode(fromText(text));
      setAsText(false);
    } catch (e) {
      setError(e);
    }
  };
  const membership = byQuery ? { base: base.trim(), scope, filter } : null;
  const definitions = useMemo(() => new Map((catalog ?? []).flatMap((d) => d.entitlements.map((e) => [e.dn.toLowerCase(), e] as const))), [catalog]);
  const grantFor = (dn: string) => grants.find((g) => g.entitlement.toLowerCase() === dn.toLowerCase());
  const setGrant = (dn: string, values: string[] | null) => {
    const rest = grants.filter((g) => g.entitlement.toLowerCase() !== dn.toLowerCase());
    setGrants(values === null ? rest : [...rest, { entitlement: dn, values }]);
  };
  const grantProblems = grants.flatMap((g) => {
    const d = definitions.get(g.entitlement.toLowerCase());
    if (!d) {
      return catalog ? [`${g.entitlement} is no longer an entitlement here; remove it`] : [];
    }
    if (d.kind !== 'none' && g.values.length === 0) {
      return [`${d.displayName ?? d.name} needs a value`];
    }
    return [];
  });
  const canSave = (!!policy || name.trim().length > 0) && !filterProblem && (identity !== 'other' || otherIdentity.trim()) && grantProblems.length === 0;

  const save = () => {
    const spec: RbePolicySpec = {
      description: description.trim(),
      membership,
      identity: identity === 'service' ? serviceDriver?.dn ?? null : identity === 'other' ? otherIdentity.trim() : null,
      members,
      excluded,
      grants,
      criteria: byQuery ? (asText ? (() => { try { return toCriteria(fromText(text)); } catch { return null; } })() : toCriteria(node)) : null,
    };
    setBusy(true);
    setError(null);
    run((c) => (policy ? api.rbeChange(policy.guid, { ...spec, version: policy.version }, c) : api.rbeCreate(setGuid, { ...spec, name: name.trim() }, c)))
      .then(() => onSaved(policy?.name ?? name.trim()), setError)
      .finally(() => setBusy(false));
  };

  return (
    <Modal isOpen onClose={onClose} variant="large" aria-labelledby="rbe-edit-title">
      {dialog}
      <ModalHeader title={policy ? `Change ${policy.name}` : 'New entitlement policy'} labelId="rbe-edit-title"
        description="Takes effect when the Entitlements Service driver restarts." />
      <ModalBody>
        <Form onSubmit={(e) => { e.preventDefault(); if (canSave) { save(); } }}>
          {!policy && (
            <FormGroup label="Name" isRequired fieldId="rbe-name">
              <TextInput id="rbe-name" value={name} onChange={(_e, v) => setName(v)} autoFocus />
            </FormGroup>
          )}
          <FormGroup label="Description" fieldId="rbe-description">
            <TextArea id="rbe-description" value={description} onChange={(_e, v) => setDescription(v)} rows={2} resizeOrientation="vertical" />
          </FormGroup>

          <FormSection title="Who it covers" titleElement="h3">
            <Checkbox id="rbe-by-query" label="Members from a query" isChecked={byQuery} onChange={(_e, v) => { setByQuery(v); setTested(null); }}
              description="Everyone the query finds is a member, as eDirectory computes it; static members are added and exclusions taken away." />
            {byQuery && (
              <>
                <FormGroup label="Under" fieldId="rbe-base">
                  <div className="dc-row">
                    <TextInput id="rbe-base" value={base} onChange={(_e, v) => { setBase(v); setTested(null); }} placeholder="the whole tree" className="dc-mono" />
                    <BrowseContainers onChoose={(dn) => { setBase(dn); setTested(null); }} />
                  </div>
                </FormGroup>
                <FormGroup label="Scope" fieldId="rbe-scope">
                  <FormSelect id="rbe-scope" value={scope} onChange={(_e, v) => { setScope(v as typeof scope); setTested(null); }}>
                    <FormSelectOption value="sub" label="The whole subtree" />
                    <FormSelectOption value="one" label="One level below" />
                    <FormSelectOption value="base" label="That object only" />
                  </FormSelect>
                </FormGroup>
                <FormGroup label="Filter" fieldId="rbe-filter">
                  <ToggleGroup aria-label="Filter as" isCompact className="dc-tab-body">
                    <ToggleGroupItem text="Builder" isSelected={!asText} onChange={() => switchMode(false)} />
                    <ToggleGroupItem text="LDAP filter text" isSelected={asText} onChange={() => switchMode(true)} />
                  </ToggleGroup>
                  {asText
                    ? <TextArea id="rbe-filter" value={text} onChange={(_e, v) => { setText(v); setTested(null); }} rows={3} className="dc-mono" resizeOrientation="vertical" />
                    : <FilterBuilder node={node} onChange={(n) => { setNode(n); setTested(null); }} attributes={attributeOptions(attributes)} classes={classOptions(classes)} />}
                  <FormHelperText><HelperText>
                    {filterProblem
                      ? <HelperTextItem variant="error">{filterProblem.message}</HelperTextItem>
                      : <HelperTextItem><span className="dc-mono">{filter}</span></HelperTextItem>}
                    {!filterProblem && !toCriteriaSafe(asText ? text : node) && (
                      <HelperTextItem variant="warning">
                        Designer and Identity Console show this filter only as its query: it uses a test or nesting their editors do not have.
                      </HelperTextItem>
                    )}
                  </HelperText></FormHelperText>
                  <Button variant="secondary" size="sm" className="dc-tab-body" isDisabled={!!filterProblem}
                    onClick={() => { setError(null); api.rbeTest(setGuid, membership!).then(setTested, setError); }}>Test the query</Button>
                  {tested && (
                    <div className="dc-tab-body">
                      <strong>{tested.items.length}{tested.more ? '+' : ''} found</strong>
                      <span className="dc-subtle"> now, with your rights; eDirectory computes the members as the search identity below</span>
                      <ul>{tested.items.slice(0, 20).map((m) => <li key={m.dn} className="dc-mono">{m.dn}</li>)}</ul>
                      {tested.items.length > 20 && <span className="dc-subtle">and {tested.items.length - 20}{tested.more ? '+' : ''} more</span>}
                    </div>
                  )}
                </FormGroup>
                <FormGroup label="Search as" role="radiogroup" isStack fieldId="rbe-identity">
                  <Radio id="rbe-identity-service" name="rbe-identity" isChecked={identity === 'service'} isDisabled={!serviceDriver}
                    onChange={() => setIdentity('service')}
                    label={serviceDriver ? <>The Entitlements Service driver, <strong>{serviceDriver.name}</strong></> : 'The Entitlements Service driver (this set has none)'}
                    description="Members are those the driver's rights let it find." />
                  <Radio id="rbe-identity-other" name="rbe-identity" isChecked={identity === 'other'} onChange={() => setIdentity('other')}
                    label="Another object" description="Its rights decide who the query finds, and the policy borrows them: choose with care." />
                  {identity === 'other' && (
                    <div className="dc-row">
                      <TextInput aria-label="Search identity DN" value={otherIdentity} onChange={(_e, v) => setOtherIdentity(v)} className="dc-mono" />
                      <ObjectPicker label="Find" onPick={(r) => setOtherIdentity(r.dn)} />
                    </div>
                  )}
                  <Radio id="rbe-identity-none" name="rbe-identity" isChecked={identity === 'none'} onChange={() => setIdentity('none')}
                    label="Nobody" description="eDirectory then computes no members from the query; only static members count." />
                </FormGroup>
              </>
            )}
            <DnList label="Static members" help="Members whether or not the query finds them." values={members} onChange={setMembers} />
            <DnList label="Excluded" help="Never members, even when the query finds them or they are static members." values={excluded} onChange={setExcluded} />
          </FormSection>

          <FormSection title="What it grants" titleElement="h3">
            {!catalog ? <Spinner size="md" aria-label="Reading the drivers' entitlements" /> : catalog.length === 0 ? (
              <p className="dc-subtle">No driver in this set defines an entitlement.</p>
            ) : catalog.map((d) => (
              <div key={d.driver.dn} className="dc-tab-body">
                <strong>{d.driver.name}</strong>
                {d.entitlements.map((e) => {
                  const g = grantFor(e.dn);
                  return (
                    <div key={e.dn} className="dc-rbe-grant">
                      <Checkbox id={`rbe-grant-${e.dn}`} isChecked={!!g} onChange={(_x, on) => setGrant(e.dn, on ? [] : null)}
                        label={<>{e.displayName ?? e.name} {e.conflictResolution && <Label isCompact title="When policies grant different values">{e.conflictResolution === 'union' ? 'values merge' : 'priority wins'}</Label>}</>}
                        description={e.description ?? undefined} />
                      {g && <Values definition={e} values={g.values} onChange={(v) => setGrant(e.dn, v)} />}
                    </div>
                  );
                })}
              </div>
            ))}
            {grants.filter((g) => catalog && !definitions.get(g.entitlement.toLowerCase())).map((g) => (
              <Alert key={g.entitlement} variant="warning" isInline isPlain title={`${g.entitlement}: not an entitlement of this set's drivers`}
                actionLinks={<Button variant="link" isInline onClick={() => setGrant(g.entitlement, null)}>Remove it</Button>} />
            ))}
            {grantProblems.length > 0 && <HelperText><HelperTextItem variant="error">{grantProblems.join('; ')}</HelperTextItem></HelperText>}
          </FormSection>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={save} isLoading={busy} isDisabled={busy || !canSave}>{policy ? 'Save' : 'Create'}</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

function toCriteriaSafe(f: string | FilterNode): string | null {
  try {
    return toCriteria(typeof f === 'string' ? fromText(f) : f);
  } catch {
    return null;
  }
}

/** A list of DNs, each removable, with a finder to add more. */
function DnList({ label, help, values, onChange }: { label: string; help: string; values: string[]; onChange: (v: string[]) => void }) {
  return (
    <FormGroup label={label} fieldId={`rbe-${label}`}>
      {values.length === 0 ? <div className="dc-subtle">none</div> : values.map((dn) => (
        <div key={dn} className="dc-row">
          <span className="dc-mono">{dn}</span>
          <Button variant="plain" size="sm" aria-label={`Remove ${dn}`} icon={<TimesIcon />} onClick={() => onChange(values.filter((v) => v !== dn))} />
        </div>
      ))}
      <ObjectPicker label="Add" exclude={[]} onPick={(r) => { if (!values.some((v) => v.toLowerCase() === r.dn.toLowerCase())) { onChange([...values, r.dn]); } }} />
      <FormHelperText><HelperText><HelperTextItem>{help}</HelperTextItem></HelperText></FormHelperText>
    </FormGroup>
  );
}

/** The values granted for one entitlement, as its definition allows: picked from its list, or typed. */
function Values({ definition: d, values, onChange }: { definition: RbeDefinition; values: string[]; onChange: (v: string[]) => void }) {
  const [typed, setTyped] = useState('');
  if (d.kind === 'none') {
    return null;
  }
  if (d.kind === 'list') {
    return (
      <div className="dc-rbe-values">
        {d.values.map((v) => d.multiValued ? (
          <Checkbox key={v} id={`rbe-v-${d.dn}-${v}`} label={v} isChecked={values.includes(v)}
            onChange={(_e, on) => onChange(on ? [...values, v] : values.filter((x) => x !== v))} />
        ) : (
          <Radio key={v} id={`rbe-v-${d.dn}-${v}`} name={`rbe-v-${d.dn}`} label={v} isChecked={values[0] === v} onChange={() => onChange([v])} />
        ))}
      </div>
    );
  }
  const add = () => {
    const v = typed.trim();
    if (v && !values.includes(v)) {
      onChange(d.multiValued ? [...values, v] : [v]);
    }
    setTyped('');
  };
  return (
    <div className="dc-rbe-values">
      {values.map((v) => (
        <Label key={v} onClose={() => onChange(values.filter((x) => x !== v))} closeBtnAriaLabel={`Remove ${v}`}>{v}</Label>
      ))}
      <div className="dc-row">
        <TextInput aria-label={`A value for ${d.name}`} value={typed} onChange={(_e, v) => setTyped(v)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
          placeholder={d.kind === 'query' ? 'a value the application knows' : 'a value'} />
        <Button variant="secondary" size="sm" onClick={add} isDisabled={!typed.trim()}>{d.multiValued || values.length === 0 ? 'Add' : 'Replace'}</Button>
      </div>
      {d.kind === 'query' && <span className="dc-subtle">The driver offers its values by asking the application; type them as the application names them.</span>}
    </div>
  );
}
