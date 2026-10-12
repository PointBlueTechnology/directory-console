import { useState } from 'react';
import { Button, Label, Spinner } from '@patternfly/react-core';
import { type Value, isAcl, isBinary, isReference, isWithheld } from '../api';
import { useSession } from '../session';
import { navigate } from '../router';

/** One attribute value: text, a reference opened by GUID, a binary summary, or an ACL in words. */
export function ValueView({ value }: { value: Value }) {
  if (typeof value === 'string') {
    return <span className="dc-mono">{value}</span>;
  }
  if (isWithheld(value)) {
    return <Label isCompact color="purple">set ({value.withheld} value{value.withheld === 1 ? '' : 's'}), never shown</Label>;
  }
  if (isBinary(value)) {
    return <Label isCompact>{Math.floor((value.base64.length * 3) / 4) - (value.base64.endsWith('==') ? 2 : value.base64.endsWith('=') ? 1 : 0)} bytes, binary</Label>;
  }
  if (isAcl(value)) {
    return (
      <span>
        {value.privileges.length ? value.privileges.join(', ') : 'no rights'} on <strong>{value.attribute}</strong> for{' '}
        {'special' in value.trustee ? <code>{value.trustee.special}</code> : <ReferenceLink dn={value.trustee.dn} name={value.trustee.name} />}
        {' '}<Label isCompact>{value.scope === 'subtree' ? 'inherited' : 'this object'}</Label>
      </span>
    );
  }
  if (isReference(value)) {
    return <ReferenceLink dn={value.dn} name={value.name} />;
  }
  return <span>{JSON.stringify(value)}</span>;
}

/** A DN in a value is resolved to its GUID when followed, never put in a URL. */
export function ReferenceLink({ dn, name }: { dn: string; name: string }) {
  const { tree } = useSession();
  const [busy, setBusy] = useState(false);
  const [missing, setMissing] = useState(false);
  const open = async () => {
    setBusy(true);
    try {
      const r = await tree.resolve(dn);
      navigate(`/objects/${r.data.guid}`);
    } catch {
      setMissing(true);
    } finally {
      setBusy(false);
    }
  };
  return (
    <span title={dn}>
      <Button variant="link" isInline onClick={open} isDisabled={missing}>{name}</Button>
      {busy && <Spinner size="sm" aria-label="Opening" />}
      {missing && <> <Label isCompact color="orange">not found</Label></>}
      <span className="dc-mono dc-subtle"> {dn}</span>
    </span>
  );
}
