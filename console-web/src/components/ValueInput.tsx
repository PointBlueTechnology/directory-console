import { useState } from 'react';
import { Button, FileUpload, FormSelect, FormSelectOption, TextInput } from '@patternfly/react-core';
import type { SchemaAttribute } from '../api';
import { ObjectPicker } from './ObjectPicker';

const DN = '1.3.6.1.4.1.1466.115.121.1.12';
const BOOLEAN = '1.3.6.1.4.1.1466.115.121.1.7';
const INTEGER = '1.3.6.1.4.1.1466.115.121.1.27';
const TIME = '1.3.6.1.4.1.1466.115.121.1.24';

/** A value as the API takes it: text, true/false, {guid} for a reference, {base64} for binary; undefined while empty. */
export type InputValue = string | boolean | { guid: string } | { base64: string } | undefined;

/** "2026-10-13T09:30" in the browser's time → "20261013143000Z" (generalized time is UTC). */
function generalized(local: string): string {
  return new Date(local).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z').replace('T', '');
}

/**
 * One value, entered as its syntax needs: a reference is picked, a boolean chosen, a time in the
 * browser's own time zone, binary from a file; anything else is text. {@code attribute} undefined
 * (not in the schema the console read) falls back to text.
 */
export function ValueInput({ id, attribute, onChange }: { id: string; attribute?: SchemaAttribute; onChange: (v: InputValue) => void }) {
  const [text, setText] = useState('');
  const [picked, setPicked] = useState<{ name: string; dn: string } | null>(null);
  const [file, setFile] = useState('');
  const syntax = attribute?.syntax;

  if (syntax === DN) {
    return picked ? (
      <span>{picked.name} <span className="dc-subtle dc-mono">{picked.dn}</span>{' '}
        <Button variant="link" isInline onClick={() => { setPicked(null); onChange(undefined); }}>Change</Button></span>
    ) : <ObjectPicker label="Find the object it refers to" onPick={(r) => { setPicked(r); onChange({ guid: r.guid }); }} />;
  }
  if (syntax === BOOLEAN) {
    return (
      <FormSelect id={id} value={text} onChange={(_e, v) => { setText(v); onChange(v === '' ? undefined : v === 'true'); }}>
        <FormSelectOption value="" label="Choose" isPlaceholder />
        <FormSelectOption value="true" label="True" />
        <FormSelectOption value="false" label="False" />
      </FormSelect>
    );
  }
  if (syntax === TIME) {
    return <TextInput id={id} type="datetime-local" value={text} onChange={(_e, v) => { setText(v); onChange(v ? generalized(v) : undefined); }} />;
  }
  if (attribute?.binary) {
    return (
      <FileUpload id={id} filename={file} filenamePlaceholder="Choose a file" browseButtonText="Choose" hideDefaultPreview
        onFileInputChange={(_e, f) => {
          setFile(f.name);
          f.arrayBuffer().then((b) => {
            let s = '';
            new Uint8Array(b).forEach((x) => { s += String.fromCharCode(x); });
            onChange({ base64: btoa(s) });
          });
        }}
        onClearClick={() => { setFile(''); onChange(undefined); }} />
    );
  }
  return (
    <TextInput id={id} type={syntax === INTEGER ? 'number' : 'text'} value={text}
      onChange={(_e, v) => { setText(v); onChange(v.trim() ? v.trim() : undefined); }} />
  );
}
