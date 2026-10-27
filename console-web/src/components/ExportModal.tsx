import { useState } from 'react';
import {
  Button, Checkbox, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody,
  ModalFooter, ModalHeader, Radio, ToggleGroup, ToggleGroupItem,
} from '@patternfly/react-core';
import type { ExportFormat, ExportOptions, ExportRequest } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';

/** What the person last chose, kept in this browser. */
interface Remembered {
  format: ExportFormat;
  limit: number;
  ldif: { wrap: number; version: boolean; eol: 'lf' | 'crlf' };
  csv: { delimiter: string; valueDelimiter: string; quote: string; eol: 'lf' | 'crlf'; formulaGuard: boolean; bom: boolean };
}

const KEY = 'dc-export-options';
const DEFAULTS: Remembered = {
  format: 'csv',
  limit: 0,
  ldif: { wrap: 76, version: true, eol: 'lf' },
  csv: { delimiter: ',', valueDelimiter: '|', quote: '"', eol: 'crlf', formulaGuard: true, bom: false },
};

function load(): Remembered {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? 'null') as Partial<Remembered> | null;
    return v ? { ...DEFAULTS, ...v, ldif: { ...DEFAULTS.ldif, ...v.ldif }, csv: { ...DEFAULTS.csv, ...v.csv } } : DEFAULTS;
  } catch {
    return DEFAULTS;
  }
}

function remember(r: Remembered) {
  try {
    localStorage.setItem(KEY, JSON.stringify(r));
  } catch {
    // not kept: the defaults next time
  }
}

/** A choice of what to export, for the browse page: this object, its children, or it and everything below. */
export interface ExportScope {
  scope: 'base' | 'one' | 'subtree';
  label: string;
}

const DELIMITERS = [[',', 'Comma'], [';', 'Semicolon'], ['\t', 'Tab'], ['|', 'Vertical bar']];
const VALUE_DELIMITERS = [['|', 'Vertical bar (|)'], ['; ', 'Semicolon and space (; )'], [',', 'Comma'], ['\n', 'A line break (within the quoted cell)']];
const LIMITS = [[0, 'All'], [1000, '1,000'], [10000, '10,000'], [50000, '50,000']];

/**
 * Export a search, or part of the tree, as LDIF, CSV or JSON: the server writes the file as it reads,
 * with the person's own rights, and the export is audited. Passwords and keys are never written.
 */
export function ExportModal({ query, scopes, format: fixedFormat, title, onClose }: {
  /** The search: base, depth, filter and the attributes (none named: all, for LDIF). */
  query: Omit<ExportRequest, 'format' | 'limit' | 'options'>;
  /** For the browse page: depth choices replacing the query's own. */
  scopes?: ExportScope[];
  /** Start on this format (the browse page offers LDIF first). */
  format?: ExportFormat;
  title: string;
  onClose: () => void;
}) {
  const { tree } = useSession();
  const [r, setR] = useState<Remembered>(() => ({ ...load(), ...(fixedFormat ? { format: fixedFormat } : {}) }));
  const [scope, setScope] = useState(scopes?.[0]?.scope ?? query.scope);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<string | null>(null);
  const set = (p: Partial<Remembered>) => setR((x) => ({ ...x, ...p }));

  const run = async () => {
    setBusy(true);
    setError(null);
    setDone(null);
    remember(r);
    const options: ExportOptions = r.format === 'ldif' ? r.ldif : r.format === 'csv' ? r.csv : {};
    try {
      const name = await tree.exportResults({ ...query, scope, format: r.format, limit: r.limit || undefined, options });
      setDone(`Saved ${name}. Check your browser's downloads.`);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const noColumns = r.format === 'csv' && !(query.attributes ?? []).some((a) => a !== '*' && a !== '+');
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="export-title">
      <ModalHeader title={title} labelId="export-title"
        description="Written as it is read, with your own rights. Passwords and private keys are never included." />
      <ModalBody>
        <Form id="export-form" onSubmit={(e) => { e.preventDefault(); void run(); }}>
          <FormGroup label="Format" fieldId="export-format" role="radiogroup" isInline>
            <ToggleGroup aria-label="Format">
              <ToggleGroupItem text="LDIF" isSelected={r.format === 'ldif'} onChange={() => set({ format: 'ldif' })} />
              <ToggleGroupItem text="CSV" isSelected={r.format === 'csv'} onChange={() => set({ format: 'csv' })} />
              <ToggleGroupItem text="JSON" isSelected={r.format === 'json'} onChange={() => set({ format: 'json' })} />
            </ToggleGroup>
            <FormHelperText><HelperText><HelperTextItem>
              {r.format === 'ldif' ? 'Every attribute you can read (or the columns chosen), for importing elsewhere. Binary values are base64.'
                : r.format === 'csv' ? 'One row per object: DN, name, class, then the columns chosen. Binary values are base64.'
                  : 'One object per entry, with the columns chosen (or every attribute).'}
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {scopes && (
            <FormGroup label="What" fieldId="export-what" role="radiogroup" isStack>
              {scopes.map((s) => <Radio key={s.scope} id={`export-${s.scope}`} name="export-what" label={s.label}
                isChecked={scope === s.scope} onChange={() => setScope(s.scope)} />)}
            </FormGroup>
          )}
          <FormGroup label="At most" fieldId="export-limit">
            <FormSelect id="export-limit" value={r.limit} onChange={(_e, v) => set({ limit: Number(v) })}>
              {LIMITS.map(([v, l]) => <FormSelectOption key={v} value={v} label={l as string} />)}
            </FormSelect>
          </FormGroup>
          {r.format === 'ldif' && (
            <>
              <FormGroup label="Line width" fieldId="export-wrap">
                <FormSelect id="export-wrap" value={r.ldif.wrap} onChange={(_e, v) => set({ ldif: { ...r.ldif, wrap: Number(v) } })}>
                  <FormSelectOption value={76} label="76 characters (RFC 2849)" />
                  <FormSelectOption value={0} label="No folding (one line per value)" />
                </FormSelect>
              </FormGroup>
              <Checkbox id="export-version" label='Start with "version: 1"' isChecked={r.ldif.version}
                onChange={(_e, v) => set({ ldif: { ...r.ldif, version: v } })} />
              <EolChoice id="export-ldif-eol" eol={r.ldif.eol} onChange={(eol) => set({ ldif: { ...r.ldif, eol } })} />
            </>
          )}
          {r.format === 'csv' && (
            <>
              {noColumns && <HelperText><HelperTextItem variant="warning">No columns are chosen: the file has the DN, name and class only.</HelperTextItem></HelperText>}
              <FormGroup label="Between cells" fieldId="export-delim">
                <FormSelect id="export-delim" value={r.csv.delimiter} onChange={(_e, v) => set({ csv: { ...r.csv, delimiter: v } })}>
                  {DELIMITERS.map(([v, l]) => <FormSelectOption key={v} value={v} label={l} />)}
                </FormSelect>
              </FormGroup>
              <FormGroup label="Between values of one attribute" fieldId="export-vdelim">
                <FormSelect id="export-vdelim" value={r.csv.valueDelimiter} onChange={(_e, v) => set({ csv: { ...r.csv, valueDelimiter: v } })}>
                  {VALUE_DELIMITERS.map(([v, l]) => <FormSelectOption key={v} value={v} label={l} />)}
                </FormSelect>
              </FormGroup>
              <FormGroup label="Quote" fieldId="export-quote">
                <FormSelect id="export-quote" value={r.csv.quote} onChange={(_e, v) => set({ csv: { ...r.csv, quote: v } })}>
                  <FormSelectOption value={'"'} label='Double quote (")' />
                  <FormSelectOption value="'" label="Single quote (')" />
                </FormSelect>
              </FormGroup>
              <EolChoice id="export-csv-eol" eol={r.csv.eol} onChange={(eol) => set({ csv: { ...r.csv, eol } })} />
              <Checkbox id="export-guard" label="Keep cells that start with =, +, - or @ as text" description="So a spreadsheet does not run them as formulas."
                isChecked={r.csv.formulaGuard} onChange={(_e, v) => set({ csv: { ...r.csv, formulaGuard: v } })} />
              <Checkbox id="export-bom" label="Mark the file as UTF-8 for Excel" description="Adds a byte-order mark, so Excel shows accented letters correctly."
                isChecked={r.csv.bom} onChange={(_e, v) => set({ csv: { ...r.csv, bom: v } })} />
            </>
          )}
        </Form>
        <ProblemAlert error={error} />
        {done && <HelperText><HelperTextItem variant="success">{done}</HelperTextItem></HelperText>}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="export-form" isLoading={busy} isDisabled={busy}>Export</Button>
        <Button variant="link" onClick={onClose}>{done ? 'Close' : 'Cancel'}</Button>
      </ModalFooter>
    </Modal>
  );
}

function EolChoice({ id, eol, onChange }: { id: string; eol: 'lf' | 'crlf'; onChange: (e: 'lf' | 'crlf') => void }) {
  return (
    <FormGroup label="Line endings" fieldId={id}>
      <FormSelect id={id} value={eol} onChange={(_e, v) => onChange(v as 'lf' | 'crlf')}>
        <FormSelectOption value="lf" label="LF (macOS, Linux)" />
        <FormSelectOption value="crlf" label="CRLF (Windows)" />
      </FormSelect>
    </FormGroup>
  );
}
