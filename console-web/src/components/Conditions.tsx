import { Button, FormGroup, FormSelect, FormSelectOption, TextInput, ToggleGroup, ToggleGroupItem } from '@patternfly/react-core';
import { MinusCircleIcon, PlusCircleIcon } from '@patternfly/react-icons';
import type { SchemaAttribute } from '../api';
import { type Condition, OPS } from '../filters';
import { NameInput, attributeOptions } from './NameInput';

export const EMPTY_CONDITION: Condition = { attribute: 'cn', op: 'prefix', value: '' };

/** "Where": rows of attribute, test and value, joined by all or any. Used by Search and by Identity Manager's migrate. */
export function ConditionsEditor({ id, conditions, onChange, join, onJoin, attributes }: {
  id: string;
  conditions: Condition[];
  onChange: (c: Condition[]) => void;
  join: 'and' | 'or';
  onJoin: (j: 'and' | 'or') => void;
  attributes: SchemaAttribute[];
}) {
  const options = attributeOptions(attributes);
  const set = (i: number, c: Partial<Condition>) => onChange(conditions.map((x, j) => (i === j ? { ...x, ...c } : x)));
  return (
    <FormGroup label="Where" fieldId={`${id}-0-attr`}>
      <ToggleGroup aria-label="Match" isCompact>
        <ToggleGroupItem text="All of these" isSelected={join === 'and'} onChange={() => onJoin('and')} />
        <ToggleGroupItem text="Any of these" isSelected={join === 'or'} onChange={() => onJoin('or')} />
      </ToggleGroup>
      {conditions.map((c, i) => {
        const needs = OPS.find((o) => o.op === c.op)?.needsValue;
        return (
          <div key={i} className="dc-filter-row dc-tab-body">
            <NameInput id={`${id}-${i}-attr`} ariaLabel="Attribute" options={options} value={c.attribute} onChange={(v) => set(i, { attribute: v })} />
            <FormSelect aria-label="Test" value={c.op} onChange={(_e, v) => set(i, { op: v as Condition['op'] })}>
              {OPS.map((o) => <FormSelectOption key={o.op} value={o.op} label={o.label} />)}
            </FormSelect>
            <TextInput aria-label="Value" value={c.value} isDisabled={!needs} onChange={(_e, v) => set(i, { value: v })} />
            <Button variant="plain" aria-label="Remove this condition" icon={<MinusCircleIcon />} isDisabled={conditions.length === 1}
              onClick={() => onChange(conditions.filter((_x, j) => j !== i))} />
          </div>
        );
      })}
      <Button variant="link" icon={<PlusCircleIcon />} onClick={() => onChange([...conditions, { ...EMPTY_CONDITION, attribute: '' }])}>Add a condition</Button>
    </FormGroup>
  );
}
