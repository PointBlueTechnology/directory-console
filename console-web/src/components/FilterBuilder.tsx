import {
  Button, Dropdown, DropdownItem, DropdownList, FormSelect, FormSelectOption, MenuToggle, TextInput, ToggleGroup, ToggleGroupItem,
} from '@patternfly/react-core';
import { EllipsisVIcon, PlusCircleIcon } from '@patternfly/react-icons';
import { useState } from 'react';
import { type FilterNode, newCondition, newGroup } from '../filterTree';
import { OPS } from '../filters';

/**
 * The advanced search's filter as items: groups that need all or any of what they hold, NOT around one
 * item, and conditions (attribute, test, value). Groups nest to any depth.
 */
export function FilterBuilder({ node, onChange, listId }: {
  node: FilterNode;
  onChange: (n: FilterNode) => void;
  /** A datalist of attribute names for the attribute boxes. */
  listId: string;
}) {
  // the top is always a group, so there is somewhere to add items
  const top: FilterNode = node.kind === 'and' || node.kind === 'or' ? node : { kind: 'and', children: [node] };
  return <Item node={top} onChange={onChange} listId={listId} path="f" />;
}

function Item({ node, onChange, onRemove, onWrap, listId, path }: {
  node: FilterNode;
  onChange: (n: FilterNode) => void;
  onRemove?: () => void;
  onWrap?: () => void;
  listId: string;
  path: string;
}) {
  if (node.kind === 'cond') {
    const needs = OPS.find((o) => o.op === node.op)?.needsValue;
    return (
      <div className="dc-filter-row">
        <TextInput id={`${path}-attr`} aria-label="Attribute" list={listId} value={node.attribute} placeholder="attribute"
          onChange={(_e, v) => onChange({ ...node, attribute: v })} />
        <FormSelect aria-label="Test" value={node.op} onChange={(_e, v) => onChange({ ...node, op: v as typeof node.op })}>
          {OPS.map((o) => <FormSelectOption key={o.op} value={o.op} label={o.label} />)}
        </FormSelect>
        <TextInput aria-label="Value" value={node.value} isDisabled={!needs} placeholder={needs ? 'value' : ''}
          onChange={(_e, v) => onChange({ ...node, value: v })} />
        <ItemMenu label="this condition" onRemove={onRemove} onWrap={onWrap} />
      </div>
    );
  }
  if (node.kind === 'not') {
    return (
      <div className="dc-filter-group dc-filter-not">
        <div className="dc-filter-group-head">
          <strong>Not</strong>
          <span className="dc-subtle">matches what does not match:</span>
          <ItemMenu label="this NOT" onRemove={onRemove} onUnwrap={() => onChange(node.child)} />
        </div>
        <Item node={node.child} listId={listId} path={`${path}-n`} onChange={(c) => onChange({ ...node, child: c })} />
      </div>
    );
  }
  const set = (i: number, c: FilterNode) => onChange({ ...node, children: node.children.map((x, j) => (i === j ? c : x)) });
  const remove = (i: number) => onChange({ ...node, children: node.children.filter((_x, j) => j !== i) });
  return (
    <div className="dc-filter-group">
      <div className="dc-filter-group-head">
        <ToggleGroup aria-label="Match" isCompact>
          <ToggleGroupItem text="All of these" isSelected={node.kind === 'and'} onChange={() => onChange({ ...node, kind: 'and' })} />
          <ToggleGroupItem text="Any of these" isSelected={node.kind === 'or'} onChange={() => onChange({ ...node, kind: 'or' })} />
        </ToggleGroup>
        {(onRemove || onWrap) && <ItemMenu label="this group" onRemove={onRemove} onWrap={onWrap} />}
      </div>
      {node.children.map((c, i) => (
        <Item key={i} node={c} listId={listId} path={`${path}-${i}`} onChange={(n) => set(i, n)}
          onRemove={() => remove(i)} onWrap={() => set(i, { kind: 'not', child: c })} />
      ))}
      {node.children.length === 0 && <p className="dc-subtle">Empty: add a condition or a group.</p>}
      <div className="dc-filter-add">
        <Button variant="link" size="sm" icon={<PlusCircleIcon />} onClick={() => onChange({ ...node, children: [...node.children, newCondition()] })}>Condition</Button>
        <Button variant="link" size="sm" icon={<PlusCircleIcon />}
          onClick={() => onChange({ ...node, children: [...node.children, newGroup(node.kind === 'and' ? 'or' : 'and')] })}>Group</Button>
      </div>
    </div>
  );
}

function ItemMenu({ label, onRemove, onWrap, onUnwrap }: { label: string; onRemove?: () => void; onWrap?: () => void; onUnwrap?: () => void }) {
  const [open, setOpen] = useState(false);
  if (!onRemove && !onWrap && !onUnwrap) {
    return <span />;
  }
  return (
    <Dropdown isOpen={open} onOpenChange={setOpen} popperProps={{ position: 'right' }}
      toggle={(ref) => <MenuToggle ref={ref} variant="plain" aria-label={`Actions for ${label}`} icon={<EllipsisVIcon />} onClick={() => setOpen(!open)} isExpanded={open} />}>
      <DropdownList>
        {onWrap && <DropdownItem key="wrap" onClick={() => { setOpen(false); onWrap(); }} description="Match what does not match it">Put inside NOT</DropdownItem>}
        {onUnwrap && <DropdownItem key="unwrap" onClick={() => { setOpen(false); onUnwrap(); }}>Remove the NOT, keep what is inside</DropdownItem>}
        {onRemove && <DropdownItem key="remove" onClick={() => { setOpen(false); onRemove(); }}>Remove {label}</DropdownItem>}
      </DropdownList>
    </Dropdown>
  );
}
