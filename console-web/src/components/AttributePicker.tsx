import { useMemo, useState } from 'react';
import {
  Button, DataList, DataListAction, DataListCell, DataListItem, DataListItemCells, DataListItemRow, Flex, FlexItem, FormGroup,
  FormHelperText, HelperText, HelperTextItem, Menu, MenuContent, MenuItem, MenuList, Modal, ModalBody, ModalFooter, ModalHeader,
  SearchInput, TextArea,
} from '@patternfly/react-core';
import { ArrowDownIcon, ArrowUpIcon, TimesIcon } from '@patternfly/react-icons';
import type { SchemaAttribute } from '../api';
import { columnList } from '../report';

const SPECIAL = [
  { name: '*', description: 'every attribute you can read' },
  { name: '+', description: 'operational attributes (creatorsName, modifyTimestamp…)' },
];

/**
 * Choose the attributes a search returns, in order: pick from the schema, or paste a list. The order is
 * the columns' order in the results and in exports.
 */
export function AttributePicker({ attributes, chosen, onChoose, onClose }: {
  attributes: SchemaAttribute[];
  chosen: string[];
  onChoose: (names: string[]) => void;
  onClose: () => void;
}) {
  const [list, setList] = useState<string[]>(chosen);
  const [find, setFind] = useState('');
  const [pasted, setPasted] = useState(chosen.join(', '));
  const lower = new Set(list.map((x) => x.toLowerCase()));
  const known = useMemo(() => new Set(attributes.map((a) => a.name.toLowerCase())), [attributes]);
  const shown = [...SPECIAL.map((s) => ({ name: s.name, description: s.description })),
    ...attributes.map((a) => ({ name: a.name, description: a.ndsName && a.ndsName !== a.name ? a.ndsName : '' }))]
    .filter((a) => !lower.has(a.name.toLowerCase()) && a.name.toLowerCase().includes(find.trim().toLowerCase()))
    .slice(0, 200);

  const update = (next: string[]) => {
    setList(next);
    setPasted(next.join(', '));
  };
  const move = (i: number, d: number) => {
    const next = [...list];
    [next[i], next[i + d]] = [next[i + d], next[i]];
    update(next);
  };
  const unknown = list.filter((x) => x !== '*' && x !== '+' && !known.has(x.toLowerCase()));

  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="attr-picker-title">
      <ModalHeader title="Columns" labelId="attr-picker-title" description="The attributes each result shows, in this order. Exports use the same columns." />
      <ModalBody>
        <Flex alignItems={{ default: 'alignItemsFlexStart' }} flexWrap={{ default: 'wrap', md: 'nowrap' }}>
          <FlexItem flex={{ default: 'flex_1' }}>
            <SearchInput aria-label="Find an attribute" placeholder="Find an attribute" value={find} onChange={(_e, v) => setFind(v)} onClear={() => setFind('')} />
            <Menu isScrollable className="dc-attr-picker" onSelect={(_e, v) => update([...list, String(v)])}>
              <MenuContent maxMenuHeight="18rem">
                <MenuList aria-label="Attributes to add">
                  {shown.map((a) => (
                    <MenuItem key={a.name} itemId={a.name} description={a.description || undefined}>
                      <span className="dc-mono">{a.name}</span>
                    </MenuItem>
                  ))}
                  {shown.length === 0 && <MenuItem isDisabled itemId="none">Nothing matches</MenuItem>}
                </MenuList>
              </MenuContent>
            </Menu>
          </FlexItem>
          <FlexItem flex={{ default: 'flex_1' }}>
            <strong>Chosen ({list.length})</strong>
            {list.length === 0 && <p className="dc-subtle">None: results show the name and class.</p>}
            <DataList aria-label="Chosen attributes" isCompact>
              {list.map((a, i) => (
                <DataListItem key={a} aria-labelledby={`chosen-${i}`}>
                  <DataListItemRow>
                    <DataListItemCells dataListCells={[<DataListCell key="n"><span id={`chosen-${i}`} className="dc-mono">{a}</span></DataListCell>]} />
                    <DataListAction id={`chosen-${i}-actions`} aria-label={`Order of ${a}`} aria-labelledby={`chosen-${i}`}>
                      <Button variant="plain" size="sm" aria-label={`Move ${a} up`} icon={<ArrowUpIcon />} isDisabled={i === 0} onClick={() => move(i, -1)} />
                      <Button variant="plain" size="sm" aria-label={`Move ${a} down`} icon={<ArrowDownIcon />} isDisabled={i === list.length - 1} onClick={() => move(i, 1)} />
                      <Button variant="plain" size="sm" aria-label={`Remove ${a}`} icon={<TimesIcon />} onClick={() => update(list.filter((_x, j) => j !== i))} />
                    </DataListAction>
                  </DataListItemRow>
                </DataListItem>
              ))}
            </DataList>
          </FlexItem>
        </Flex>
        <FormGroup label="Or paste a list" fieldId="attr-paste" className="dc-tab-body">
          <TextArea id="attr-paste" rows={2} className="dc-mono" value={pasted} placeholder="cn, sn, mail"
            onChange={(_e, v) => { setPasted(v); setList(columnList(v)); }} />
          <FormHelperText><HelperText>
            {unknown.length > 0
              ? <HelperTextItem variant="warning">Not in this directory's schema: {unknown.join(', ')}</HelperTextItem>
              : <HelperTextItem>Commas or spaces between names. The order is kept.</HelperTextItem>}
          </HelperText></FormHelperText>
        </FormGroup>
      </ModalBody>
      <ModalFooter>
        <Button onClick={() => { onChoose(list); onClose(); }}>Use these columns</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
