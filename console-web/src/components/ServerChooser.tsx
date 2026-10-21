import { Flex, FlexItem, FormSelect, FormSelectOption, Label } from '@patternfly/react-core';
import { ServerIcon } from '@patternfly/react-icons';
import { explain } from '../help/glossary';
import { Hint } from '../help/Help';

export interface ServerChoice { guid: string; name: string; connected?: boolean }

/**
 * Which server's engine Identity Manager works on: a choice when several servers run the driver set, and otherwise a
 * label naming the one, so it is always clear where state, starting and stopping apply.
 */
export function ServerChooser({ id, choices, server, onChange }: {
  id: string; choices: ServerChoice[]; server: string | undefined; onChange: (guid: string | undefined) => void;
}) {
  if (choices.length === 0) {
    return null;
  }
  const label = (x: ServerChoice) => `${x.name}${x.connected ? ' (connected)' : ''}`;
  return (
    <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsSm' }} flexWrap={{ default: 'nowrap' }}>
      <FlexItem><Hint text={explain('idmServer')}><span className="dc-subtle"><ServerIcon /> Server</span></Hint></FlexItem>
      <FlexItem>
        {choices.length > 1 ? (
          <FormSelect id={id} aria-label="Server" value={server ?? ''} onChange={(_e, v) => onChange(v || undefined)}>
            {choices.map((x) => <FormSelectOption key={x.guid} value={x.connected ? '' : x.guid} label={label(x)} />)}
          </FormSelect>
        ) : (
          <Label isCompact>{label(choices[0])}</Label>
        )}
      </FlexItem>
      {choices.length === 1 && <FlexItem><span className="dc-subtle">the only server running this driver set</span></FlexItem>}
    </Flex>
  );
}
