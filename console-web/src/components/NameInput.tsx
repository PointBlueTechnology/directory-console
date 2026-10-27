import { useRef, useState } from 'react';
import { Menu, MenuContent, MenuItem, MenuList, Popper, TextInput } from '@patternfly/react-core';
import { type NameOption, matches } from '../names';

export { type NameOption, attributeOptions, classOptions, matches } from '../names';

/** In a list typed with commas or spaces, the word at the end: what is being typed now. */
function lastWord(v: string): { word: string; start: number } {
  const m = /[^\s,;]*$/.exec(v);
  return { word: m ? m[0] : '', start: m ? m.index : v.length };
}

/**
 * A text box that offers attribute or class names as they are typed, from this directory's schema.
 * Arrow down moves into the offers, Enter or a click takes one, Escape closes them. With {@code list},
 * the box holds several names (commas or spaces between) and offers complete the last one.
 */
export function NameInput({ id, value, onChange, options, list, placeholder, ariaLabel, isDisabled }: {
  id?: string;
  value: string;
  onChange: (v: string) => void;
  options: NameOption[];
  list?: boolean;
  placeholder?: string;
  ariaLabel?: string;
  isDisabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const typed = list ? lastWord(value).word : value;
  const offers = matches(options, typed);
  const shown = open && offers.length > 0;

  const take = (name: string) => {
    if (list) {
      const { start } = lastWord(value);
      onChange(`${value.slice(0, start)}${name}, `);
    } else {
      onChange(name);
      setOpen(false);
    }
    input.current?.focus();
  };

  return (
    <Popper
      trigger={
        <TextInput id={id} ref={input} value={value} placeholder={placeholder} aria-label={ariaLabel} isDisabled={isDisabled}
          autoComplete="off" role="combobox" aria-expanded={shown} aria-autocomplete="list"
          onChange={(_e, v) => { onChange(v); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={(e) => { if (!menu.current?.contains(e.relatedTarget as Node)) { setOpen(false); } }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown' && shown) {
              e.preventDefault();
              menu.current?.querySelector<HTMLElement>('button, [role="menuitem"]')?.focus();
            } else if (e.key === 'Escape') {
              setOpen(false);
            }
          }} />
      }
      popper={
        <Menu ref={menu} isScrollable onSelect={(_e, v) => take(String(v))}
          onKeyDown={(e) => { if (e.key === 'Escape') { setOpen(false); input.current?.focus(); } }}
          onBlur={(e) => { if (e.relatedTarget !== input.current && !menu.current?.contains(e.relatedTarget as Node)) { setOpen(false); } }}>
          <MenuContent maxMenuHeight="16rem">
            <MenuList>
              {offers.map((o) => (
                <MenuItem key={o.name} itemId={o.name} description={o.note}>
                  <span className="dc-mono">{o.name}</span>
                </MenuItem>
              ))}
            </MenuList>
          </MenuContent>
        </Menu>
      }
      isVisible={shown}
      appendTo={() => document.body}
      minWidth="trigger"
    />
  );
}
