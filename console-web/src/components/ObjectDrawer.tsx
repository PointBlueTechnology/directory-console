import { useEffect, useState } from 'react';
import {
  Drawer, DrawerActions, DrawerCloseButton, DrawerContent, DrawerContentBody, DrawerHead, DrawerPanelBody, DrawerPanelContent,
} from '@patternfly/react-core';
import type { DirObject } from '../api';
import { ObjectPanel } from './ObjectPanel';
import { ErrorBoundary } from './ErrorBoundary';

const WIDE = '(min-width: 75rem)';

/** A page with the selected object's details beside it (wide screens) or over it (narrow ones). */
export function ObjectDrawer({ guid, onClose, onChanged, children }: {
  guid: string | null;
  onClose: () => void;
  onChanged: (o: DirObject | null) => void;
  children: React.ReactNode;
}) {
  const wide = useMedia(WIDE);
  const panel = (
    <DrawerPanelContent isResizable defaultSize={wide ? '40%' : '85%'} minSize="24rem">
      <DrawerHead>
        <DrawerActions>
          <DrawerCloseButton onClick={onClose} />
        </DrawerActions>
      </DrawerHead>
      <DrawerPanelBody>
        {guid && <ErrorBoundary resetKey={guid}><ObjectPanel key={guid} guid={guid} onChanged={onChanged} /></ErrorBoundary>}
      </DrawerPanelBody>
    </DrawerPanelContent>
  );
  return (
    <Drawer isExpanded={!!guid} isInline={wide}>
      <DrawerContent panelContent={panel}>
        <DrawerContentBody>{children}</DrawerContentBody>
      </DrawerContent>
    </Drawer>
  );
}

function useMedia(query: string): boolean {
  const [on, setOn] = useState(() => window.matchMedia?.(query).matches ?? true);
  useEffect(() => {
    const m = window.matchMedia(query);
    const f = () => setOn(m.matches);
    m.addEventListener('change', f);
    return () => m.removeEventListener('change', f);
  }, [query]);
  return on;
}
