import { useState } from 'react';
import { Button, Modal, ModalBody, ModalFooter, ModalHeader } from '@patternfly/react-core';
import { FolderOpenIcon } from '@patternfly/react-icons';
import type { Row } from '../api';
import { ContainerTree } from './ContainerTree';

/**
 * A Browse button beside a DN field: it opens the directory's containers, a level at a time, and puts the chosen
 * one's DN into the field.
 */
export function BrowseContainers({ onChoose, title = 'Choose a container', label = 'Browse' }: {
  onChoose: (dn: string) => void;
  title?: string;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [row, setRow] = useState<Row | null>(null);
  const close = () => { setOpen(false); setRow(null); };
  return (
    <>
      <Button variant="secondary" icon={<FolderOpenIcon />} onClick={() => setOpen(true)}>{label}</Button>
      {open && (
        <Modal isOpen onClose={close} variant="medium" aria-labelledby="choose-container-title">
          <ModalHeader title={title} labelId="choose-container-title" description="Open a container to see the ones inside it." />
          <ModalBody>
            <div className="dc-chooser">
              <ContainerTree selected={row?.guid} onSelect={setRow} />
            </div>
            <p className="dc-tab-body">{row ? <>Chosen: <span className="dc-mono">{row.dn}</span></> : <span className="dc-subtle">Nothing chosen yet.</span>}</p>
          </ModalBody>
          <ModalFooter>
            <Button isDisabled={!row} onClick={() => { if (row) { onChoose(row.dn); close(); } }}>Use this container</Button>
            <Button variant="link" onClick={close}>Cancel</Button>
          </ModalFooter>
        </Modal>
      )}
    </>
  );
}
