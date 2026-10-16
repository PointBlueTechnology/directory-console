import { useCallback, useState } from 'react';
import { Button, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { ApiError } from '../api';
import { explain } from '../help/glossary';

/**
 * Run an Identity Manager operation; when the directory is production the console answers 409
 * "confirm-directory", this asks for the directory's name and runs it again with it.
 */
export function useConfirmed() {
  const [pending, setPending] = useState<null | { message: string; retry: (name: string) => void; cancel: () => void }>(null);

  const run = useCallback(<T,>(op: (confirm?: string) => Promise<T>): Promise<T> => op().catch((e) => {
    if (!(e instanceof ApiError) || e.code !== 'confirm-directory') {
      throw e;
    }
    return new Promise<T>((resolve, reject) => {
      setPending({
        message: e.message,
        retry: (name) => { setPending(null); op(name).then(resolve, reject); },
        cancel: () => { setPending(null); reject(new Error('Not confirmed.')); },
      });
    });
  }), []);

  const dialog = pending ? <ConfirmDialog message={pending.message} onConfirm={pending.retry} onCancel={pending.cancel} /> : null;
  return { run, dialog };
}

function ConfirmDialog({ message, onConfirm, onCancel }: { message: string; onConfirm: (name: string) => void; onCancel: () => void }) {
  const [name, setName] = useState('');
  return (
    <Modal isOpen onClose={onCancel} variant="small" aria-labelledby="confirm-title">
      <ModalHeader title="Production tree" titleIconVariant="warning" labelId="confirm-title" />
      <ModalBody>
        <p>{message}</p>
        <Form id="confirm-form" onSubmit={(e) => { e.preventDefault(); onConfirm(name); }} className="dc-tab-body">
          <FormGroup label="Tree name" fieldId="confirm-name" isRequired>
            <TextInput id="confirm-name" value={name} onChange={(_e, v) => setName(v)} autoFocus />
            <FormHelperText><HelperText><HelperTextItem>{explain('directoryName')}</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="confirm-form" isDisabled={!name}>Go ahead</Button>
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** "Are you sure?" for a disruptive operation (stopping a driver, clearing its cache) on any directory. */
export function useAreYouSure() {
  const [pending, setPending] = useState<null | { title: string; body: string; action: string; go: () => void }>(null);
  const ask = useCallback((title: string, body: string, action: string, go: () => void) => setPending({ title, body, action, go }), []);
  const dialog = pending ? (
    <Modal variant="small" isOpen onClose={() => setPending(null)} aria-labelledby="sure-title">
      <ModalHeader title={pending.title} labelId="sure-title" titleIconVariant="warning" />
      <ModalBody>{pending.body}</ModalBody>
      <ModalFooter>
        <Button variant="danger" onClick={() => { const go = pending.go; setPending(null); go(); }}>{pending.action}</Button>
        <Button variant="link" onClick={() => setPending(null)}>Cancel</Button>
      </ModalFooter>
    </Modal>
  ) : null;
  return { ask, dialog };
}
