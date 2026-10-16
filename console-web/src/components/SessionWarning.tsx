import { useEffect, useState } from 'react';
import { Button, Modal, ModalBody, ModalFooter, ModalHeader } from '@patternfly/react-core';
import { lastServerContact, session, sessionLimits } from '../api';
import { useSession } from '../session';

/** Warn this long before the session would time out. */
const IDLE_WARNING_MS = 2 * 60 * 1000;
/** Warn this long before the session's hard end. */
const END_WARNING_MS = 5 * 60 * 1000;

const clock = (ms: number) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};

/**
 * Warns before the session ends. Idle time is counted from the console's last answer, so this asks the
 * console nothing until the person chooses to stay. That keeps the warning from extending the session.
 * At the idle limit it checks the session, which signs the person out when it has ended. The tree's
 * longest session cannot be extended: that warning only says when it ends.
 */
export function SessionWarning() {
  const { me, signOut } = useSession();
  const [now, setNow] = useState(Date.now());
  const [signedInWith, setLimits] = useState(me.session);
  // the console sends the current limits with every answer: a change by an admin shows here at once
  const limits = sessionLimits() ?? signedInWith;
  const [dismissedEnd, setDismissedEnd] = useState(false);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const idleLeft = limits ? limits.idleSeconds * 1000 - (now - lastServerContact()) : Infinity;
  const endLeft = limits ? Date.parse(limits.expiresAt) - now : Infinity;

  // at the idle limit, ask: an ended session answers 401, which signs the person out with a reason
  useEffect(() => {
    if (idleLeft <= 0 && !checking) {
      setChecking(true);
      session.me().then((m) => setLimits(m.session)).catch(() => undefined).finally(() => setChecking(false));
    }
  }, [idleLeft, checking]);

  const stay = () => {
    session.me().then((m) => setLimits(m.session)).catch(() => undefined);
  };

  if (!limits) {
    return null;
  }
  // the hard end comes first: staying cannot help
  if (endLeft <= END_WARNING_MS && endLeft > 0 && endLeft <= idleLeft && !dismissedEnd) {
    return (
      <Modal isOpen variant="small" onClose={() => setDismissedEnd(true)} aria-labelledby="session-end-title">
        <ModalHeader title="Your session is ending" labelId="session-end-title" titleIconVariant="warning" />
        <ModalBody>
          Sessions on this directory have a fixed longest length. This one ends in <strong>{clock(endLeft)}</strong>, at
          {' '}{new Date(limits.expiresAt).toLocaleTimeString()}, and you will need to sign in again. Save anything you are working on.
        </ModalBody>
        <ModalFooter>
          <Button onClick={() => setDismissedEnd(true)}>OK</Button>
          <Button variant="link" onClick={signOut}>Sign out now</Button>
        </ModalFooter>
      </Modal>
    );
  }
  if (idleLeft <= IDLE_WARNING_MS && idleLeft > 0) {
    return (
      <Modal isOpen variant="small" onClose={stay} aria-labelledby="session-idle-title">
        <ModalHeader title="Are you still there?" labelId="session-idle-title" titleIconVariant="warning" />
        <ModalBody>
          You will be signed out in <strong>{clock(idleLeft)}</strong> because nothing has happened for a while.
        </ModalBody>
        <ModalFooter>
          <Button onClick={stay}>Stay signed in</Button>
          <Button variant="link" onClick={signOut}>Sign out</Button>
        </ModalFooter>
      </Modal>
    );
  }
  return null;
}
