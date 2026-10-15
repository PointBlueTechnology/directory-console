import { useEffect, useState } from 'react';
import { Alert, AlertActionCloseButton, AlertActionLink, PageSection } from '@patternfly/react-core';
import { UPGRADING_URL, type UpdateState } from '../api';
import { navigate } from '../router';

/** A dismissal lasts for this browser session, and only for the version (or failure) it was about. */
const KEY = 'directory-console.update-dismissed';

function dismissed(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

/**
 * For admins: a newer release, or that the console could not check for one. A failed check is shown
 * quietly, with its reason and where to turn the check off; nothing else is affected.
 */
export function UpdateBanner({ update }: { update: UpdateState | null }) {
  const [hidden, setHidden] = useState(dismissed);
  useEffect(() => setHidden(dismissed()), [update]);
  if (!update || !update.enabled) {
    return null;
  }
  const key = update.newer ? `newer:${update.latest}` : update.error ? `error:${update.error}` : null;
  if (!key || hidden === key) {
    return null;
  }
  const dismiss = () => {
    try {
      sessionStorage.setItem(KEY, key);
    } catch {
      // storage blocked: dismissed until the page reloads
    }
    setHidden(key);
  };
  return (
    <PageSection padding={{ default: 'noPadding' }}>
      {update.newer ? (
        <Alert variant="info" isInline component="h2" title={`Directory Console ${update.latest} is available (this is ${update.current})`}
          actionClose={<AlertActionCloseButton onClose={dismiss} />}
          actionLinks={<>
            {update.url && <AlertActionLink component="a" href={update.url} target="_blank" rel="noreferrer">Release notes</AlertActionLink>}
            <AlertActionLink component="a" href={UPGRADING_URL} target="_blank" rel="noreferrer">How to upgrade</AlertActionLink>
          </>} />
      ) : (
        <Alert variant="warning" isInline isPlain component="h2" title="The console cannot check for new versions"
          actionClose={<AlertActionCloseButton onClose={dismiss} />}
          actionLinks={<AlertActionLink onClick={() => navigate('/settings?tab=updates')}>Update settings</AlertActionLink>}>
          {update.error}. Everything else works as usual. If this console has no internet access, turn the check off.
        </Alert>
      )}
    </PageSection>
  );
}
