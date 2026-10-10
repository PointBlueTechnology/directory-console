import { Alert, AlertActionLink } from '@patternfly/react-core';
import { ApiError } from '../api';

/** A refused request, with eDirectory's own error number when it gave one. */
export function ProblemAlert({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: string }) {
  if (!error) {
    return null;
  }
  const e = error instanceof ApiError ? error : null;
  const nds = e?.problem.ndsError as number | undefined;
  return (
    <Alert variant={e?.status === 412 ? 'warning' : 'danger'} isInline
      title={title ?? (e?.status === 412 ? 'This object changed since you opened it' : e?.status === 403 ? 'Not allowed' : 'The request failed')}
      actionLinks={onRetry ? <AlertActionLink onClick={onRetry}>{e?.status === 412 ? 'Reload' : 'Try again'}</AlertActionLink> : undefined}>
      {e ? e.message : String(error)}
      {nds !== undefined && <> (eDirectory error {nds})</>}
    </Alert>
  );
}
