import { Alert, AlertActionLink } from '@patternfly/react-core';
import { ApiError } from '../api';
import { useHeading } from '../heading';

/** A refused request, with eDirectory's own error number when it gave one. */
export function ProblemAlert({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: string }) {
  const level = useHeading();
  if (!error) {
    return null;
  }
  const e = error instanceof ApiError ? error : null;
  const nds = e?.problem.ndsError as number | undefined;
  return (
    <Alert component={level} variant={e?.status === 412 ? 'warning' : 'danger'} isInline
      title={title ?? (e?.status === 412 ? 'This object changed since you opened it'
        : e?.code === 'would-lock-out' ? 'Not saved: this would lock everyone out of the object'
          : e?.status === 403 ? 'Not allowed' : 'The request failed')}
      actionLinks={onRetry ? <AlertActionLink onClick={onRetry}>{e?.status === 412 ? 'Reload' : 'Try again'}</AlertActionLink> : undefined}>
      {error instanceof Error ? error.message : String(error)}
      {nds !== undefined && <> (eDirectory error {nds})</>}
    </Alert>
  );
}
