import { Label } from '@patternfly/react-core';
import { Hint } from '../help/Help';
import { GLOSSARY } from '../help/glossary';

/** Replica types as people read them. */
export const REPLICA_TYPE_LABEL: Record<string, string> = {
  master: 'Master', 'read-write': 'Read/write', 'read-only': 'Read-only', 'subordinate-reference': 'Subordinate reference',
  'sparse-write': 'Sparse write', 'sparse-read': 'Sparse read',
};

/** What a replica type means, from the glossary. */
export function replicaTypeHelp(type: string): string {
  const key = `replica.${type}`;
  return key in GLOSSARY ? GLOSSARY[key as keyof typeof GLOSSARY] : type;
}

/** A replica type as a coloured label, its meaning on hover: the master purple, subordinate references grey. */
export function ReplicaTypeLabel({ type }: { type: string }) {
  return (
    <Hint text={replicaTypeHelp(type)}>
      <Label isCompact color={type === 'master' ? 'purple' : type === 'subordinate-reference' ? 'grey' : 'blue'}>{REPLICA_TYPE_LABEL[type] ?? type}</Label>
    </Hint>
  );
}
