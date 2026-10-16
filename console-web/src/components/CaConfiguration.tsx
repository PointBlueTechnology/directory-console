import { useState } from 'react';
import { Alert, Switch } from '@patternfly/react-core';
import { type CaConfiguration, type Certificate } from '../api';
import { ProblemAlert } from './Problem';

type Key = keyof CaConfiguration;

/** Identity Console's names for them, so the two read alike. */
const OPTIONS: { key: Key; label: string; help?: string }[] = [
  { key: 'requireReadRights', label: 'Require read rights to operate the CA' },
  { key: 'requireWriteRights', label: 'Require write rights to operate the CA',
    help: 'Servers are not given write rights to the CA\'s private key by default; grant them if this is on.' },
  { key: 'serverSelfProvisioning', label: 'Enable server self-provisioning',
    help: 'eDirectory\'s own renewal: when ndsd starts or DSRepair runs, the PKI Health Check creates a missing SSL CertificateDNS and renews an expired or mismatched one in place, keeping its name.' },
  { key: 'forceHealthCheck', label: 'Health Check - Force default certificate creation/update on CA change',
    help: 'Only with server self-provisioning.' },
  { key: 'userSelfProvisioning', label: 'Enable user self-provisioning',
    help: 'Users may create certificates for themselves without rights to the CA.' },
  { key: 'userEmergencyCrl', label: 'Allow any authenticated user to issue an emergency CRL' },
  { key: 'suiteB', label: 'Enable Suite B mode',
    help: 'Only for a CA with nothing but an ECDSA certificate on P-256 or P-384. New servers added to the directory must then use Enhanced Background Authentication.' },
];

/**
 * The Organizational CA's settings, each switched on its own. Server self-provisioning is the switch
 * that lets eDirectory renew its default certificates itself.
 */
export function CaConfigurationPanel({ value, certificates, editor, save }: {
  value: CaConfiguration; certificates: Certificate[]; editor: boolean; save: (change: Partial<CaConfiguration>) => Promise<CaConfiguration>;
}) {
  const [config, setConfig] = useState(value);
  const [busy, setBusy] = useState<Key | null>(null);
  const [error, setError] = useState<unknown>(null);
  // Suite B needs a CA with only an ECDSA P-256 or P-384 certificate
  const suiteBPossible = certificates.length > 0 && certificates.every((c) => c.key === 'EC 256' || c.key === 'EC 384');
  const change = (key: Key, on: boolean) => {
    setBusy(key);
    setError(null);
    save({ [key]: on }).then(setConfig, setError).finally(() => setBusy(null));
  };
  return (
    <div className="dc-tab-body">
      {OPTIONS.map((o) => {
        const blocked = o.key === 'forceHealthCheck' && !config.serverSelfProvisioning
          || o.key === 'suiteB' && !config.suiteB && !suiteBPossible;
        return (
          <div key={o.key} className="dc-tab-body">
            <Switch id={`ca-${o.key}`} label={o.label} isChecked={config[o.key]} isDisabled={!editor || busy !== null || blocked}
              onChange={(_e, on) => change(o.key, on)} />
            {o.help && <div className="dc-subtle" style={{ marginLeft: '3.5rem' }}>{o.help}</div>}
          </div>
        );
      })}
      {config.serverSelfProvisioning && (
        <Alert variant="info" isInline isPlain title="Takes effect at the next PKI Health Check: when ndsd starts on a server, or DSRepair runs there." />
      )}
      <ProblemAlert error={error} />
    </div>
  );
}
