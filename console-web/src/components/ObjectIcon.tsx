import type { ReactElement } from 'react';
import {
  BuildingIcon, CertificateIcon, CogIcon, CubeIcon, DesktopIcon, FileIcon, FlagIcon, FolderIcon, FolderOpenIcon, GlobeIcon, HddIcon, IdBadgeIcon,
  KeyIcon, MapMarkerAltIcon, PlugIcon, PrintIcon, ServerIcon, ShieldAltIcon, UserIcon, UsersIcon,
} from '@patternfly/react-icons';

/** Kinds of object, most specific first: the first whose classes an entry has picks its icon. */
const KINDS: { classes: string[]; icon: ReactElement; label: string }[] = [
  { classes: ['computer'], icon: <DesktopIcon />, label: 'computer' },
  { classes: ['device'], icon: <PlugIcon />, label: 'device' },
  { classes: ['inetorgperson', 'person', 'organizationalperson', 'user', 'posixaccount'], icon: <UserIcon />, label: 'person' },
  { classes: ['groupofnames', 'groupofuniquenames', 'posixgroup', 'group', 'dynamicgroup'], icon: <UsersIcon />, label: 'group' },
  { classes: ['organizationalrole'], icon: <IdBadgeIcon />, label: 'role' },
  { classes: ['ndspkicertificateauthority', 'certificationauthority', 'pkica'], icon: <ShieldAltIcon />, label: 'certificate authority' },
  { classes: ['ndspkikeymaterial', 'ndspkitrustedroot', 'ndspkitrustedrootobject'], icon: <CertificateIcon />, label: 'certificate' },
  { classes: ['nspmpasswordpolicy', 'saslogincontainer', 'sasloginmethodcontainer'], icon: <KeyIcon />, label: 'security' },
  { classes: ['dirxml-driverset', 'dirxml-driver', 'dirxml-job', 'dirxml-resource'], icon: <CogIcon />, label: 'Identity Manager' },
  { classes: ['ncpserver', 'server'], icon: <ServerIcon />, label: 'server' },
  { classes: ['volume', 'filesystem'], icon: <HddIcon />, label: 'volume' },
  { classes: ['printer', 'printqueue'], icon: <PrintIcon />, label: 'printer' },
  { classes: ['country', 'ndscountry'], icon: <FlagIcon />, label: 'country' },
  { classes: ['locality'], icon: <MapMarkerAltIcon />, label: 'locality' },
  { classes: ['organization'], icon: <BuildingIcon />, label: 'organization' },
  { classes: ['domain', 'dcobject', 'dnsdomain'], icon: <GlobeIcon />, label: 'domain' },
];

/**
 * The icon for an object, by what it is rather than whether it can be opened, as Arbor and ArborJ do: a
 * user that holds child objects is still drawn as a person. Organizational units and other containers get
 * a folder; anything else a plain object.
 */
export function objectIcon(objectClasses: string[] | undefined, container: boolean, open = false): ReactElement {
  const have = new Set((objectClasses ?? []).map((c) => c.toLowerCase()));
  for (const k of KINDS) {
    if (k.classes.some((c) => have.has(c))) {
      return k.icon;
    }
  }
  if (container || have.has('organizationalunit')) {
    return open ? <FolderOpenIcon /> : <FolderIcon />;
  }
  return have.size === 0 ? <FileIcon /> : <CubeIcon />;
}
