import { Bullseye, Content, EmptyState, EmptyStateBody } from '@patternfly/react-core';
import { WrenchIcon } from '@patternfly/react-icons';

/** Bootstrap mode: until setup is finished the console answers only health and the setup API. */
export function SetupRequired() {
  return (
    <Bullseye>
      <EmptyState titleText="Directory Console needs setting up" headingLevel="h1" icon={WrenchIcon}>
        <EmptyStateBody>
          <Content component="p">
            Finish setup with the one-time token printed in the console's log, after checking that the certificate
            fingerprint printed with it is the one your browser shows.
          </Content>
          <Content component="p">
            <code className="dc-mono">docker compose logs console</code>
          </Content>
        </EmptyStateBody>
      </EmptyState>
    </Bullseye>
  );
}
