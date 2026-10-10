import { Button, EmptyState, EmptyStateActions, EmptyStateBody, EmptyStateFooter, PageSection } from '@patternfly/react-core';
import { SearchIcon } from '@patternfly/react-icons';
import { navigate } from '../router';

export function NotFound() {
  return (
    <PageSection>
      <EmptyState titleText="Page not found" headingLevel="h1" icon={SearchIcon}>
        <EmptyStateBody>There is no page at this address.</EmptyStateBody>
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="primary" onClick={() => navigate('/browse')}>Browse the directory</Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      </EmptyState>
    </PageSection>
  );
}
