import { Card, CardBody, PageSection } from '@patternfly/react-core';
import { ObjectPanel } from '../components/ObjectPanel';
import { navigate } from '../router';

/** An object on its own page: where a reference in another object's attributes leads. */
export function ObjectPage({ guid }: { guid: string }) {
  return (
    <PageSection isFilled>
      <Card>
        <CardBody>
          <ObjectPanel key={guid} guid={guid} headingLevel="h1" onChanged={(o) => { if (!o) { navigate('/browse'); } }} />
        </CardBody>
      </Card>
    </PageSection>
  );
}
