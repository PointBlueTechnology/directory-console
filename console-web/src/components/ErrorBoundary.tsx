import { Component, type ReactNode } from 'react';
import { Alert, AlertActionLink } from '@patternfly/react-core';

/** A rendering failure stays inside its part of the page, with a way to try again. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null; key?: string }> {
  state: { error: Error | null; key?: string } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  static getDerivedStateFromProps(props: { resetKey?: string }, state: { error: Error | null; key?: string }) {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null;
  }

  render() {
    if (this.state.error) {
      return (
        <Alert variant="danger" isInline title="This part of the page failed"
          actionLinks={<AlertActionLink onClick={() => this.setState({ error: null })}>Try again</AlertActionLink>}>
          {this.state.error.message}
        </Alert>
      );
    }
    return this.props.children;
  }
}
