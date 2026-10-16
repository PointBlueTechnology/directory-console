import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Content, DrawerActions, DrawerCloseButton, DrawerHead, DrawerPanelBody, DrawerPanelContent, FormGroupLabelHelp, Popover,
  Title, Tooltip,
} from '@patternfly/react-core';
import { TOPICS, topicFor } from './topics';

interface HelpState {
  /** The topic the current page asks for; a page with tabs names its tab's. */
  topic: string;
  setTopic: (id: string) => void;
  /** Back to the page's own topic (a panel that named one has closed). */
  reset: () => void;
  open: boolean;
  setOpen: (open: boolean) => void;
}

export const HelpContext = createContext<HelpState>({ topic: 'console', setTopic: () => {}, reset: () => {}, open: false, setOpen: () => {} });

/**
 * A page names its own help topic, such as the tab it shows ("settings.directory"). The shell starts
 * from the address; this refines it while the page is shown.
 */
export function useHelpTopic(id: string | null | undefined): void {
  const { setTopic, reset } = useContext(HelpContext);
  useEffect(() => {
    if (!id) {
      return undefined;
    }
    setTopic(id);
    return reset;
  }, [id, setTopic, reset]);
}

/** The help panel's content, for the current topic. */
export function HelpPanel({ onClose }: { onClose: () => void }) {
  const { topic: wanted, setTopic } = useContext(HelpContext);
  const { topic } = topicFor(wanted);
  return (
    <DrawerPanelContent widths={{ default: 'width_33' }} minSize="320px" isResizable aria-label="Help">
      <DrawerHead>
        <Title headingLevel="h2" size="xl">{topic.title}</Title>
        <DrawerActions><DrawerCloseButton onClick={onClose} aria-label="Close help" /></DrawerActions>
      </DrawerHead>
      <DrawerPanelBody>
        <Content component="p">{topic.summary}</Content>
        {topic.sections.map((s) => (
          s.caution ? (
            <Alert key={s.title} variant="warning" isInline isPlain title={s.title} className="dc-tab-body">
              {s.paragraphs?.map((p) => <p key={p}>{p}</p>)}
              {s.list && <ul>{s.list.map((x) => <li key={x}>{x}</li>)}</ul>}
            </Alert>
          ) : (
            <section key={s.title} className="dc-help-section">
              <Title headingLevel="h3" size="md">{s.title}</Title>
              {s.paragraphs?.map((p) => <Content component="p" key={p}>{p}</Content>)}
              {s.list && <Content component="ul">{s.list.map((x) => <Content component="li" key={x}>{x}</Content>)}</Content>}
            </section>
          )
        ))}
        {topic.related && topic.related.length > 0 && (
          <section className="dc-help-section">
            <Title headingLevel="h3" size="md">See also</Title>
            <Content component="ul">
              {topic.related.filter((r) => TOPICS[r]).map((r) => (
                <Content component="li" key={r}><Button variant="link" isInline onClick={() => setTopic(r)}>{TOPICS[r].title}</Button></Content>
              ))}
            </Content>
          </section>
        )}
      </DrawerPanelBody>
    </DrawerPanelContent>
  );
}

/**
 * A short hover hint on an element that does not explain itself (an icon button, a term of art). With no
 * text (a reason that applies only sometimes) the element is shown as it is.
 */
export function Hint({ text, children }: { text: ReactNode; children: React.ReactElement }) {
  return text ? <Tooltip content={text}>{children}</Tooltip> : children;
}

/** The ? beside a form field's label, opening a short explanation. Pass as a FormGroup's labelHelp. */
export function FieldHelp({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Popover headerContent={label} bodyContent={children}>
      <FormGroupLabelHelp aria-label={`More about ${label}`} />
    </Popover>
  );
}

/** Holds the help panel's state for the shell: open or closed, and the page's topic. */
export function useHelpState(pathTopic: string): HelpState {
  const [topic, setTopic] = useState(pathTopic);
  const [open, setOpen] = useState(false);
  // a new page starts from its own address; it may then name a tab's topic
  useEffect(() => setTopic(pathTopic), [pathTopic]);
  const reset = useCallback(() => setTopic(pathTopic), [pathTopic]);
  return useMemo(() => ({ topic, setTopic, reset, open, setOpen }), [topic, reset, open]);
}
