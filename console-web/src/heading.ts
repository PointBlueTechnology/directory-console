import { createContext, useContext } from 'react';

export type Level = 'h2' | 'h3' | 'h4';

/**
 * The heading level for sections and alert titles where a component is shown: h2 under a page's h1,
 * h3 inside the object drawer (whose title is h2). Keeps heading order valid for screen readers.
 */
export const HeadingLevel = createContext<Level>('h2');

export function useHeading(): Level {
  return useContext(HeadingLevel);
}
