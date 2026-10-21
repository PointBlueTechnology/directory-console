/** "2024-01-20 20:57" from a role assignment's 20240120205711Z. */
function when(t: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(t);
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}` : t;
}

const unescape = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

/**
 * A role assignment (the <assignment> in an nrfAssignedRoles value) in words: since and until when, who asked, why.
 * Null when the text is not one. The element holds only simple child elements, so they are read directly.
 */
export function assignment(text: string): string | null {
  const t = text.trim();
  if (!/^<assignment[\s>]/.test(t)) {
    return null;
  }
  const get = (tag: string) => {
    const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(t);
    return m && m[1].trim() ? unescape(m[1].trim()) : null;
  };
  const start = get('start_tm');
  const end = get('end_tm');
  const by = get('req');
  const parts = [
    start && `since ${when(start)}`,
    end && `until ${when(end)}`,
    by && `requested by ${by.split(',')[0].replace(/^[a-z]+=/i, '')}`,
    get('req_desc'),
  ].filter(Boolean);
  return parts.length ? `(${parts.join('; ')})` : null;
}
