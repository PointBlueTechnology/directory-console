package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.Test;

/** The shapes of message a lab tree's 351 templates take, each kept as it is written when it is saved unchanged. */
public class TemplatesTest {

    private static final String DESCS = "\n\t<form:token-descriptions>\n\t\t<form:token-description description=\"Ticket\" item-name=\"ticketNumber\"/>\n\t</form:token-descriptions>";

    private static void unchanged(String xml) {
        Templates.Parts p = Templates.parts(xml);
        assertEquals(xml, Templates.rebuild(xml, p.tokens(), p.text() == null ? p.body() : null, p.text()));
    }

    @Test
    public void plainTextStraightInHtmlIsText() {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><html xmlns:form=\"" + Templates.FORM_NS + "\">" + DESCS
            + "Hi,\n\nTicket number: $ticketNumber$ &amp; more\n</html>";
        Templates.Parts p = Templates.parts(xml);
        assertEquals("Hi,\n\nTicket number: $ticketNumber$ & more\n", p.text());
        unchanged(xml);
        String now = Templates.rebuild(xml, p.tokens(), null, "Hello <you> & $ticketNumber$");
        assertTrue(now, now.endsWith("</form:token-descriptions>Hello &lt;you&gt; &amp; $ticketNumber$</html>"));
    }

    @Test
    public void aFormTextRootAndAnotherFormNamespaceAreKept() {
        unchanged("<?xml version=\"1.0\" encoding=\"UTF-8\"?><form:text xmlns:form=\"" + Templates.FORM_NS + "\">" + DESCS + "Your ticket $ticketNumber$.\n\n</form:text>");
        // one lab template binds form: to the task form's namespace and has no declaration
        String mtask = "<html xmlns:form=\"http://www.novell.com/dirxml/mtask/form\"> <form:if-item-exists name=\"result-message\"> <p> Job message was: $result-message$ </p> </form:if-item-exists></html>";
        Templates.Parts p = Templates.parts(mtask);
        assertNull("elements, so XHTML", p.text());
        assertTrue(p.body(), p.body().contains("<form:if-item-exists name=\"result-message\">"));
        unchanged(mtask);
    }

    @Test
    public void aNestedHtmlAndTheTokensAreChangedInPlace() {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><html xmlns:form=\"" + Templates.FORM_NS + "\">" + DESCS
            + "\n\t<html>\n\t\t<body>\n\t\t\t<div>$ticketNumber$<br/></div>\n\t\t</body>\n\t</html>\n</html>";
        unchanged(xml);
        Templates.Parts p = Templates.parts(xml);
        String now = Templates.rebuild(xml, List.of(Map.of("name", "ticketNumber", "description", "Ticket"), Map.of("name", "who", "description", "Who")), p.body(), null);
        assertTrue(now, now.contains("item-name=\"who\"") && now.contains("<div>$ticketNumber$<br/></div>"));
        assertThrows(IllegalArgumentException.class, () -> Templates.rebuild(xml, p.tokens(), "<p>a<br>b</p>", null));
    }
}
