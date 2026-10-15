package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class UpdatesTest {

    @Test
    public void versionsCompareByNumberNotText() {
        assertEquals(true, Updates.newer("0.3.10", "0.3.9"));
        assertEquals(true, Updates.newer("v1.0.0", "0.9.9"));
        assertEquals(false, Updates.newer("0.3.2", "0.3.2"));
        assertEquals(false, Updates.newer("0.3.1", "0.3.2"));
        assertNull("a development build is not compared", Updates.newer("0.3.2", "development"));
    }
}
