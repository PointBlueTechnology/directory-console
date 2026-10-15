package com.pointblue.console.server.idm;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.LdapContext;

/**
 * The engine's job catalogue: DiscoverJobs (IDM extended operation 51), which reads the job definitions
 * packaged in the job jars on that server, and NotifyJobUpdate. DiscoverJobs answers with a chunked
 * result, read as DirXMLDev's Vault reads one (64 512 bytes a chunk, then closed).
 *
 * <p>The engine's request classes ({@code dirxml_misc.jar}) are on the class path only when the customer
 * mounts them, so they are reached by name; they implement JNDI's {@link ExtendedRequest}, so the person's
 * own connection to that server sends them.
 */
public final class JobCatalog {

    private static final String PKG = "com.novell.nds.dirxml.ldap.";
    private static final int CHUNK = 64512;

    private JobCatalog() {
    }

    /** The engine's answer, as it sends it, for the driver or driver set {@code dn}. */
    public static byte[] discover(LdapContext ctx, String dn) throws NamingException {
        try {
            for (String r : new String[] {"DiscoverJobsResponse", "GetChunkedResultResponse"}) {
                Class.forName(PKG + r).getMethod("register").invoke(null);
            }
            ExtendedResponse first = ctx.extendedOperation(request("DiscoverJobsRequest", new Class<?>[] {String.class, boolean.class, int.class}, dn, false, 0));
            int handle = (int) first.getClass().getMethod("getDataHandle").invoke(first);
            int size = (int) first.getClass().getMethod("getDataSize").invoke(first);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(size, 0));
            try {
                for (int left = size; left > 0;) {
                    ExtendedResponse chunk = ctx.extendedOperation(request("GetChunkedResultRequest", new Class<?>[] {int.class, int.class, int.class}, handle, Math.min(left, CHUNK), 0));
                    byte[] data = (byte[]) chunk.getClass().getMethod("getData").invoke(chunk);
                    if (data == null || data.length == 0) {
                        break;
                    }
                    out.write(data, 0, data.length);
                    left -= data.length;
                }
            } finally {
                if (size > 0) {
                    ctx.extendedOperation(request("CloseChunkedResultRequest", new Class<?>[] {int.class}, handle));
                }
            }
            return out.toByteArray();
        } catch (NamingException x) {
            throw x;
        } catch (java.lang.reflect.InvocationTargetException x) {
            if (x.getCause() instanceof NamingException n) {
                throw n;
            }
            throw new IllegalStateException("the engine's DiscoverJobs failed: " + x.getCause(), x.getCause());
        } catch (ReflectiveOperationException | LinkageError x) {
            throw new UnsupportedOperationException("job discovery needs the engine's jars: " + x);
        }
    }

    /**
     * Tell the engine a job was added or changed (NotifyJobUpdate), so that it schedules it now; false when
     * that failed, and the engine then finds the job when it next reads its jobs.
     */
    public static boolean notify(LdapContext ctx, String jobDn) {
        try {
            ctx.extendedOperation(request("NotifyJobUpdateRequest", new Class<?>[] {String.class}, jobDn));
            return true;
        } catch (NamingException | ReflectiveOperationException | LinkageError | RuntimeException x) {
            return false;
        }
    }

    private static ExtendedRequest request(String name, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        Constructor<?> c = Class.forName(PKG + name).getConstructor(types);
        return (ExtendedRequest) c.newInstance(args);
    }

}
