package com.pointblue.console.server.idm;

import com.pointblue.dirxml.dev.deploy.IdmOps;
import java.io.ByteArrayOutputStream;
import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.LdapContext;

/**
 * The engine's job catalogue: DiscoverJobs (IDM extended operation 51), which reads the job definitions
 * packaged in the job jars on that server, and NotifyJobUpdate. Encoded and decoded with DirXMLDev's
 * {@link IdmOps} (no engine jars) and sent on the person's own JNDI connection to that server. DiscoverJobs
 * answers with a chunked result (a handle and a size), read as DirXMLDev's Vault reads one: 64 512 bytes a
 * chunk, then closed.
 */
public final class JobCatalog {

    private static final int CHUNK = 64512;
    private static final String DISCOVER_JOBS = IdmOps.OID_BASE + "51";

    private JobCatalog() {
    }

    /** The engine's answer, as it sends it, for the driver or driver set {@code dn}. */
    public static byte[] discover(LdapContext ctx, String dn) throws NamingException {
        // the arguments as the engine reads them: the object, 0 (its containment decides), the default timeout
        IdmOps.Reply first = call(ctx, DISCOVER_JOBS, dn, 0, 0);
        if (first.size() < 2) {
            return new byte[0];
        }
        int handle = first.integer(0);
        int size = first.integer(1);
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(size, 0));
        try {
            for (int left = size; left > 0;) {
                byte[] data = call(ctx, IdmOps.Op.GET_CHUNKED_RESULT.oid(), handle, Math.min(left, CHUNK), 0).bytes(0);
                if (data == null || data.length == 0) {
                    break;
                }
                out.write(data, 0, data.length);
                left -= data.length;
            }
        } finally {
            if (size > 0) {
                call(ctx, IdmOps.Op.CLOSE_CHUNKED_RESULT.oid(), handle);
            }
        }
        return out.toByteArray();
    }

    /**
     * Tell the engine a job was added or changed (NotifyJobUpdate), so that it schedules it now; false when
     * that failed, and the engine then finds the job when it next reads its jobs.
     */
    public static boolean notify(LdapContext ctx, String jobDn) {
        try {
            call(ctx, IdmOps.Op.NOTIFY_JOB_UPDATE.oid(), jobDn);
            return true;
        } catch (NamingException | RuntimeException x) {
            return false;
        }
    }

    private static IdmOps.Reply call(LdapContext ctx, String oid, Object... args) throws NamingException {
        ExtendedResponse r = ctx.extendedOperation(new Request(oid, IdmOps.encode(args)));
        byte[] value = r.getEncodedValue();
        return IdmOps.decode(value == null ? new byte[0] : value);
    }

    /** An IDM extended request: its OID and the BER value IdmOps encoded; the reply is read by {@link IdmOps#decode}. */
    private record Request(String oid, byte[] value) implements ExtendedRequest {
        @Override
        public String getID() {
            return oid;
        }

        @Override
        public byte[] getEncodedValue() {
            return value;
        }

        @Override
        public ExtendedResponse createExtendedResponse(String id, byte[] berValue, int offset, int length) {
            byte[] copy = berValue == null ? null : java.util.Arrays.copyOfRange(berValue, offset, offset + length);
            return new ExtendedResponse() {
                @Override
                public String getID() {
                    return id;
                }

                @Override
                public byte[] getEncodedValue() {
                    return copy;
                }
            };
        }
    }
}
