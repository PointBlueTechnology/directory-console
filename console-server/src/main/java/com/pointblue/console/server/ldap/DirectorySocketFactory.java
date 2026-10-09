package com.pointblue.console.server.ldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * JNDI takes an LDAPS socket factory by class name and calls its static {@code getDefault()}; this
 * hands out the factory of the connection being opened on this thread, so each directory connection
 * gets its own trust manager. {@link Ldap} sets it around the context creation and clears it after.
 * JNDI's connection pool is off for these connections, so a factory is never reused for another.
 */
public final class DirectorySocketFactory extends SocketFactory {

    private static final ThreadLocal<SSLSocketFactory> CURRENT = new ThreadLocal<>();

    private final SSLSocketFactory delegate;

    private DirectorySocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    static void set(SSLSocketFactory f) {
        CURRENT.set(f);
    }

    static void clear() {
        CURRENT.remove();
    }

    /** Called by JNDI. */
    public static SocketFactory getDefault() {
        SSLSocketFactory f = CURRENT.get();
        if (f == null) {
            throw new IllegalStateException("a directory connection is opened only through Ldap.connect");
        }
        return new DirectorySocketFactory(f);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return delegate.createSocket(address, port, localAddress, localPort);
    }
}
