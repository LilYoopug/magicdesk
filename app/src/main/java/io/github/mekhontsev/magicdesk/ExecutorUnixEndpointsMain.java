package io.github.mekhontsev.magicdesk;

import android.app.BroadcastOptions;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import io.github.mekhontsev.magicdesk.hosted.HostedProcessContext;

/** Endpoint admission for a captured non-shell executor; never copies protocol bytes. */
public final class ExecutorUnixEndpointsMain {
    static final String ACTION = "io.github.mekhontsev.magicdesk.UNIX_ENDPOINTS_READY";
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Expected host, executor and nonce");
        Looper.prepareMainLooper();
        var context = HostedProcessContext.create(args[1]);
        int ownerUid = context.getPackageManager().getPackageUid(args[0], 0);
        Handler handler = new Handler(Looper.getMainLooper());
        class Broker extends IExecutorUnixEndpoints.Stub {
            private IBinder owner;
            private boolean stopping;
            private final java.util.List<ShellUnixEndpoint> endpoints = new java.util.ArrayList<>();
            private final Runnable expire = this::shutdown;
            private void check() {
                if (Binder.getCallingUid() != ownerUid) throw new SecurityException("Not the endpoint owner");
            }
            @Override public synchronized void retain(IBinder next) throws android.os.RemoteException {
                check();
                if (owner != null || stopping) throw new IllegalStateException("Broker is unavailable");
                next.linkToDeath(() -> handler.post(this::shutdown), 0);
                owner = next;
                handler.removeCallbacks(expire);
            }
            @Override public synchronized IShellUnixEndpoint open(String name, int uid, int timeout, IUnixConnectionReceiver receiver) {
                check();
                if (owner == null || stopping) throw new IllegalStateException("Not retained");
                try {
                    var endpoint = new ShellUnixEndpoint(name, uid, timeout, receiver);
                    endpoints.add(endpoint);
                    return endpoint;
                }
                catch (java.io.IOException error) { throw new IllegalStateException(error); }
            }
            @Override public void close() { check(); handler.post(this::shutdown); }
            private synchronized void shutdown() {
                stopping = true;
                for (ShellUnixEndpoint endpoint : endpoints) endpoint.release();
                endpoints.clear();
                System.exit(0);
            }
        }
        var endpoint = new Broker();
        // EVENT_WAIT: authenticated owner retention; expiry releases this unclaimed broker.
        handler.postDelayed(endpoint.expire, 30_000);
        Bundle extras = new Bundle();
        extras.putBinder("endpoints", endpoint);
        extras.putString("nonce", args[2]);
        context.sendBroadcast(new Intent(ACTION).setPackage(args[0]).putExtras(extras), null,
                BroadcastOptions.makeBasic().setShareIdentityEnabled(true).toBundle());
        Looper.loop();
    }
}
