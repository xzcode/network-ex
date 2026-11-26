package com.xzcode.networkex;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import android.system.OsConstants;
import org.json.*;
import java.net.InetAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import mobile.Mobile;
import mobile.Platform;
import mobile.Session;

/** One app-private VPN session. No root or global default route changes. */
public final class NetworkExVpnService extends VpnService {
    static final String CONNECT = "com.xzcode.networkex.CONNECT";
    static final String DIRECT = "direct";
    static final String DISCONNECT = "com.xzcode.networkex.DISCONNECT";
    private static final String CHANNEL = "network_ex_vpn";
    private static final int NOTIFICATION = 801;
    private static volatile Session session;
    private static volatile String serviceError = "";
    private static volatile boolean desired;
    private static final Object SERVICE_LOCK = new Object();
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private Network lastNetwork;
    private String lastLinkSignature="";
    private boolean allowDirect;
    private java.util.concurrent.ScheduledFuture<?> pendingRefresh;
    private volatile Session owned;
    private volatile boolean destroyed;
    private final Handler main = new Handler(Looper.getMainLooper());

    static String status() {
        Session s = session;
        if (s != null) {
            try { JSONObject v=new JSONObject(s.status());if(!serviceError.isEmpty())v.put("error",serviceError);return v.toString(); } catch (Exception ignored) { }
        }
        JSONObject v = new JSONObject();
        try { v.put("running", false); v.put("error", serviceError); } catch (JSONException ignored) {}
        return v.toString();
    }
    static boolean active() { return desired || (session != null && !session.waitStopped(0)); }

    @Override public void onCreate() {
        super.onCreate();
        connectivity = getSystemService(ConnectivityManager.class);
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (DISCONNECT.equals(action)) { requestStop(); return START_NOT_STICKY; }
        if (!CONNECT.equals(action) || VpnService.prepare(this) != null) {
            if (!desired) stopSelf();
            return START_NOT_STICKY;
        }
        try {
            Notification notification = notification();
            if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            else startForeground(NOTIFICATION, notification);
        } catch (RuntimeException e) {
            serviceError = "Cannot start VPN foreground service: " + e.getClass().getSimpleName();
            stopSelf(); return START_NOT_STICKY;
        }
        synchronized(SERVICE_LOCK){if (desired) return START_NOT_STICKY; desired = true;}
        allowDirect=intent.getBooleanExtra(DIRECT,false);
        serviceError = "";
        worker.execute(() -> {
            try {
                Session old = session;
                if (old != null && !old.waitStopped(0)) { old.stop(); if (!old.waitStopped(15000)) throw new IllegalStateException(getString(R.string.stopping)); }
                if (!desired || destroyed) return;
                lastNetwork = connectivity.getActiveNetwork();
                lastLinkSignature = linkSignature(lastNetwork);
                Session next = Mobile.newSession(new AndroidPlatform());
                owned = next;
                session = next;
                next.startWithDirect(ProfileStore.root(this),allowDirect);
                if(!desired||destroyed)next.stop();
            } catch (Exception e) { fail(e); }
        });
        registerNetworkCallback();
        worker.scheduleWithFixedDelay(() -> {
            if (!desired || destroyed) return;
            Session s = owned;
            if (s != null && s.waitStopped(0)) {
                // Terminal errors/revocations must not be automatically restarted.
                try { serviceError = new JSONObject(s.status()).optString("error"); } catch (JSONException ignored) {}
                requestStop();
            }
        }, 3, 3, TimeUnit.SECONDS);
        return START_NOT_STICKY;
    }

    private Notification notification() {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), flags);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, NetworkExVpnService.class).setAction(DISCONNECT), flags);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_network)
            .setContentTitle(getString(R.string.notification_title)).setContentText(getString(R.string.notification_text))
            .setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null, getString(R.string.disconnect), stop).build()).build();
    }

    private void registerNetworkCallback() {
        if (networkCallback != null) return;
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network n) { changed(); }
            @Override public void onLost(Network n) { changed(); }
            @Override public void onLinkPropertiesChanged(Network n, LinkProperties lp) { changed(); }
            private void changed() {
                if (!desired || destroyed) return;
                try { synchronized(NetworkExVpnService.this){if(pendingRefresh!=null)pendingRefresh.cancel(false);pendingRefresh=worker.schedule(NetworkExVpnService.this::refreshUnderlay,1500,TimeUnit.MILLISECONDS);} }
                catch (java.util.concurrent.RejectedExecutionException ignored) {}
            }
        };
        try {
            connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback);
        } catch (RuntimeException e) { networkCallback = null; }
    }

    private void refreshUnderlay() {
        if (!desired || destroyed) return;
        Network current = connectivity.getActiveNetwork();
        String signature=linkSignature(current);
        if (java.util.Objects.equals(current, lastNetwork)&&signature.equals(lastLinkSignature)) return;
        lastNetwork = current;lastLinkSignature=signature;
        Session s = owned;
        if (s == null || s.waitStopped(0)) return;
        // Re-open protected sockets and refresh authorization on an underlay change.
        s.stop();
        if (!s.waitStopped(15000)) { fail(new IllegalStateException(getString(R.string.stopping))); return; }
        if (desired && !destroyed) {
            try { s.startWithDirect(ProfileStore.root(this),allowDirect); } catch (Exception e) { fail(e); }
        }
    }
    private String linkSignature(Network n) {
        if(n==null)return "";
        LinkProperties lp=connectivity.getLinkProperties(n);
        if(lp==null)return "";
        return String.valueOf(lp.getInterfaceName())+"|"+lp.getLinkAddresses()+"|"+lp.getRoutes()+"|"+lp.getDnsServers();
    }
    private void fail(Exception e) {
        serviceError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        requestStop();
    }
    private void requestStop() {
        synchronized(SERVICE_LOCK){desired = false;}
        Session s = owned;
        if (s != null) s.stop();
        main.post(() -> {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        });
    }
    @Override public void onRevoke() { requestStop(); super.onRevoke(); }
    @Override public void onDestroy() {
        destroyed = true; desired = false;
        synchronized(this){if(pendingRefresh!=null)pendingRefresh.cancel(false);}
        if (networkCallback != null) { try { connectivity.unregisterNetworkCallback(networkCallback); } catch (RuntimeException ignored) {} }
        Session s = owned; if (s != null) s.stop();
        worker.shutdownNow();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    private static InetAddress privateIPv4(String raw) throws Exception {
        if (!raw.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) throw new IllegalArgumentException("IPv4 required");
        String[] parts = raw.split("\\."); byte[] b = new byte[4];
        for (int i=0;i<4;i++) { int n=Integer.parseInt(parts[i]); if(n>255||!parts[i].equals(Integer.toString(n)))throw new IllegalArgumentException("Invalid IPv4"); b[i]=(byte)n; }
        int a=b[0]&255, c=b[1]&255;
        if (!(a==10||(a==172&&c>=16&&c<=31)||(a==192&&c==168))) throw new IllegalArgumentException("Private overlay IPv4 required");
        return InetAddress.getByAddress(b);
    }

    private void rejectOverlap(InetAddress address) throws Exception {
        for (Network n : connectivity.getAllNetworks()) {
            NetworkCapabilities nc=connectivity.getNetworkCapabilities(n);
            if (nc==null||!nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue;
            LinkProperties lp=connectivity.getLinkProperties(n); if(lp==null) continue;
            for (RouteInfo route : lp.getRoutes()) {
                IpPrefix dest=route.getDestination();
                if (dest.getPrefixLength()!=0 && dest.contains(address)) throw new IllegalArgumentException("Overlay overlaps existing network route: "+dest);
            }
        }
    }

    private final class AndroidPlatform implements Platform {
        @Override public int openTunnel(String json) {
            if (!desired || destroyed || VpnService.prepare(NetworkExVpnService.this)!=null) return -1;
            ParcelFileDescriptor pfd = null;
            try {
                JSONObject spec = new JSONObject(json);
                InetAddress local=privateIPv4(spec.getString("address")); rejectOverlap(local);
                if(spec.getInt("mtu")!=1280) throw new IllegalArgumentException("Invalid MTU");
                JSONArray routes=spec.getJSONArray("routes");if(routes.length()>64)throw new IllegalArgumentException("Too many routes");
                Builder b = new Builder().setSession("Network EX").setMtu(1280).setBlocking(false)
                    .addAddress(local,32).allowFamily(OsConstants.AF_INET6)
                    .addDisallowedApplication(getPackageName());
                // Protect app/control traffic as a second boundary in addition to
                // VpnService.protect on explicitly created underlay sockets.
                for(int i=0;i<routes.length();i++){
                    String r=routes.getString(i); if(!r.endsWith("/32"))throw new IllegalArgumentException("Only peer /32 routes allowed");
                    InetAddress ip=privateIPv4(r.substring(0,r.length()-3));rejectOverlap(ip);b.addRoute(ip,32);
                }
                Network underlying=connectivity.getActiveNetwork();
                if(underlying!=null)b.setUnderlyingNetworks(new Network[]{underlying});
                pfd=b.establish();
                if(pfd==null)return -1;
                if(!desired||destroyed){pfd.close();return -1;}
                // Go owns the detached descriptor; Java never closes it again.
                return pfd.detachFd();
            } catch(Exception e) {
                serviceError = "VPN setup: "+e.getMessage();
                if(pfd!=null)try{pfd.close();}catch(Exception ignored){}
                return -1;
            }
        }
        @Override public boolean protectSocket(int fd) {
            if(!desired||destroyed||fd<0)return false;
            try{return protect(fd);}catch(RuntimeException e){return false;}
        }
    }
}
