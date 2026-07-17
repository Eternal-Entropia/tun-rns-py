package com.reticulum.tun;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;

public class TunVpnService extends VpnService {

    private static final String TAG = "TunVpnService";
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "ReticulumTUN";

    private ParcelFileDescriptor vpnInterface;
    private Thread workerThread;
    private volatile boolean running = false;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        RnsBridge.setVpnService(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        String destHash = intent.getStringExtra("dest_hash");
        String serverHost = intent.getStringExtra("server_host");
        int serverPort = intent.getIntExtra("server_port", 4242);
        int tunMtu = intent.getIntExtra("tun_mtu", 1500);
        boolean compress = intent.getBooleanExtra("compress", false);
        String clientIp = intent.getStringExtra("client_ip");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = "10.244.0.2";
        }

        if (destHash == null || serverHost == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification());
        startPipeline(destHash, serverHost, serverPort, tunMtu, compress, clientIp);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        cleanup();
        RnsBridge.setVpnService(null);
        super.onDestroy();
    }

    private void startPipeline(String destHash, String serverHost,
                                int serverPort, int tunMtu, boolean compress, String clientIp) {
        running = true;
        workerThread = new Thread(() -> {
            try {
                RnsBridge.onStatus("Initializing RNS...");
                RnsBridge.initPython(getApplicationContext());

                RnsBridge.onStatus("Setting up RNS and connecting...");
                String configDir = getFilesDir().getAbsolutePath();
                RnsBridge.setupRnsAndWaitLink(configDir, serverHost,
                                              serverPort, destHash, compress);

                if (!"RNS link active".equals(RnsBridge.getStatus())) {
                    RnsBridge.onStatus("RNS setup failed");
                    stopSelf();
                    return;
                }

                RnsBridge.onStatus("Protecting RNS TCP socket...");
                int sockFd = RnsBridge.getTcpSocketFd();
                if (sockFd >= 0 && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    protect(sockFd);
                    Log.i(TAG, "Protected RNS socket fd=" + sockFd);
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    Log.w(TAG, "Hook missed, brute-force protecting fds...");
                    int count = 0;
                    for (int fd = 3; fd < 4096; fd++) {
                        try {
                            if (protect(fd)) count++;
                        } catch (Exception ignored) {}
                    }
                    Log.i(TAG, "Brute-force protected " + count + " fds");
                } else {
                    Log.w(TAG, "API < 29, cannot protect individual fds");
                }

                RnsBridge.onStatus("Establishing VPN TUN...");
                Builder builder = new Builder();
                builder.setSession("Reticulum TUN");
                builder.setMtu(tunMtu);
                String actualClientIp = clientIp;
                if (actualClientIp == null || actualClientIp.isEmpty() || "auto".equalsIgnoreCase(actualClientIp)) {
                    actualClientIp = RnsBridge.getClientIp();
                }
                builder.addAddress(actualClientIp, 24);
                builder.addRoute("0.0.0.0", 0);
                builder.addDnsServer("8.8.8.8");
                builder.addDnsServer("1.1.1.1");
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (Exception e) {
                    Log.e(TAG, "addDisallowedApplication error", e);
                }
                builder.setBlocking(true);

                vpnInterface = builder.establish();
                if (vpnInterface == null) {
                    RnsBridge.onStatus("VPN establish returned null");
                    stopSelf();
                    return;
                }

                int tunFd = vpnInterface.getFd();
                Log.i(TAG, "TUN fd=" + tunFd);
                RnsBridge.onStatus("VPN up, starting TUN bridge...");
                RnsBridge.startTun(tunFd, tunMtu);

                while (running) {
                    Thread.sleep(1000);
                }

            } catch (Exception e) {
                Log.e(TAG, "pipeline error", e);
                RnsBridge.onStatus("Error: " + e.getMessage());
                stopSelf();
            }
        }, "vpn-worker");
        workerThread.start();
    }

    private void cleanup() {
        RnsBridge.stopAll();
        if (vpnInterface != null) {
            try { vpnInterface.close(); } catch (IOException ignored) {}
            vpnInterface = null;
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Reticulum TUN",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder
            .setContentTitle("Reticulum TUN")
            .setContentText("VPN active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pIntent)
            .build();
    }
}
