package com.reticulum.tun;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private EditText etServerHost, etServerPort, etDestHash, etTunMtu, etClientIp;
    private CheckBox cbVerbose, cbCompress;
    private Button btnConnect, btnDisconnect;
    private TextView tvStatus, tvMyHash, tvLog;
    private ScrollView svLog;
    private Handler handler = new Handler(Looper.getMainLooper());
    private Runnable logPoller;
    private boolean connected = false;

    private static final int VPN_REQUEST_CODE = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        RnsBridge.initPython(getApplicationContext());

        etServerHost = findViewById(R.id.et_server_host);
        etServerPort = findViewById(R.id.et_server_port);
        etDestHash = findViewById(R.id.et_dest_hash);
        etTunMtu = findViewById(R.id.et_tun_mtu);
        etClientIp = findViewById(R.id.et_client_ip);
        cbVerbose = findViewById(R.id.cb_verbose);
        cbCompress = findViewById(R.id.cb_compress);
        btnConnect = findViewById(R.id.btn_connect);
        btnDisconnect = findViewById(R.id.btn_disconnect);
        tvStatus = findViewById(R.id.tv_status);
        tvMyHash = findViewById(R.id.tv_my_hash);
        tvLog = findViewById(R.id.tv_log);
        svLog = findViewById(R.id.sv_log);

        etServerPort.setText("4242");
        etTunMtu.setText("1500");
        etClientIp.setText("auto");

        SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
        String savedHost = prefs.getString("server_host", "");
        String savedHash = prefs.getString("dest_hash", "");
        String savedClientIp = prefs.getString("client_ip", "auto");
        int savedPort = prefs.getInt("server_port", 4242);
        int savedMtu = prefs.getInt("tun_mtu", 1500);
        boolean savedVerbose = prefs.getBoolean("verbose", false);
        boolean savedCompress = prefs.getBoolean("compress", false);
        if (cbVerbose != null) cbVerbose.setChecked(savedVerbose);
        if (cbCompress != null) cbCompress.setChecked(savedCompress);
        if (!savedHost.isEmpty()) etServerHost.setText(savedHost);
        if (!savedHash.isEmpty()) etDestHash.setText(savedHash);
        if (!savedClientIp.isEmpty()) etClientIp.setText(savedClientIp);
        if (savedPort != 4242) etServerPort.setText(String.valueOf(savedPort));
        if (savedMtu != 1500) etTunMtu.setText(String.valueOf(savedMtu));
        RnsBridge.setVerbose(savedVerbose);

        btnConnect.setOnClickListener(v -> connect());
        btnDisconnect.setOnClickListener(v -> disconnect());

        updateMyHash();
        startLogPoller();
        updateStatus();
    }

    private void connect() {
        String host = etServerHost.getText().toString().trim();
        String portStr = etServerPort.getText().toString().trim();
        String hash = etDestHash.getText().toString().trim();
        String mtuStr = etTunMtu.getText().toString().trim();
        String clientIp = etClientIp.getText().toString().trim();

        if (host.isEmpty() || hash.isEmpty()) {
            log("Enter server host and destination hash");
            return;
        }

        if (clientIp.isEmpty()) {
            clientIp = "auto";
        }

        int port = 4242;
        int mtu = 1500;
        try { port = Integer.parseInt(portStr); } catch (NumberFormatException ignored) {}
        try { mtu = Integer.parseInt(mtuStr); } catch (NumberFormatException ignored) {}

        boolean compress = cbCompress != null && cbCompress.isChecked();

        Intent prepare;
        try {
            prepare = VpnService.prepare(this);
        } catch (SecurityException e) {
            log("Security Exception: " + e.getMessage() + "\n(This is a known MIUI/Dual Apps system bug. Try disabling Dual Apps or rebooting.)");
            tvStatus.setText("Security Error");
            return;
        }

        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST_CODE);
            pendingConnect = new ConnectionParams(host, port, hash, mtu, compress, clientIp);
        } else {
            doConnect(host, port, hash, mtu, compress, clientIp);
        }
    }

    private ConnectionParams pendingConnect;

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_REQUEST_CODE && result == RESULT_OK && pendingConnect != null) {
            doConnect(pendingConnect.host, pendingConnect.port,
                      pendingConnect.hash, pendingConnect.mtu, pendingConnect.compress, pendingConnect.clientIp);
        }
        pendingConnect = null;
    }

    private void doConnect(String host, int port, String hash, int mtu, boolean compress, String clientIp) {
        boolean verbose = cbVerbose != null && cbVerbose.isChecked();
        SharedPreferences.Editor ed = getPreferences(Context.MODE_PRIVATE).edit();
        ed.putString("server_host", host);
        ed.putInt("server_port", port);
        ed.putString("dest_hash", hash);
        ed.putInt("tun_mtu", mtu);
        ed.putBoolean("verbose", verbose);
        ed.putBoolean("compress", compress);
        ed.putString("client_ip", clientIp);
        ed.apply();
        RnsBridge.setVerbose(verbose);

        connected = true;
        tvStatus.setText("Connecting...");

        Intent intent = new Intent(this, TunVpnService.class);
        intent.putExtra("server_host", host);
        intent.putExtra("server_port", port);
        intent.putExtra("dest_hash", hash);
        intent.putExtra("tun_mtu", mtu);
        intent.putExtra("compress", compress);
        intent.putExtra("client_ip", clientIp);
        startService(intent);
    }

    private void disconnect() {
        connected = false;
        Intent intent = new Intent(this, TunVpnService.class);
        stopService(intent);
        RnsBridge.stopAll();
        tvStatus.setText("Disconnected");
        finishAndRemoveTask();
        handler.postDelayed(() -> System.exit(0), 200);
    }

    private void updateStatus() {
        String status = RnsBridge.getStatus();
        tvStatus.setText(status);

        boolean isActive = !"idle".equals(status) && !"stopped".equals(status) && !"Disconnected".equals(status) && !status.contains("failed") && !status.contains("Error");
        btnConnect.setEnabled(!isActive);
        btnDisconnect.setEnabled(isActive);

        handler.postDelayed(this::updateStatus, 1000);
    }

    private void updateMyHash() {
        String hash = RnsBridge.getMyHash();
        if (!hash.isEmpty()) {
            tvMyHash.setText(hash);
        }
        handler.postDelayed(this::updateMyHash, 3000);
    }

    private void startLogPoller() {
        logPoller = () -> {
            String logText = RnsBridge.getLogText();
            if (!logText.isEmpty()) {
                tvLog.setText(logText);
                svLog.post(() -> svLog.fullScroll(ScrollView.FOCUS_DOWN));
            }
            handler.postDelayed(logPoller, 1000);
        };
        handler.postDelayed(logPoller, 1000);
    }

    private void log(String msg) {
        String existing = tvLog.getText().toString();
        tvLog.setText(existing + "\n" + msg);
        svLog.post(() -> svLog.fullScroll(ScrollView.FOCUS_DOWN));
    }

    private static class ConnectionParams {
        final String host;
        final int port;
        final String hash;
        final int mtu;
        final boolean compress;
        final String clientIp;
        ConnectionParams(String h, int p, String ha, int m, boolean c, String ip) {
            host = h; port = p; hash = ha; mtu = m; compress = c; clientIp = ip;
        }
    }
}
