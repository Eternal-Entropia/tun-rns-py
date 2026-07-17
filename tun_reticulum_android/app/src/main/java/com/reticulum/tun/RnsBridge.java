package com.reticulum.tun;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.chaquo.python.Python;
import com.chaquo.python.PyObject;
import com.chaquo.python.android.AndroidPlatform;

public class RnsBridge {
    private static final String TAG = "RnsBridge";

    private static TunVpnService vpnService;
    private static Python py;
    private static PyObject tunnelModule;
    private static volatile boolean pythonReady = false;
    private static volatile String lastStatus = "idle";

    public static void setVpnService(TunVpnService svc) {
        vpnService = svc;
    }

    public static TunVpnService getVpnService() {
        return vpnService;
    }

    public static boolean isPythonReady() {
        return pythonReady && tunnelModule != null;
    }

    public static void initPython(Context context) {
        if (pythonReady) return;
        if (!Python.isStarted()) {
            Python.start(new AndroidPlatform(context));
        }
        py = Python.getInstance();
        tunnelModule = py.getModule("tunnel_core");
        pythonReady = true;
        Log.i(TAG, "Python initialized");
    }

    public static void setupRnsAndWaitLink(String configDir,
                                            String serverHost,
                                            int serverPort,
                                            String destHash,
                                            boolean compress) {
        if (!isPythonReady()) {
            onStatus("Python not ready");
            return;
        }
        try {
            onStatus("Setting up RNS...");
            tunnelModule.callAttr("setup", configDir, serverHost,
                                  serverPort, destHash, compress);

            PyObject ok = tunnelModule.callAttr("wait_for_link", 60);
            if (ok != null && ok.toBoolean()) {
                onStatus("RNS link active");
                Log.i(TAG, "RNS link established");
            } else {
                onStatus("RNS link failed");
                Log.w(TAG, "RNS link not established");
            }
        } catch (Exception e) {
            Log.e(TAG, "setupRns error", e);
            onStatus("RNS error: " + e.getMessage());
        }
    }

    public static void startTun(int tunFd, int mtu) {
        if (!isPythonReady()) return;
        try {
            tunnelModule.callAttr("start_tun", tunFd, mtu);
            onStatus("tunnel active");
        } catch (Exception e) {
            Log.e(TAG, "startTun error", e);
            onStatus("TUN error: " + e.getMessage());
        }
    }

    public static void stopAll() {
        if (isPythonReady()) {
            try {
                tunnelModule.callAttr("stop_all");
            } catch (Exception e) {
                Log.e(TAG, "stopAll error", e);
            }
        }
        onStatus("stopped");
    }

    public static String getStatus() {
        return lastStatus;
    }

    public static String getMyHash() {
        if (!isPythonReady()) return "";
        try {
            PyObject h = tunnelModule.callAttr("get_my_hash");
            return h != null ? h.toString() : "";
        } catch (Exception e) {
            return "";
        }
    }

    public static String getLogText() {
        if (!isPythonReady()) return "";
        try {
            PyObject log = tunnelModule.callAttr("get_log");
            return log != null ? log.toString() : "";
        } catch (Exception e) {
            return "";
        }
    }

    public static int getTcpSocketFd() {
        if (!isPythonReady()) return -1;
        try {
            PyObject fd = tunnelModule.callAttr("get_tcp_socket_fd");
            return fd != null ? fd.toInt() : -1;
        } catch (Exception e) {
            Log.e(TAG, "getTcpSocketFd error", e);
            return -1;
        }
    }

    public static boolean protectFd(int fd) {
        if (vpnService != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                boolean ok = vpnService.protect(fd);
                Log.i(TAG, "Protected socket fd=" + fd + " result=" + ok);
                return ok;
            } else {
                Log.w(TAG, "protectFd: API < 29, cannot protect fd=" + fd);
            }
        } else {
            Log.w(TAG, "protectFd: vpnService is null, cannot protect fd=" + fd);
        }
        return false;
    }

    public static String getClientIp() {
        if (!isPythonReady()) return "10.244.0.2";
        try {
            PyObject ip = tunnelModule.callAttr("get_client_ip");
            return ip != null ? ip.toString() : "10.244.0.2";
        } catch (Exception e) {
            Log.e(TAG, "getClientIp error", e);
            return "10.244.0.2";
        }
    }

    public static void setVerbose(boolean on) {
        if (isPythonReady()) {
            try {
                tunnelModule.callAttr("set_verbose", on);
            } catch (Exception e) {
                Log.e(TAG, "setVerbose error", e);
            }
        }
    }

    public static void onStatus(String status) {
        lastStatus = status;
        Log.i(TAG, status);
    }
}
