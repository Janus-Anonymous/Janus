package xyz.hexene.localvpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.util.Log;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Created by daiminglong on 2016/7/10.
 */
public class NewWifiManager extends NewNetworkManager{


    public static long lastByte = 0;
    public static long currentThroughput = 0;

    public NewWifiManager(Context context){
        super(context);
    }


    /**
     * this function used to disable Mobile data through command line,root permission needed
     */
    public void disableWifi(){
        //execute
        Log.d("NewWifiManager", "disable Wifi");
        executeCmdLine("svc wifi disable");

    }


    /**
     * this function used to enable Mobile data through command line,root permission needed
     */
    public void enableWifi(){
        //execute
        Log.d("NewWifiManager", "enable Wifi");
        executeCmdLine("svc wifi enable");
    }


    /**
     * this function used to get current wifi local address
     * @return
     */
    public InetAddress getWifiLocalAddress(){
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();

        int intIpAddress = wifiInfo.getIpAddress();
        String ipAddress = fromIntToIP(intIpAddress);
        InetAddress inetAddress = null;
        try {
            inetAddress = InetAddress.getByName(ipAddress);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return inetAddress;
    }


    /**
     * this function used to get current wifi gateway address
     * @return
     */
    public String getWifiGateway(){
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        DhcpInfo dhcpInfo = wifiManager.getDhcpInfo();
        int intGatewayAddress = dhcpInfo.gateway;
        String gatewayAddress = fromIntToIP(intGatewayAddress);
        return gatewayAddress;
    }


    /**
     * this function used to get wifi state
     *
     * @return
     */
    public static boolean isWifiEnabled(){
        ConnectivityManager mConnectivityManager = (ConnectivityManager) Constant.context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo.State state = mConnectivityManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI).getState();
        if (state != NetworkInfo.State.CONNECTED) {
            return false;
        }else{
            return true;
        }
    }


    /**
     * this function used to get wifi's average RTT through 4 PingTask
     * @param ipAddress
     * @return 0:address unreachable
     *         others:average RTT
     */
    public static float getWifiRTT(String ipAddress){
        GetRTTThread getRTTThread = new GetRTTThread(Constant.WIFI_TRANSMISSION, ipAddress);
        getRTTThread.start();
        try {
            getRTTThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return getRTTThread.getRttTime();
    }

}
