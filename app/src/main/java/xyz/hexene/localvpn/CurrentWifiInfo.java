package xyz.hexene.localvpn;

import android.content.Context;

import java.net.InetAddress;

/**
 * Created by daiminglong on 2016/7/10.
 */
public class CurrentWifiInfo {

    public static InetAddress currentWifiLocalAddress;
    public static String currentWifiGateway;


    /**
     * this function used to get current Wifi's local address, gateway and other info
     *
     * @param context
     * @return
     */
    public static void getCurrentWifiInfo(Context context){

        NewWifiManager newWifiManager = new NewWifiManager(context);

        if(!NewWifiManager.isWifiEnabled()){
            newWifiManager.enableWifi();
        }
        CurrentWifiInfo.currentWifiLocalAddress = newWifiManager.getWifiLocalAddress();
        CurrentWifiInfo.currentWifiGateway = newWifiManager.getWifiGateway();
    }
}
