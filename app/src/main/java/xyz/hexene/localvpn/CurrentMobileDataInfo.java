package xyz.hexene.localvpn;

import android.content.Context;

import java.net.InetAddress;

/**
 * Created by daiminglong on 2016/7/19.
 */
public class CurrentMobileDataInfo {

    public static InetAddress currentMobileDataLocalAddress;// current IP

    /**
     * this function used to get current Mobile data's local address and other info
     *
     * @param context
     * @return
     */
    public static void getCurrentMobileDataInfo(Context context){

        NewMobileDataManager newMobileDataManager = new NewMobileDataManager(context);
        currentMobileDataLocalAddress = newMobileDataManager.getMobileDataLocalAddress();
    }
}
