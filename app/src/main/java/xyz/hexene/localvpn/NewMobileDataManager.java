package xyz.hexene.localvpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * Created by daiminglong on 2016/6/29.
 */
public class NewMobileDataManager extends NewNetworkManager{

    public static long lastByte = 0;
    public static long currentThroughput = 0;


    public NewMobileDataManager(Context context){
        super(context);
    }


    /**
     * this function used to disable Mobile data through command line,root permission needed
     */
    public void disableMobileData(){
        //execute
        Log.d("NewMobileDataManager", "disable Mobile Data");
        executeCmdLine("svc data disable");

    }


    /**
     * this function used to enable Mobile data through command line,root permission needed
     */
    public void enableMobileData(){
        //execute
        Log.d("NewMobileDataManager", "enable Mobile Data");
        executeCmdLine("svc data enable");
    }


    /**
     * this function used to get current Mobile Data local address
     *
     * @return
     */
    public InetAddress getMobileDataLocalAddress(){

        try {
            for(Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ){
                NetworkInterface intf = en.nextElement();
                if(!intf.getName().equals("wlan0")){
                    for(Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ){
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address){
                            return inetAddress;
                        }
                    }
                }
            }
        }catch(SocketException e){
            Log.e("mobile data ", "WifiPreference IpAddress" + e.toString());
        }
        return null;
    }


    /**
     * this function used to get 3G state
     *
     * @return
     */
    public boolean isMobileDataEnabled(){
        ConnectivityManager mConnectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo.State state = mConnectivityManager.getNetworkInfo(ConnectivityManager.TYPE_MOBILE).getState();

        if (state != NetworkInfo.State.CONNECTED) {
            return false;
        }else{
            return true;
        }
    }


    /**
     * this function used to get 3G's average RTT through 4 PingTask
     * @param ipAddress
     * @return 0:address unreachable
     *         others:average RTT
     */
    public static float getMobileDataRTT(String ipAddress){
        GetRTTThread getRTTThread = new GetRTTThread(Constant.MOBILE_DATA_TRANSMISSION, ipAddress);
        getRTTThread.start();
        try {
            getRTTThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return getRTTThread.getRttTime();
    }
}
