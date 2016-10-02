package xyz.hexene.localvpn;

import android.content.Context;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Created by daiminglong on 2016/7/25.
 */
public class Constant {

    public static String DAIMINGLONGTAG = "daiminglongtag";

    public static Map<String,ByteBuffer> requestBufferMap;
    public static int FLAG;
    public static final int WIFI_TRANSMISSION = 0;
    public static final int MOBILE_DATA_TRANSMISSION = 1;

    public static int DEFAULT_TRANSMISSION;

    public static int WIFI_RTT_LOW_THRESHOLD = 250;//unit ms
    public static int WIFI_RTT_HIGH_THRESHOLD = 300;//unit ms

    public static Context context;
}
