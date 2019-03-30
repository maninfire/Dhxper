package com.tsz.lier.dhxper;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.PixelFormat;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.google.common.collect.Lists;

import org.apache.commons.lang3.StringUtils;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        //System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        tv.setText("  ");
        getInstallAppList();
    }

    private void getInstallAppList() {

        final List<Appinfo> allAppInfo = Lists.newLinkedList();
        try {
            List<PackageInfo> packageInfos = getPackageManager().getInstalledPackages(0);
            for (PackageInfo packageInfo : packageInfos) {
                if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0 && (!StringUtils.equals(packageInfo.packageName, "com.smartdone.dexdump"))) {
                    Log.d("unpack3",packageInfo.packageName);
//                    Appinfo info = new Appinfo();
//                    info.setIcon(zoomDrawable(packageInfo.applicationInfo.loadIcon(getPackageManager()), DensityUtil.dip2px(this, 128), DensityUtil.dip2px(this, 128)));
//                    info.setAppName(packageInfo.applicationInfo.loadLabel(getPackageManager()).toString());
//                    info.setAppPackage(packageInfo.packageName);
//                    allAppInfo.add(info);
                }
            }
//            MainActivity.this.runOnUiThread(new Runnable() {
//                @Override
//                public void run() {
//                    appinfos.addAll(allAppInfo);
//                    adapter.notifyDataSetChanged();
//                }
            //});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Drawable zoomDrawable(Drawable drawable, int w, int h) {
        int width = drawable.getIntrinsicWidth();
        int height = drawable.getIntrinsicHeight();
        Bitmap oldbmp = drawableToBitmap(drawable);
        Matrix matrix = new Matrix();
        float scaleWidth = ((float) w / width);
        float scaleHeight = ((float) h / height);
        matrix.postScale(scaleWidth, scaleHeight);
        Bitmap newbmp = Bitmap.createBitmap(oldbmp, 0, 0, width, height,
                matrix, true);
        return new BitmapDrawable(null, newbmp);
    }


    private Bitmap drawableToBitmap(Drawable drawable) {
        int width = drawable.getIntrinsicWidth();
        int height = drawable.getIntrinsicHeight();
        Bitmap.Config config = drawable.getOpacity() != PixelFormat.OPAQUE ? Bitmap.Config.ARGB_8888
                : Bitmap.Config.RGB_565;
        Bitmap bitmap = Bitmap.createBitmap(width, height, config);
        Canvas canvas = new Canvas(bitmap);
        drawable.setBounds(0, 0, width, height);
        drawable.draw(canvas);
        return bitmap;
    }
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    //public native String stringFromJNI();
}
