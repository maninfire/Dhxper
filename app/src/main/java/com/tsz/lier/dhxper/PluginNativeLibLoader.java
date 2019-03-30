package com.tsz.lier.dhxper;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * Created by virjar on 2018/5/17.<br>
 * load the native lib
 */

public class PluginNativeLibLoader {
    private static final String HOOKLIB = "unshellnative";

    static {
        loadPluginLib();
    }

    public static void makeSureNativeLibLoaded() {
        //do nothing
    }


    private static void loadPluginLib() {


        //由于在代码植入到宿主程序，需要改变默认的静态链接库构成规则
        XC_MethodHook.Unhook unhook = XposedHelpers.findAndHookMethod("dalvik.system.BaseDexClassLoader", ClassLoader.getSystemClassLoader(), "findLibrary", String.class, new XC_MethodHook(XC_MethodHook.PRIORITY_HIGHEST) {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (HOOKLIB.equals(param.args[0]) && param.getResult() == null) {
                    param.setResult("/data/data/" + BuildConfig.APPLICATION_ID + "/lib/lib" + HOOKLIB + ".so");
                }
            }
        });
        //加载native层代码
        System.loadLibrary(HOOKLIB);
        //加载完成，取消hook设定
        unhook.unhook();
    }
}
