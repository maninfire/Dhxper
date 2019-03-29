package com.tsz.lier.dhxper;

import android.content.Context;
import android.util.Log;

import org.apache.commons.io.comparator.DefaultFileComparator;
import org.apache.commons.lang3.ObjectUtils;
import org.json.JSONException;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;

import dalvik.system.DexFile;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HotLoadPackageEntry {
    private static final String TAG = "HotPluginLoader";
    //private static MyServer server = new MyServer();
    //private static final XC_LoadPackage.LoadPackageParam=;

    //这里需要通过反射调用，HotLoadPackageEntry的entry的全路径不允许改变（包括方法签名），方法签名是xposed回调和热加载器的桥梁，需要满足调用接口规范
    //但是这个类的其他地方是可以修改的，因为这个代码已经是在最新插件apk的类加载器里面执行了
    @SuppressWarnings("unused")
    public static boolean entry(ClassLoader masterClassLoader, ClassLoader pluginClassLoader,
                                Context context, XC_LoadPackage.LoadPackageParam loadPackageParam) {

        Log.d(TAG,"message.......");
        hookDefineClass(loadPackageParam);
        return true;
    }

    public static void hookDefineClass(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            /*get DexFile Class*/
            Class clazz = loadPackageParam.classLoader.loadClass("dalvik.system.DexFile");
            Method[] methods = clazz.getDeclaredMethods();
            for (int i = 0; i < methods.length; i++) {
                String name = methods[i].getName();
                //clazz.getMethod().getName();
                //clazz.getDeclaredConstructors();
                //clazz.getMethods();
                if (name.equalsIgnoreCase("defineClass")) {
                    XposedBridge.hookMethod(methods[i],new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable{

                        }
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable{
                            Log.d(TAG,"success");
                        }

                    });

                }
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
