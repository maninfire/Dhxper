package com.tsz.lier.dhxper;

import android.app.Activity;
import android.content.Context;
import android.util.Log;

import org.apache.commons.lang3.StringUtils;
import java.lang.reflect.Method;
import java.util.List;

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

        //Log.d(TAG,"message.......");
        hookDefineClass(loadPackageParam);
        return true;
    }

    public static void hookDefineClass(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            /*get DexFile Class*/
            PluginNativeLibLoader.makeSureNativeLibLoaded();
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

// catch (ClassNotFoundException e) {
//                                if (suppressed != null) {
//                                    suppressed.add(e);
//                                }
 //                           }
                        }
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable{
                            //Log.d(TAG,"success");
                            Class result = null;
                            List<Throwable> suppressed=(List<Throwable> )param.args[3];
                            try {
                                Dumper.Dumperfromdefineclass((String)(param.args[0]),
                                        param.args[1],
                                        (int)(param.args[2]));
                                //result = defineClassNative(param.args[0], param.args[1],
                                //        param.args[2]);
                                ///Log.d(TAG,"success");
                                //Dumper.testa();
                                //result = defineClassNative(name, loader, cookie);
                                //private static Class defineClass(String name, ClassLoader loader
//                            , int cookie,
//                                List<Throwable> suppressed)
                            } catch (NoClassDefFoundError e) {
                                if (suppressed != null) {
                                    suppressed.add(e);
                                }
                            }
                        }

                    });

                }
            }

            //registerDump3(loadPackageParam);

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void registerDump3(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        if (StringUtils.equals(loadPackageParam.packageName, BuildConfig.APPLICATION_ID)) {
            return;//不hook自身
        }
        if (!StringUtils.equals(loadPackageParam.packageName, "com.tencent.android.qqdownloader")) {
            Log.d(TAG,"escape:"+loadPackageParam.packageName);
            return;//不hook自身
        }
        Log.d(TAG,"hit yingyongbao");
        XposedBridge.log("对" + loadPackageParam.packageName + "进行脱壳dump处理");
        PluginNativeLibLoader.makeSureNativeLibLoaded();
//        XposedBridge.hookAllConstructors(Activity.class, new SingletonXC_MethodHook() {
//
//
//            @Override
//            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
//                Class<?> aClass = param.thisObject.getClass();
//                if (aClass.getClassLoader().equals(Activity.class.getClassLoader())) {
//                    return;
//                }
//                throw new UnsupportedOperationException("开源版本不支持三代壳脱壳方案");
//            }
//        });
        Log.i(TAG,"registerDumps3");
        XposedHelpers.findAndHookConstructor(Activity.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object activity = param.thisObject;
                if (activity == null) {
                    return;
                }
                XposedBridge.log("hook class " + activity.getClass());
                Log.i(TAG,"compare name:"+activity.getClass().getName());
//                if (StringUtils.equalsIgnoreCase(activity.getClass().getName(), "com.xxx.xxx.MainActivity")) {
//                    Log.i(tag,"dump begin:");
//                    com.virjar.xposedhooktool.unshell.Dumper.dumpDex(activity);
//                }else if(StringUtils.equalsIgnoreCase(activity.getClass().getName(), "com.xxx.xxx.xxx.MainActivity")){
//                    Log.i(tag,"dump next begin:");
//                    com.virjar.xposedhooktool.unshell.Dumper.dumpDex(activity);
//                }
                if(activity.getClass().getName().indexOf("com")!=-1 && activity.getClass().getName().indexOf("MainActivity")!=-1){
                    Log.i(TAG,"dump begin:"+activity.getClass().getName());
                    com.tsz.lier.dhxper.Dumper.dumpDex(activity);
                }
            }
        });

        //PluginNativeLibLoader.makeSureNativeLibLoaded();
        //Dumper.dumpVersion3();
    }
}
