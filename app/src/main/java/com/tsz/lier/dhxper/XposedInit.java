package com.tsz.lier.dhxper;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.nfc.Tag;
import android.os.Process;
import android.util.Log;

import com.google.common.collect.Maps;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.util.List;
import java.util.concurrent.ConcurrentMap;

import dalvik.system.DexFile;
import dalvik.system.PathClassLoader;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

public class XposedInit implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private String hotloadPluginEntry="com.tsz.lier.dhxper.HotLoadPackageEntry";
    private volatile  boolean hooked = false;
    private String TAG="inittag";
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam){
        if (!lpparam.isFirstApplication) {

            return;
        }
        HotLoadPackageEntry.hookDefineClass(lpparam);
//        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook(XCallback.PRIORITY_HIGHEST * 2) {
//
//            //由于集成了脱壳功能，所以必须选择before了
//            @Override
//            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//                hotLoadPlugin(lpparam.classLoader, (Context) param.args[0], lpparam);
//            }
//        });

    }
    private static final String INSTANT_RUN_CLASS = "com.android.tools.fd.runtime.BootstrapApplication";
    private static ConcurrentMap<String, PathClassLoader> classLoaderCache = Maps.newConcurrentMap();


    @SuppressLint("PrivateApi")
    private void hotLoadPlugin(ClassLoader ownerClassLoader, Context context, XC_LoadPackage.LoadPackageParam lpparam) {
        boolean hasInstantRun = true;
        try {
            XposedInit.class.getClassLoader().loadClass(INSTANT_RUN_CLASS);
        } catch (ClassNotFoundException e) {
            //正常情况应该报错才对
            hasInstantRun = false;
        }
        if (hasInstantRun) {
            Log.e("weijia", "  Cannot load module, please disable \"Instant Run\" in Android Studio.");
            return;
        }

        ClassLoader hotClassLoader = replaceClassloader(context, lpparam);
//        if (hotClassLoader == XposedInit.class.getClassLoader()) {
//            //这证明不需要实现代码替换，或者热加载框架作用失效
//            //XposedBridge.log("热加载未生效");
//        }
        // check  Instant Run, 热加载启动后，需要重新检查Instant Run
        hasInstantRun = true;
        try {
            hotClassLoader.loadClass(INSTANT_RUN_CLASS);
        } catch (ClassNotFoundException e) {
            //正常情况应该报错才对
            hasInstantRun = false;
        }
        if (hasInstantRun) {
            Log.e("weijia", "  Cannot load module, please disable \"Instant Run\" in Android Studio.");
            return;
        }


        try {
            Class<?> aClass = hotClassLoader.loadClass(hotloadPluginEntry);
            Log.i("weijia", "invoke hot load entry");
            aClass
                    .getMethod("entry", ClassLoader.class, ClassLoader.class, Context.class, XC_LoadPackage.LoadPackageParam.class)
                    .invoke(null, ownerClassLoader, hotClassLoader, context, lpparam);
        } catch (Exception e) {
            if (e instanceof ClassNotFoundException) {
                InputStream inputStream = hotClassLoader.getResourceAsStream("assets/hotload_entry.txt");
                if (inputStream == null) {
                    XposedBridge.log("do you not disable Instant Runt for Android studio?");
                } else {
                    IOUtils.closeQuietly(inputStream);
                }
            }
            XposedBridge.log(e);
        }
    }

    private static ClassLoader replaceClassloader(Context context, XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader classLoader = XposedInit.class.getClassLoader();
        if (!(classLoader instanceof PathClassLoader)) {
            XposedBridge.log("classloader is not PathClassLoader: " + classLoader.toString());
            return classLoader;
        }

//        //find the apk location installed in android system,this file maybe a dex cache mapping(do not the real installed apk)
//        Object element = bindApkLocation(classLoader);
//        if (element == null) {
//            return classLoader;
//        }
//        File apkLocation = (File) XposedHelpers.getObjectField(element, "zip");
//        //原文件可能已被删除，直接打开文件无法得到句柄，所以只能去获取持有删除文件句柄对象
//        ZipFile zipFile = (ZipFile) XposedHelpers.getObjectField(element, "zipFile");
//        if (zipFile == null && apkLocation.exists()) {
//            try {
//                zipFile = new ZipFile(apkLocation);
//            } catch (Exception e) {
//                //ignore
//            }
//        }
////        if (zipFile == null) {
////            return classLoader;
////        }
//        String packageName = findPackageName(zipFile);
//        if (StringUtils.isBlank(packageName)) {
////            XposedBridge.log("can not find package name  for this apk ");
////            return classLoader;
//            //先暂时这么写，为啥有问题后面排查
//            packageName = "com.virjar.xposedhooktool";
//        }

        //find real apk location by package name
        PackageManager packageManager = context.getPackageManager();
        if (packageManager == null) {
            XposedBridge.log("can not find packageManager");
            return classLoader;
        }

        PackageInfo packageInfo = null;
        try {
            packageInfo = packageManager.getPackageInfo(BuildConfig.APPLICATION_ID, PackageManager.GET_META_DATA);
        } catch (PackageManager.NameNotFoundException e) {
            //ignore
        }
        if (packageInfo == null) {
            XposedBridge.log("can not find plugin install location for plugin: " + BuildConfig.APPLICATION_ID);
            return classLoader;
        }

        //check if apk file has relocated,apk location maybe change if xposed plugin is reinstalled(system did not reboot)
        //xposed 插件安装后不能立即生效（需要重启Android系统）的本质原因是这两个文件不equal

        //hotClassLoader can load apk class && classLoader.getParent() can load xposed framework and android framework
        //使用parent是为了绕过缓存，也就是不走系统启动的时候链接的插件apk，但是xposed框架在这个classloader里面持有，所以集成

        return createClassLoader(classLoader.getParent(), packageInfo);
    }
    /**
     * 这样做的目的是保证classloader单例，因为宿主存在多个dex的时候，或者有壳的宿主在解密代码之后，存在多次context的创建，当然xposed本身也存在多次IXposedHookLoadPackage的回调
     *
     * @param parent      父classloader
     * @param packageInfo 插件自己的包信息
     * @return 根据插件apk创建的classloader
     */
    private static PathClassLoader createClassLoader(ClassLoader parent, PackageInfo packageInfo) {
        if (classLoaderCache.containsKey(packageInfo.applicationInfo.sourceDir)) {
            return classLoaderCache.get(packageInfo.applicationInfo.sourceDir);
        }
        synchronized (XposedInit.class) {
            if (classLoaderCache.containsKey(packageInfo.applicationInfo.sourceDir)) {
                return classLoaderCache.get(packageInfo.applicationInfo.sourceDir);
            }
            XposedBridge.log("create a new classloader for plugin with new apk path: " + packageInfo.applicationInfo.sourceDir);
            PathClassLoader hotClassLoader = new PathClassLoader(packageInfo.applicationInfo.sourceDir, parent);
            classLoaderCache.putIfAbsent(packageInfo.applicationInfo.sourceDir, hotClassLoader);
            return hotClassLoader;
        }
    }
    private static final int DEBUG_ENABLE_DEBUGGER = 0x1;
    private XC_MethodHook debugAppsHook = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param)
                throws Throwable {
            XposedBridge.log("-- beforeHookedMethod :" + param.args[1]);
            int id = 5;
            int flags = (Integer) param.args[id];
            if ((flags & DEBUG_ENABLE_DEBUGGER) == 0) {
                flags |= DEBUG_ENABLE_DEBUGGER;
            }
            param.args[id] = flags;
        }
    };

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        //https://github.com/deskid/XDebug 让所有进程处于可以被调试的状态
        XposedBridge.hookAllMethods(Process.class, "start", debugAppsHook);
    }
}
