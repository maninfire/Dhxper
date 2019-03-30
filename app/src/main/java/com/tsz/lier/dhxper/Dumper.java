package com.tsz.lier.dhxper;

import android.util.Log;

import com.google.common.io.ByteStreams;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;

import java.io.IOException;
import java.io.PrintStream;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import dalvik.bytecode.Opcodes;

public class Dumper {

    public ClassLoader classLoader=null;
   //public  DexBackedDexFile dexFile=null;
   public static String utag="unpack3";


    public static void WriteStringToFile(String filePath,String input) {
        try {
            File file = new File(filePath);
            if(!file.exists()){
                try{
                    Log.d(utag,"file create");
                    file.createNewFile();
                }catch (Exception e){
                    Log.d(utag,e.getMessage());
                }

            }else{
                file.delete();
                try{
                    Log.d(utag,"file recreate");
                    file.createNewFile();
                }catch (Exception e){
                    Log.d(utag,"recreate:"+e.getMessage());
                }

            }
            PrintStream ps = new PrintStream(new FileOutputStream(file));
            ps.println("http://www.jb51.net");// 往文件里写入字符串
            ps.append(input);// 在已有的基础上添加字符串
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /*
     * 创建dexFile模型
     * */
    private static void createMemoryDexFile(Class loader) {
        ByteBuffer byteBuffer = (ByteBuffer)originDex(loader);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byte[] buffer = new byte[byteBuffer.capacity()];
        byteBuffer.get(buffer, 0, byteBuffer.capacity());
        File dump=new File("/data/local/tmp/unpack/test.dex");
        writetofile(buffer,dump);
}

    /**
     * 将对应class对应的dex文件的二进制dump出来
     *
     * @param loader 该dex文件定义的任何一个class，或者class定义的object
     * @return 一个byteBuffer，包含了二进制数据
     */
    public static Class resolveLoaderClass(Object loader){
        return loader.getClass();
    }


    public static ByteBuffer dumpDex(Object loader) {
        Log.i(utag, " wellcoming into world dumpdex");
        Class loaderClass = resolveLoaderClass(loader);
        String packagename=loaderClass.getPackage().getName();
        Log.d(utag,"packagename:"+loaderClass.getCanonicalName()+" :"+packagename);
        createMemoryDexFile(loaderClass);


        //return ByteBuffer.wrap();
        return null;
    }

    public static void writetofile(byte[] input,File file){
        //Log.d(utag,"input bytebuf:"+input);
        //File ret=new File("/data/local/tmp/unpack/dump.dex");
        if(!file.exists()){
            try{
                Log.d(utag,"file create");
                file.createNewFile();
            }catch (Exception e){
                Log.d(utag,e.getMessage());
            }

        }else{
            file.delete();
            try{
                Log.d(utag,"file recreate");
                file.createNewFile();
            }catch (Exception e){
                Log.d(utag,"recreate:"+e.getMessage());
            }

        }
        //FileChannel in = null, out = null;
        try {
            ///in = new FileInputStream(source).getChannel();
            FileOutputStream out = new FileOutputStream(file,true);//.getChannel();
            //long size = in.size();
            //MappedByteBuffer buf = in.map(FileChannel.MapMode.READ_ONLY, 0, size);
            out.write(input);
            //in.close();

            out.close();
            Log.d(utag,"file writen finished");
            //source.delete();//文件复制完成后，删除源文件
        }catch(Exception e){
            Log.d(utag,"write file exception:"+e.getMessage());
            e.printStackTrace();
        } finally {
            //in.close();
            //out.close();
        }
    }
public static void writetofile(ByteBuffer input,File file){
        Log.d(utag,"input bytebuf:"+input.getChar());
    //File ret=new File("/data/local/tmp/unpack/dump.dex");
    if(!file.exists()){
        try{
            Log.d(utag,"file create");
            file.createNewFile();
        }catch (Exception e){
            Log.d(utag,e.getMessage());
        }

    }else{
        file.delete();
        try{
            Log.d(utag,"file recreate");
            file.createNewFile();
        }catch (Exception e){
            Log.d(utag,"recreate:"+e.getMessage());
        }

    }
    //FileChannel in = null, out = null;
    try {
        ///in = new FileInputStream(source).getChannel();
        FileOutputStream out = new FileOutputStream(file,true);//.getChannel();
        //long size = in.size();
        //MappedByteBuffer buf = in.map(FileChannel.MapMode.READ_ONLY, 0, size);
        out.write(input.array());
        //in.close();

        out.close();
        Log.d(utag,"file writen finished");
        //source.delete();//文件复制完成后，删除源文件
    }catch(Exception e){
        Log.d(utag,"write file exception:"+e.getMessage());
        e.printStackTrace();
    } finally {
        //in.close();
        //out.close();
    }
}

public static void testa(){
        test();
}


    public static native void Dumperfromdefineclass(String name, Object loader, int cookie);
    public static native Object originDex(Class loader);
    public static native void test();
    public  static  native Object methodDataWithDescriptor(String methodDescriptor_,
                                                         String methodName_,
                                                         Class searchClass);
    public  static  native int getMethodAccessFlagsWithDescriptor(String methodDescriptor_,
                                                           String methodName_,
                                                           Class searchClass);
}
