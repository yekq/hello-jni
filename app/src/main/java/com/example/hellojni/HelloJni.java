/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.hellojni;

import android.R.color;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;


public class HelloJni extends Activity
{
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.hello_jni);
        /* Create a TextView and set its content.
         * the text is retrieved by calling a native
         * function.
         */
        TextView  tv = (TextView) findViewById(R.id.tv);
//        tv.setText(this.encodeFromC("abc",3) + this.decodeFromC("bcd后",4)+",内核版本:"+stringFromJNI());
//        String en= this.getAES("1");
        String en= this.getAESDe("1");
        Log.d("aes",en);
        tv.setBackgroundResource(color.white);
        tv.setText(en);
        final Button btn= (Button) findViewById(R.id.btn);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                btn.setText(testStatic("1"));
            }
        });
    }

    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
    public native String  stringFromJNI();
    public native String encodeFromC(String txt,int leng);
    public native String decodeFromC(String txt,int leng);
    public native String getAESEn(String str);
    public native String getAESDe(String str);
    public native String testStatic(String str);
    static {
        System.loadLibrary("hello-jni");
    }
}
