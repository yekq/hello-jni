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

import android.app.Activity;
import android.os.Bundle;
import android.support.v7.widget.AppCompatEditText;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import com.example.hellojni.R.id;
import com.example.hellojni.R.layout;


public class HelloJni extends Activity implements OnClickListener {


    private AppCompatEditText mEtEncrpt;
    private Button mBtnEncrpt;
    private AppCompatEditText mEtDecrypt;
    private Button mBtnDecrypt;
    private TextView mTvDecryptResult;
    private TextView mTvCheck;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.setContentView(layout.hello_jni);
        this.initView();

    }

    private void initView() {
        this.mEtEncrpt = (AppCompatEditText) this.findViewById(id.et_encrpt);
        this.mBtnEncrpt = (Button) this.findViewById(id.btn_encrpt);
        this.mEtDecrypt = (AppCompatEditText) this.findViewById(id.et_decrypt);
        this.mBtnDecrypt = (Button) this.findViewById(id.btn_decrypt);
        this.mTvDecryptResult = (TextView) this.findViewById(id.tv_decrypt_result);
        this.mTvCheck = (TextView) this.findViewById(id.tv_check);

        this.mBtnEncrpt.setOnClickListener(this);
        this.mBtnDecrypt.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case id.btn_encrpt:
                this.mEtDecrypt.setText(this.getAESEn(this.mEtEncrpt.getText().toString()));
                break;
            case id.btn_decrypt:
                String result= this.getAESDe(this.mEtDecrypt.getText().toString()).trim();
                this.mTvDecryptResult.setText(result);
                this.mTvCheck.setText(this.mEtEncrpt.getText().toString().equals(result)?"成功!与加密前一致":"失败!与加密前不一致");
                break;
        }
    }

    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
    public native String stringFromJNI();

    public native String encodeFromC(String txt, int leng);

    public native String decodeFromC(String txt, int leng);

    public native String getAESEn(String str);

    public native String getAESDe(String str);

    static {
        System.loadLibrary("hello-jni");
    }


}
