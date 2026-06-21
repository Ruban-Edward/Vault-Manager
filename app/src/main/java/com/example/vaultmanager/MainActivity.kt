package com.example.vaultmanager

import android.app.Activity
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowFileAccess = true

            // Enable Dark Mode support for WebView
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val nightModeFlags = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
                if (nightModeFlags == Configuration.UI_MODE_NIGHT_YES) {
                    forceDark = WebSettings.FORCE_DARK_ON
                } else {
                    forceDark = WebSettings.FORCE_DARK_OFF
                }
            }
        }

        webView.webViewClient = WebViewClient()
        webView.loadUrl("file:///android_asset/index.html")

        setContentView(webView)
    }
}