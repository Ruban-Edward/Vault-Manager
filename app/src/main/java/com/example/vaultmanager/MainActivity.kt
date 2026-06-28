package com.example.vaultmanager

import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {

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
                if (androidx.webkit.WebViewFeature.isFeatureSupported(androidx.webkit.WebViewFeature.FORCE_DARK)) {
                    androidx.webkit.WebSettingsCompat.setForceDark(webView.settings, androidx.webkit.WebSettingsCompat.FORCE_DARK_ON)
                }
            }
        }

        webView.addJavascriptInterface(BiometricBridge(this, webView), "Android")
        webView.webViewClient = WebViewClient()
        webView.loadUrl("file:///android_asset/index.html")

        setContentView(webView)
    }
    class BiometricBridge(private val activity: AppCompatActivity, private val webView: WebView) {
        private val executor: Executor = ContextCompat.getMainExecutor(activity)

        @JavascriptInterface
        fun authenticateBiometric(): String {
            activity.runOnUiThread {
                // If device does not support biometrics or none enrolled, return a simple error string
                val bm = BiometricManager.from(activity)
                val can = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                if (can != BiometricManager.BIOMETRIC_SUCCESS) {
                    webView.evaluateJavascript("window.onBiometricResult(false);", null)
                    return@runOnUiThread
                }

                val prompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        // Call JS callback with true
                        webView.evaluateJavascript("window.onBiometricResult(true);", null)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        // errorCode 13 is BiometricPrompt.ERROR_NEGATIVE_BUTTON
                        val res = if (errorCode == 13) "'NEGATIVE'" else "'CANCEL'"
                        webView.evaluateJavascript("window.onBiometricResult($res);", null)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        // failed attempt, but allow retry
                    }
                })

                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock Vault")
                    .setSubtitle("Authenticate to open Vault")
                    .setConfirmationRequired(false)
                    .setNegativeButtonText("Use App PIN")
                    .build()

                // Start the biometric prompt asynchronously.
                prompt.authenticate(info)
            }
            return "STARTED"
        }

        @JavascriptInterface
        fun shareText(text: String) {
            val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(android.content.Intent.EXTRA_TEXT, text)
            }
            activity.startActivity(android.content.Intent.createChooser(intent, "Share via"))
        }
    }
}