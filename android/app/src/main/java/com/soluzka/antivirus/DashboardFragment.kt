package com.soluzka.antivirus

import android.annotation.SuppressLint
import android.content.SharedPreferences
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.preference.PreferenceManager

class DashboardFragment : Fragment() {

    private lateinit var webView: WebView
    private lateinit var progressBar: ProgressBar
    private lateinit var errorView: View
    private lateinit var errorText: TextView
    private lateinit var prefs: SharedPreferences

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_dashboard, container, false)

        prefs = PreferenceManager.getDefaultSharedPreferences(requireContext())
        webView = view.findViewById(R.id.webview)
        progressBar = view.findViewById(R.id.webProgressBar)
        errorView = view.findViewById(R.id.webErrorView)
        errorText = view.findViewById(R.id.webErrorText)
        val retryButton = view.findViewById<Button>(R.id.webRetryButton)

        retryButton.setOnClickListener { loadServer() }
        setupWebView()
        loadServer()

        return view
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            cacheMode = android.webkit.WebSettings.LOAD_DEFAULT
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
            userAgentString = "$userAgentString AntivirusServerAndroid/2.0"
        }

        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true)

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                return false
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                progressBar.visibility = View.GONE
                webView.visibility = View.VISIBLE
                errorView.visibility = View.GONE
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: android.webkit.WebResourceError?
            ) {
                super.onReceivedError(view, request, error)
                if (request?.isForMainFrame == true) {
                    showError()
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                if (newProgress < 100) {
                    progressBar.visibility = View.VISIBLE
                } else {
                    progressBar.visibility = View.GONE
                }
            }
        }
    }

    private fun loadServer() {
        val serverUrl = prefs.getString("server_url", "https://isolation-bytes.com")
            ?: "https://isolation-bytes.com"

        if (serverUrl.isBlank()) {
            showError()
            return
        }

        webView.visibility = View.VISIBLE
        errorView.visibility = View.GONE
        progressBar.visibility = View.VISIBLE
        webView.loadUrl(serverUrl)
    }

    private fun showError() {
        webView.visibility = View.GONE
        progressBar.visibility = View.GONE
        errorView.visibility = View.VISIBLE
    }
}
