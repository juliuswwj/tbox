package com.juliuswwj.tbox.android

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import com.juliuswwj.tbox.android.databinding.ActivityMainBinding
import com.juliuswwj.tbox.mobile.Mobile

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) connect() else render(TboxVpnService.State.IDLE, "VPN permission denied")
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* best-effort */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.tokenInput.setText(Prefs.token(this))
        binding.tokenInput.doAfterTextChanged { updateServerInfo(it?.toString().orEmpty()) }
        updateServerInfo(binding.tokenInput.text?.toString().orEmpty())

        binding.connectButton.setOnClickListener {
            if (TboxVpnService.state == TboxVpnService.State.IDLE) {
                requestNotificationsThenPrepare()
            } else {
                TboxVpnService.stop(this)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        TboxVpnService.listener = { state, error -> runOnUiThread { render(state, error) } }
        render(TboxVpnService.state, null)
    }

    override fun onPause() {
        super.onPause()
        TboxVpnService.listener = null
    }

    private fun requestNotificationsThenPrepare() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else connect()
    }

    private fun connect() {
        val token = binding.tokenInput.text?.toString()?.trim().orEmpty()
        if (token.isEmpty()) {
            render(TboxVpnService.State.IDLE, "Token is empty")
            return
        }
        try {
            Mobile.parseToken(token) // validate before starting
        } catch (e: Exception) {
            render(TboxVpnService.State.IDLE, "Invalid token: ${e.message}")
            return
        }
        Prefs.setToken(this, token)
        TboxVpnService.start(this, token)
    }

    private fun updateServerInfo(token: String) {
        binding.serverInfo.text = if (token.isBlank()) {
            ""
        } else {
            try {
                Mobile.tokenSummary(token.trim())
            } catch (e: Exception) {
                "Invalid token"
            }
        }
    }

    private fun render(state: TboxVpnService.State, error: String?) {
        val statusText = when {
            error != null -> "Error: $error"
            state == TboxVpnService.State.CONNECTING -> getString(R.string.status_connecting)
            state == TboxVpnService.State.CHECKING -> getString(R.string.status_checking)
            state == TboxVpnService.State.CONNECTED_NO_NET -> getString(R.string.status_connected_no_net)
            state == TboxVpnService.State.CONNECTED -> getString(R.string.status_connected)
            else -> getString(R.string.status_idle)
        }
        binding.statusText.text = statusText

        val hasTun = TboxVpnService.tunIp.isNotEmpty() &&
            state != TboxVpnService.State.IDLE
        binding.tunIpText.text = if (hasTun) "TUN: ${TboxVpnService.tunIp}" else ""
        binding.tunIpText.visibility = if (hasTun) android.view.View.VISIBLE else android.view.View.GONE

        val isIdle = state == TboxVpnService.State.IDLE
        binding.connectButton.setText(
            if (isIdle) R.string.connect else R.string.disconnect,
        )
        binding.tokenInput.isEnabled = isIdle
    }
}
