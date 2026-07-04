package com.juliuswwj.tbox.android

import android.content.Context

/** Minimal persistence for the last-used token. */
object Prefs {
    private const val FILE = "tbox"
    private const val KEY_TOKEN = "token"

    fun token(context: Context): String =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY_TOKEN, "") ?: ""

    fun setToken(context: Context, token: String) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().putString(KEY_TOKEN, token).apply()
    }
}
