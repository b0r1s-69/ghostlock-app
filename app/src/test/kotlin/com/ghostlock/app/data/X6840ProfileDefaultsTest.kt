package com.ghostlock.app.data

import android.app.Application
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The X6840 runs the exploit in-process: W3 clears seccomp inside the app
 * process, so the built-in profile must not recommend Shizuku (starting its
 * server needs a PC plus wireless ADB) and must keep the W3 clear enabled.
 *
 * Shizuku stays supported as an optional shell flow, which is why the toggle
 * still exists; it is simply no longer the suggested default.
 * See docs/W3-SECCOMP-ANALYSIS.md.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class X6840ProfileDefaultsTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val release = "6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k"

    @Test
    fun `x6840 is built in and runs without shizuku`() {
        val catalog = BuiltinProfileCatalog(context)
        assertTrue(
            "x6840 release missing from the built-in index",
            catalog.unames.contains(release),
        )
        assertFalse(
            "x6840 must not recommend Shizuku: the in-process W3 clear is the default",
            catalog.recommendShizuku.contains(release),
        )
        assertEquals(0L, catalog.builtin[release]?.get("recommend_shizuku"))
    }

    @Test
    fun `x6840 keeps the in-process w3 clear enabled`() {
        val text = AssetConfigLoader(context).load("kernel_profiles/$release.conf")
        assertTrue("built-in x6840 profile is unreadable", text.isNotEmpty())

        val document = HoconSupport.parseValue(text).asValueMap()
        assertTrue("built-in x6840 profile did not parse", document != null)

        val stages = document!!["execution"].asValueMap()?.get("stages").asValueMap()
        val attempts = (stages?.get("w3_attempts") as? Number)?.toLong()
        val chainRounds = (stages?.get("w3_chain_rounds") as? Number)?.toLong()

        assertTrue(
            "w3_attempts must stay > 0: 0 disables the in-process seccomp clear",
            attempts != null && attempts > 0,
        )
        assertTrue(
            "w3_chain_rounds must stay > 0 so a missed write is retried",
            chainRounds != null && chainRounds > 0,
        )
    }
}
