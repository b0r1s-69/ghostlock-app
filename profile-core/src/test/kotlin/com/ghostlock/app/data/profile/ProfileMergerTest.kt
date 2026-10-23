package com.ghostlock.app.data.profile

import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.valueMapOf
import org.junit.Assert.assertEquals
import org.junit.Test

class ProfileMergerTest {
    @Test
    fun `sparse route group is filled field-wise from the preset`() {
        val profile = valueMapOf(
            "execution" to valueMapOf(
                "routes" to valueMapOf(
                    "select_stack" to valueMapOf("enter_delay_us" to 1L),
                ),
            ),
        )
        val preset = valueMapOf("enter_delay_us" to 50000L, "timeout_us" to 200000L)
        ProfileMerger.fillRouteExecutionDefaults(profile, mapOf("select_stack" to preset))

        val group = profile["execution"].asValueMap()!!["routes"].asValueMap()!!
            .get("select_stack").asValueMap()!!
        assertEquals(1L, group["enter_delay_us"])   // explicit value preserved
        assertEquals(200000L, group["timeout_us"])  // missing field filled from preset
    }

    /* Regression: resolveMerged used to store the caller's tuning map by
     * reference and merge into it, so the first device profile that overrode a
     * stage leaked that value into every profile resolved afterwards (the
     * exporter writes all profiles in one process, and the app resolves on each
     * load). */
    @Test
    fun `resolving a profile does not mutate the shared tuning preset`() {
        val tuning = valueMapOf(
            "stages" to valueMapOf("w3_chain_rounds" to 3L, "w3_attempts" to 6L),
        )
        val preset = valueMapOf("enter_delay_us" to 50000L)
        val routePresets = mapOf("select_stack" to preset)

        val overriding = valueMapOf(
            "release" to "overriding",
            "kernel_major" to 6L,
            "execution" to valueMapOf("stages" to valueMapOf("w3_chain_rounds" to 2L)),
        )
        ProfileMerger.resolveMerged(
            deviceRelease = "overriding",
            builtin = overriding,
            imported = null,
            overrides = null,
            tuningExecution = tuning,
            pair = CpuPairView(0, 1),
            routePresets = routePresets,
        )

        val stages = tuning["stages"].asValueMap()!!
        assertEquals("tuning stages mutated", 3L, stages["w3_chain_rounds"])
        assertEquals("tuning stages mutated", 6L, stages["w3_attempts"])

        /* The next profile with no execution block must still see the preset. */
        val plain = valueMapOf("release" to "plain", "kernel_major" to 6L)
        val resolved = ProfileMerger.resolveMerged(
            deviceRelease = "plain",
            builtin = plain,
            imported = null,
            overrides = null,
            tuningExecution = tuning,
            pair = CpuPairView(0, 1),
            routePresets = routePresets,
        )
        val resolvedStages = resolved["execution"].asValueMap()!!["stages"].asValueMap()!!
        assertEquals("later profile inherited the override", 3L, resolvedStages["w3_chain_rounds"])

        /* Filling a route group must not alias the shared preset either. */
        val group = resolved["execution"].asValueMap()!!["routes"].asValueMap()!!
            .get("select_stack").asValueMap()!!
        group["enter_delay_us"] = 1L
        assertEquals("route preset aliased into the result", 50000L, preset["enter_delay_us"])
    }

    @Test
    fun `cpu pair outranks an imported selected_cpus`() {
        val imported = valueMapOf(
            "execution" to valueMapOf(
                "selected_cpus" to valueMapOf("main" to 7L, "consumer" to 8L),
            ),
        )
        val builtin = valueMapOf(
            "release" to "r",
            "kernel_major" to 6L,
            "execution" to valueMapOf(),
        )
        val resolved = ProfileMerger.resolveMerged(
            deviceRelease = "r",
            builtin = builtin,
            imported = imported,
            overrides = null,
            tuningExecution = null,
            pair = CpuPairView(3, 4),
            routePresets = emptyMap(),
        )
        val selected = resolved["execution"].asValueMap()!!["selected_cpus"].asValueMap()!!
        assertEquals(3L, selected["main"])
        assertEquals(4L, selected["consumer"])
    }
}
