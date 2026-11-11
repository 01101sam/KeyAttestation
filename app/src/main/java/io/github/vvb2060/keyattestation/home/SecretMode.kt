package io.github.vvb2060.keyattestation.home

import io.github.vvb2060.keyattestation.R

/**
 * Hides values that identify this particular device (certificate subjects carrying
 * serial numbers, validity dates, attested device IDs) so results can be shared
 * as screenshots. Values are replaced with a placeholder, never with made-up data.
 */
object SecretMode {
    @Volatile
    var enabled = false

    private val sensitiveTitles = setOf(
        R.string.authorization_list_attestationIdSerial,
        R.string.authorization_list_attestationIdImei,
        R.string.authorization_list_attestationIdSecondImei,
        R.string.authorization_list_attestationIdMeid,
        R.string.unique_id,
    )

    fun hides(title: Int) = enabled && title in sensitiveTitles
}
