package edu.ucr.custompermissionprobe

import android.content.Context
import org.json.JSONArray

object TargetCatalog {
    fun load(context: Context): List<ProbeTarget> {
        val raw = try {
            context.assets.open("provider_targets.json").bufferedReader().use { it.readText() }
        } catch (_: Throwable) {
            "[]"
        }
        val items = JSONArray(raw)
        val targets = mutableListOf<ProbeTarget>()
        for (i in 0 until items.length()) {
            val obj = items.getJSONObject(i)
            targets += ProbeTarget(
                alias = obj.getString("alias"),
                customPermission = obj.getString("custom_permission"),
                definingPackage = obj.getString("defining_package"),
                requestingPackage = obj.optString("requesting_package"),
                authority = obj.getString("authority"),
                uri = obj.getString("uri"),
                exported = obj.optBoolean("exported", false),
                permissionVia = obj.optString("permission_via"),
                providerClasses = obj.getJSONArray("provider_classes").toStringList(),
                sampleRequesterUris = obj.getJSONArray("sample_requester_uris").toStringList(),
                notes = obj.optString("notes")
            )
        }
        return targets
    }

    private fun JSONArray.toStringList(): List<String> {
        val values = mutableListOf<String>()
        for (i in 0 until length()) {
            values += optString(i)
        }
        return values.filter { it.isNotBlank() }
    }
}
