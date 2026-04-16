package edu.ucr.custompermissionprobe

data class ProbeTarget(
    val alias: String,
    val customPermission: String,
    val definingPackage: String,
    val requestingPackage: String,
    val authority: String,
    val uri: String,
    val exported: Boolean,
    val permissionVia: String,
    val providerClasses: List<String>,
    val sampleRequesterUris: List<String>,
    val notes: String
) {
    override fun toString(): String = "$alias | $definingPackage | $customPermission"
}
