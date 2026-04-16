package edu.ucr.custompermissionprobe

import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var targetSpinner: Spinner
    private lateinit var operationSpinner: Spinner
    private lateinit var targetSummaryView: TextView
    private lateinit var uriEditText: EditText
    private lateinit var projectionEditText: EditText
    private lateinit var selectionEditText: EditText
    private lateinit var selectionArgsEditText: EditText
    private lateinit var sortOrderEditText: EditText
    private lateinit var valuesEditText: EditText
    private lateinit var resultView: TextView

    private var targets: List<ProbeTarget> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        targetSpinner = findViewById(R.id.targetSpinner)
        operationSpinner = findViewById(R.id.operationSpinner)
        targetSummaryView = findViewById(R.id.targetSummaryView)
        uriEditText = findViewById(R.id.uriEditText)
        projectionEditText = findViewById(R.id.projectionEditText)
        selectionEditText = findViewById(R.id.selectionEditText)
        selectionArgsEditText = findViewById(R.id.selectionArgsEditText)
        sortOrderEditText = findViewById(R.id.sortOrderEditText)
        valuesEditText = findViewById(R.id.valuesEditText)
        resultView = findViewById(R.id.resultView)

        targets = TargetCatalog.load(this)
        targetSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, targets)

        val operations = listOf("query", "insert", "update", "delete")
        operationSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, operations)

        findViewById<Button>(R.id.loadButton).setOnClickListener { loadSelectedTarget() }
        findViewById<Button>(R.id.runButton).setOnClickListener { runSelectedProbe() }

        if (targets.isNotEmpty()) {
            loadSelectedTarget()
        } else {
            resultView.text = "No generated targets found in assets/provider_targets.json"
        }
    }

    private fun loadSelectedTarget() {
        val target = targetSpinner.selectedItem as? ProbeTarget ?: return
        uriEditText.setText(target.uri)
        selectionEditText.setText("")
        selectionArgsEditText.setText("")
        sortOrderEditText.setText("")
        projectionEditText.setText("")
        valuesEditText.setText("")
        targetSummaryView.text = buildString {
            appendLine("Alias: ${target.alias}")
            appendLine("Defining package: ${target.definingPackage}")
            appendLine("Requesting package: ${target.requestingPackage.ifBlank { "n/a" }}")
            appendLine("Permission: ${target.customPermission}")
            appendLine("Authority: ${target.authority}")
            appendLine("Exported: ${target.exported}")
            appendLine("Attached via: ${target.permissionVia}")
            appendLine("Providers: ${target.providerClasses.joinToString()}")
            if (target.sampleRequesterUris.isNotEmpty()) {
                appendLine("Requester URI samples: ${target.sampleRequesterUris.joinToString()}")
            }
            if (target.notes.isNotBlank()) {
                appendLine("Notes: ${target.notes}")
            }
        }
    }

    private fun runSelectedProbe() {
        val operation = operationSpinner.selectedItem?.toString() ?: "query"
        val target = targetSpinner.selectedItem as? ProbeTarget
        val uriText = uriEditText.text?.toString()?.trim().orEmpty()
        if (uriText.isBlank()) {
            resultView.text = "Target URI is empty."
            return
        }
        val uri = Uri.parse(uriText)
        val projection = projectionEditText.text?.toString().orEmpty()
            .split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toTypedArray()
            .takeIf { it.isNotEmpty() }
        val selection = selectionEditText.text?.toString()?.trim().orEmpty().ifBlank { null }
        val selectionArgs = selectionArgsEditText.text?.toString().orEmpty()
            .split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toTypedArray()
            .takeIf { it.isNotEmpty() }
        val sortOrder = sortOrderEditText.text?.toString()?.trim().orEmpty().ifBlank { null }
        val values = parseContentValues(valuesEditText.text?.toString().orEmpty())

        val output = try {
            when (operation) {
                "query" -> runQuery(uri, projection, selection, selectionArgs, sortOrder)
                "insert" -> {
                    val inserted = contentResolver.insert(uri, values)
                    "insert ok\nuri=$inserted"
                }
                "update" -> {
                    val count = contentResolver.update(uri, values, selection, selectionArgs)
                    "update ok\nrows=$count"
                }
                "delete" -> {
                    val count = contentResolver.delete(uri, selection, selectionArgs)
                    "delete ok\nrows=$count"
                }
                else -> "unknown operation: $operation"
            }
        } catch (t: Throwable) {
            buildString {
                appendLine("operation=$operation")
                appendLine("uri=$uri")
                if (target != null) {
                    appendLine("alias=${target.alias}")
                    appendLine("permission=${target.customPermission}")
                }
                appendLine("error=${t.javaClass.name}: ${t.message}")
            }
        }

        resultView.text = output
    }

    private fun runQuery(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): String {
        val cursor = contentResolver.query(uri, projection, selection, selectionArgs, sortOrder)
        if (cursor == null) {
            return "query returned null cursor"
        }
        cursor.use {
            return summarizeCursor(uri, it)
        }
    }

    private fun summarizeCursor(uri: Uri, cursor: Cursor): String {
        val columns = cursor.columnNames?.toList().orEmpty()
        val rows = mutableListOf<String>()
        var count = 0
        while (cursor.moveToNext() && count < 5) {
            val values = buildList {
                for (i in columns.indices) {
                    add("${columns[i]}=${cursor.getStringSafely(i)}")
                }
            }
            rows += values.joinToString(" | ")
            count += 1
        }
        return buildString {
            appendLine("query ok")
            appendLine("uri=$uri")
            appendLine("row_count=${cursor.count}")
            appendLine("columns=${columns.joinToString()}")
            if (rows.isNotEmpty()) {
                appendLine("preview:")
                rows.forEach { appendLine(it) }
            }
        }
    }

    private fun parseContentValues(raw: String): ContentValues {
        val values = ContentValues()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && "=" in it }
            .forEach { line ->
                val idx = line.indexOf('=')
                val key = line.substring(0, idx).trim()
                val value = line.substring(idx + 1).trim()
                values.put(key, value)
            }
        return values
    }

    private fun Cursor.getStringSafely(index: Int): String {
        return try {
            when (getType(index)) {
                Cursor.FIELD_TYPE_NULL -> "null"
                Cursor.FIELD_TYPE_BLOB -> "<blob>"
                else -> getString(index) ?: "null"
            }
        } catch (_: Throwable) {
            "<unreadable>"
        }
    }
}
