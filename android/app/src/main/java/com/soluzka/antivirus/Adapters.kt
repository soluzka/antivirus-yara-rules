package com.soluzka.antivirus

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.soluzka.antivirus.scanner.FileScanner
import com.soluzka.antivirus.scanner.QuarantineManager

class ThreatAdapter : RecyclerView.Adapter<ThreatAdapter.ViewHolder>() {

    private val threats = mutableListOf<FileScanner.ScanResult>()

    fun update(items: List<FileScanner.ScanResult>) {
        threats.clear()
        threats.addAll(items)
        notifyDataSetChanged()
    }

    fun add(item: FileScanner.ScanResult) {
        threats.add(0, item)
        notifyItemInserted(0)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_2, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val t = threats[position]
        holder.title.text = "⚠ ${t.threatName} — ${t.file.name}"
        holder.subtitle.text = "${t.severity.uppercase()} | ${formatSize(t.fileSize)} | ${t.file.absolutePath}"
    }

    override fun getItemCount(): Int = threats.size

    private fun formatSize(bytes: Long): String {
        return when {
            bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
            bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
            else -> "$bytes B"
        }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(android.R.id.text1)
        val subtitle: TextView = view.findViewById(android.R.id.text2)
    }
}

class QuarantineAdapter : RecyclerView.Adapter<QuarantineAdapter.ViewHolder>() {

    private val items = mutableListOf<QuarantineManager.QuarantineEntry>()
    private var quarantine: QuarantineManager? = null

    fun update(entries: List<QuarantineManager.QuarantineEntry>, q: QuarantineManager) {
        items.clear()
        items.addAll(entries)
        quarantine = q
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_2, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val e = items[position]
        holder.title.text = "🔒 ${e.fileName} — ${e.threatName}"
        val date = java.text.SimpleDateFormat("MMM d, HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(e.quarantinedAt))
        holder.subtitle.text = "Quarantined: $date | ${formatSize(e.fileSize)}"
    }

    override fun getItemCount(): Int = items.size

    private fun formatSize(bytes: Long): String {
        return when {
            bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
            bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
            else -> "$bytes B"
        }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(android.R.id.text1)
        val subtitle: TextView = view.findViewById(android.R.id.text2)
    }
}
