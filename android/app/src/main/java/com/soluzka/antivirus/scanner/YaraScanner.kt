package com.soluzka.antivirus.scanner

import android.content.Context
import java.io.File
import java.io.InputStream

/**
 * Pure Kotlin YARA rule parser and scanner.
 *
 * Supports the core YARA pattern types:
 *  - String literals: "text" (case-sensitive)
 *  - Hex patterns: { AA BB ?? CC }
 *  - Regex patterns: /pattern/
 *
 * Does not require native libyara — runs entirely in Kotlin/Java,
 * making it compatible with all Android devices.
 */
class YaraScanner(private val context: Context) {

    data class YaraMatch(
        val ruleName: String,
        val description: String,
        val tags: List<String>,
        val matchedStrings: List<String>
    )

    data class YaraRule(
        val name: String,
        val description: String,
        val tags: List<String>,
        val strings: List<RuleString>,
        val condition: String
    )

    data class RuleString(
        val identifier: String,  // $name
        val type: StringType,    // TEXT, HEX, REGEX
        val pattern: String,
        val nocase: Boolean = false,
        val wide: Boolean = false
    )

    enum class StringType { TEXT, HEX, REGEX }

    private val rules = mutableListOf<YaraRule>()

    /**
     * Load YARA rules from the app's assets directory.
     */
    fun loadRulesFromAssets(assetDir: String = "yara_rules") {
        rules.clear()
        val assets = context.assets
        val files = assets.list(assetDir) ?: return
        for (file in files) {
            if (file.endsWith(".yar") || file.endsWith(".yara")) {
                try {
                    val text = assets.open("$assetDir/$file").bufferedReader().use { it.readText() }
                    parseRules(text)
                } catch (e: Exception) {
                    // Skip unparseable files
                }
            }
        }
    }

    /**
     * Load YARA rules from a single text string.
     */
    fun loadRulesFromText(text: String) {
        rules.clear()
        parseRules(text)
    }

    /**
     * Parse YARA rule definitions from text.
     */
    private fun parseRules(text: String) {
        // Remove comments
        val cleanText = text
            .replace(Regex("/\\*[\\s\\S]*?\\*/"), "")   // block comments
            .replace(Regex("//[^\n]*"), "")               // line comments

        // Match: rule <name> [ : <tags> ] { ... }
        val ruleRegex = Regex(
            """rule\s+(\w+)\s*(?::\s*([^\n{]+))?\s*\{""",
            RegexOption.IGNORE_CASE
        )
        val matches = ruleRegex.findAll(cleanText).toList()
        for (i in matches.indices) {
            val m = matches[i]
            val ruleName = m.groupValues[1]
            val tagStr = m.groupValues[2].trim()
            val tags = if (tagStr.isNotEmpty()) tagStr.split(Regex("\\s+")) else emptyList()

            val bodyStart = m.range.last + 1
            val bodyEnd = if (i + 1 < matches.size) matches[i + 1].range.first else cleanText.length
            val body = cleanText.substring(bodyStart, bodyEnd)

            // Extract strings section
            val strings = mutableListOf<RuleString>()
            val stringRegex = Regex(
                """\$(\w+)\s*=\s*("([^"\\]*(?:\\.[^"\\]*)*)"|\{([^}]*)\}|/((?:[^/\\]|\\.)*)/[a-z]*)\s*(nocase|wide|ascii)*""",
                RegexOption.IGNORE_CASE
            )
            for (sm in stringRegex.findAll(body)) {
                val id = sm.groupValues[1]
                val textVal = sm.groupValues[3]
                val hexVal = sm.groupValues[4]
                val regexVal = sm.groupValues[5]
                val modifier = sm.groupValues[6].lowercase()

                when {
                    textVal.isNotEmpty() -> strings.add(RuleString(
                        identifier = "\$$id",
                        type = StringType.TEXT,
                        pattern = textVal,
                        nocase = modifier.contains("nocase"),
                        wide = modifier.contains("wide")
                    ))
                    hexVal.isNotEmpty() -> strings.add(RuleString(
                        identifier = "\$$id",
                        type = StringType.HEX,
                        pattern = hexVal.trim()
                    ))
                    regexVal.isNotEmpty() -> strings.add(RuleString(
                        identifier = "\$$id",
                        type = StringType.REGEX,
                        pattern = regexVal
                    ))
                }
            }

            // Extract description from meta
            val descMatch = Regex("""description\s*=\s*"([^"]*)"""", RegexOption.IGNORE_CASE)
                .find(body)
            val description = descMatch?.groupValues?.get(1) ?: ruleName

            // Extract condition
            val condMatch = Regex("""condition:\s*(.+?)(?:\n\s*rule\s|\Z)""",
                setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).find(body)
            val condition = condMatch?.groupValues?.get(1)?.trim() ?: "any of them"

            rules.add(YaraRule(ruleName, description, tags, strings, condition))
        }
    }

    /**
     * Scan a file against all loaded YARA rules.
     * Returns a list of matches.
     */
    fun scanFile(file: File): List<YaraMatch> {
        if (!file.exists() || !file.isFile) return emptyList()
        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            return emptyList()
        }
        return scanBytes(bytes, file.name)
    }

    /**
     * Scan raw bytes against all loaded YARA rules.
     */
    fun scanBytes(bytes: ByteArray, fileName: String = ""): List<YaraMatch> {
        val results = mutableListOf<YaraMatch>()
        val content = bytes.toString(Charsets.ISO_8859_1)  // raw bytes as string for pattern matching

        for (rule in rules) {
            val matchedStrings = mutableListOf<String>()
            var matchCount = 0

            for (rs in rule.strings) {
                val found = when (rs.type) {
                    StringType.TEXT -> matchText(content, rs.pattern, rs.nocase, rs.wide)
                    StringType.HEX -> matchHex(bytes, rs.pattern)
                    StringType.REGEX -> matchRegex(content, rs.pattern)
                }
                if (found) {
                    matchCount++
                    matchedStrings.add(rs.identifier)
                }
            }

            // Evaluate condition
            val matched = evaluateCondition(rule.condition, rule.strings, matchCount)
            if (matched) {
                results.add(YaraMatch(
                    ruleName = rule.name,
                    description = rule.description,
                    tags = rule.tags,
                    matchedStrings = matchedStrings
                ))
            }
        }
        return results
    }

    private fun matchText(content: String, pattern: String, nocase: Boolean, wide: Boolean): Boolean {
        val searchIn = if (nocase) content.lowercase() else content
        val searchFor = if (nocase) pattern.lowercase() else pattern
        if (searchIn.contains(searchFor)) return true
        // wide = UTF-16LE (each byte followed by \x00)
        if (wide) {
            val widePattern = pattern.toCharArray().joinToString("\u0000")
            val wideContent = if (nocase) widePattern.lowercase() else widePattern
            if (searchIn.contains(wideContent)) return true
        }
        return false
    }

    private fun matchHex(bytes: ByteArray, pattern: String): Boolean {
        // Parse hex pattern: "AA BB ?? CC" where ?? is wildcard
        val tokens = pattern.split(Regex("[\\s,]+"))
            .filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return false

        // Build a byte matcher
        val patternBytes = mutableListOf<Pair<Int, Boolean>>() // (value, isWildcard)
        for (token in tokens) {
            if (token == "??" || token == "?") {
                patternBytes.add(0 to true)
            } else if (token.length == 2) {
                val v = token.toInt(16)
                patternBytes.add(v to false)
            }
        }
        if (patternBytes.isEmpty()) return false

        // Scan bytes
        val plen = patternBytes.size
        for (i in 0..(bytes.size - plen)) {
            var match = true
            for (j in patternBytes.indices) {
                if (!patternBytes[j].second && bytes[i + j].toInt() and 0xFF != patternBytes[j].first) {
                    match = false
                    break
                }
            }
            if (match) return true
        }
        return false
    }

    private fun matchRegex(content: String, pattern: String): Boolean {
        return try {
            Regex(pattern, setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)).containsMatchIn(content)
        } catch (e: Exception) {
            false
        }
    }

    private fun evaluateCondition(condition: String, strings: List<RuleString>, matchCount: Int): Boolean {
        val cond = condition.trim().lowercase()
        return when {
            cond.contains("any of them") -> matchCount > 0
            cond.contains("all of them") -> matchCount == strings.size && strings.isNotEmpty()
            cond.contains("\$") -> {
                // Check for specific string references like $a and $b
                val refs = Regex("""\$(\w+)""").findAll(cond).map { it.groupValues[1] }.toList()
                // Simple: if all referenced strings were matched
                matchCount >= refs.size && refs.isNotEmpty()
            }
            cond.contains("any of (") -> matchCount > 0
            cond == "true" -> true
            matchCount > 0 -> true  // Default: any match = rule match
            else -> false
        }
    }

    fun getRuleCount(): Int = rules.size

    fun getRuleNames(): List<String> = rules.map { it.name }
}
