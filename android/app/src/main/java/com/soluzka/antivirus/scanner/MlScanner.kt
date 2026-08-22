package com.soluzka.antivirus.scanner

import android.content.Context
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import java.io.File
import java.nio.FloatBuffer

/**
 * On-device ML malware classifier using ONNX Runtime.
 *
 * Loads all ONNX models from assets (bodmas_cnn.onnx, ember_model.onnx)
 * and classifies files as malicious or benign based on byte-level features.
 */
class MlScanner(private val context: Context) {

    data class MlResult(
        val isMalicious: Boolean,
        val confidence: Float,
        val label: String
    )

    @Volatile
    private var env: OrtEnvironment? = null

    @Volatile
    private var sessions = mutableListOf<OrtSession>()
    private var inputNames = mutableListOf<String>()
    private var outputNames = mutableListOf<String>()
    private var modelNames = mutableListOf<String>()

    @Volatile
    private var loaded = false

    /**
     * Load all ONNX models from assets. Call this on a background thread.
     */
    fun loadModels() {
        if (loaded) return
        try {
            env = OrtEnvironment.getEnvironment()
            val assets = context.assets
            val modelFiles = assets.list("models")?.filter { it.endsWith(".onnx") } ?: emptyList()

            for (modelFile in modelFiles) {
                try {
                    val modelBytes = assets.open("models/$modelFile").use { it.readBytes() }
                    val opts = OrtSession.SessionOptions().apply {
                        setIntraOpNumThreads(2)
                        setOptimizationLevel(OrtSession.SessionOptions.OptLevel.BASIC_OPT)
                    }
                    val session = env?.createSession(modelBytes, opts) ?: continue
                    sessions.add(session)
                    inputNames.add(session.inputNames.first())
                    outputNames.add(session.outputNames.first())
                    modelNames.add(modelFile)
                } catch (e: Exception) {
                    // Skip this model — don't crash
                }
            }
            loaded = true
        } catch (e: Exception) {
            loaded = true  // Mark as attempted even if failed
        }
    }

    /** Compatibility method. */
    fun loadModel(assetName: String = "models/bodmas_cnn.onnx") {
        loadModels()
    }

    /**
     * Classify a file as malicious or benign.
     */
    fun classifyFile(file: File): MlResult? {
        if (sessions.isEmpty()) return null
        if (!file.exists() || !file.isFile) return null

        val maxBytes = 1_048_576
        val bytes = try {
            file.inputStream().use { stream ->
                val buf = ByteArray(maxBytes)
                val read = stream.read(buf)
                buf.copyOf(read)
            }
        } catch (e: Exception) {
            return null
        }

        val histogram = FloatArray(256)
        for (b in bytes) {
            histogram[b.toInt() and 0xFF]++
        }
        val total = bytes.size.toFloat()
        if (total > 0) {
            for (i in histogram.indices) histogram[i] /= total
        }

        var bestResult: MlResult? = null
        for (i in sessions.indices) {
            val result = classifyWithModel(histogram, i, modelNames[i])
            if (result != null) {
                if (result.isMalicious && (bestResult == null || result.confidence > bestResult.confidence)) {
                    bestResult = result
                } else if (bestResult == null) {
                    bestResult = result
                }
            }
        }
        return bestResult
    }

    private fun classifyWithModel(features: FloatArray, index: Int, modelName: String): MlResult? {
        val sess = sessions.getOrNull(index) ?: return null
        val environment = env ?: return null
        val inputName = inputNames.getOrNull(index) ?: return null
        val outputName = outputNames.getOrNull(index) ?: return null

        var inputTensor: OnnxTensor? = null
        var results: OrtSession.Result? = null
        return try {
            val shape = longArrayOf(1, features.size.toLong())
            inputTensor = OnnxTensor.createTensor(environment, FloatBuffer.wrap(features), shape)
            results = sess.run(mapOf(inputName to inputTensor))

            // Get output value safely
            val outputObj = results[outputName]
            val outputBuffer = if (outputObj is OnnxTensor) {
                outputObj.floatBuffer
            } else {
                null
            }

            if (outputBuffer != null) {
                // Read available floats (may be 1 or 2)
                val remaining = outputBuffer.remaining()
                val probs = FloatArray(remaining)
                outputBuffer.get(probs)

                val maliciousProb = if (remaining >= 2) probs[0] else probs.getOrElse(0) { 0f }
                val isMalicious = maliciousProb > 0.5f
                val confidence = if (isMalicious) maliciousProb else (1f - maliciousProb)
                val label = if (isMalicious) "Malware ($modelName)" else "Benign"
                MlResult(isMalicious, confidence, label)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        } finally {
            try { results?.close() } catch (_: Exception) {}
            try { inputTensor?.close() } catch (_: Exception) {}
        }
    }

    fun isLoaded(): Boolean = loaded && sessions.isNotEmpty()

    fun getModelCount(): Int = sessions.size

    fun getModelNames(): List<String> = modelNames.toList()

    fun close() {
        sessions.forEach { try { it.close() } catch (_: Exception) {} }
        sessions.clear()
        loaded = false
    }
}
