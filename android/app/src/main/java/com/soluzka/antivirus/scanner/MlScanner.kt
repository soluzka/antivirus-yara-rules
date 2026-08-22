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
 * Loads the bodmas_cnn.onnx model from assets and classifies files
 * as malicious or benign based on byte-level features.
 */
class MlScanner(private val context: Context) {

    data class MlResult(
        val isMalicious: Boolean,
        val confidence: Float,
        val label: String
    )

    private var env: OrtEnvironment? = null
    private var sessions = mutableListOf<OrtSession>()
    private var inputNames = mutableListOf<String>()
    private var outputNames = mutableListOf<String>()
    private var modelNames = mutableListOf<String>()

    /**
     * Load all ONNX models from assets.
     */
    fun loadModels() {
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
                    // Skip this model
                }
            }
        } catch (e: Exception) {
            // Model load failed — ML scanning will be disabled
        }
    }

    /** Legacy single-model loader. */
    fun loadModel(assetName: String = "models/bodmas_cnn.onnx") {
        loadModels()
    }

    /**
     * Classify a file as malicious or benign.
     *
     * Extracts byte histogram features (256 bins) from the file and
     * feeds them to the ONNX model.
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

        // Run through all loaded models, return the most confident malicious result
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

        return try {
            val shape = longArrayOf(1, features.size.toLong())
            val inputTensor = OnnxTensor.createTensor(environment, FloatBuffer.wrap(features), shape)
            val results = sess.run(mapOf(inputName to inputTensor))
            val output = results[outputName] as? OnnxTensor
            val outputBuffer = output?.floatBuffer

            if (outputBuffer != null) {
                val probs = FloatArray(2)
                outputBuffer.get(probs)
                results.close()

                val maliciousProb = if (probs.size >= 2) probs[0] else probs[0]
                val isMalicious = maliciousProb > 0.5f
                val confidence = if (isMalicious) maliciousProb else (1f - maliciousProb)
                val label = if (isMalicious) "Malware ($modelName)" else "Benign"
                MlResult(isMalicious, confidence, label)
            } else {
                results.close()
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    fun isLoaded(): Boolean = sessions.isNotEmpty()

    fun getModelCount(): Int = sessions.size

    fun getModelNames(): List<String> = modelNames

    fun close() {
        sessions.forEach { it.close() }
        sessions.clear()
    }
}
