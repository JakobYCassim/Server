package dev.kwasi.echoservercomplete.network

import android.util.Log
import com.google.gson.Gson
import dev.kwasi.echoservercomplete.models.ContentModel
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Exception
import kotlin.concurrent.thread
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.text.Charsets.UTF_8

/// The [Server] class has all the functionality that is responsible for the 'server' connection.
/// This is implemented using TCP. This Server class is intended to be run on the GO.

class Server(private val iFaceImpl:NetworkMessageInterface) {
    companion object {
        const val PORT: Int = 9999

    }

    private lateinit var svrSocket: ServerSocket
    private val clientMap: HashMap<String, Socket> = HashMap()
    private val studentMessages: HashMap<String, MutableList<ContentModel>> = HashMap()
    private var serverThread : Thread? = null
    private var handleThread: Thread? = null
    @Volatile
    private var isRunning = true
    var isClosed = true

    init {
        studentMessages.clear()
        startServer()
    }
    private fun startServer() {
        if (::svrSocket.isInitialized && !svrSocket.isClosed) {
            Log.e("Server", "Server is already running.")
            return
        }
        isClosed = false
        isRunning=true
        clientMap.clear()
        iFaceImpl.onStudentsUpdated(emptyList())
        serverThread = thread {
            try {
                svrSocket = ServerSocket(PORT, 0, InetAddress.getByName("192.168.49.1"))
                Log.d("Server", "Server started on port $PORT")

                while (isRunning) {
                    try {
                        val studentSocket = svrSocket.accept()
                        Log.d("SERVER", "The server has accepted a connection from ${studentSocket.inetAddress.hostAddress}")
                        handleSocket(studentSocket)
                    } catch (e: Exception) {
                        Log.e("SERVER", "An error has occurred in the server ${e.message}! and is running is $isRunning")
                    }
                }
            } catch (e: Exception) {
                Log.e("Server", "Server Socket Error: ${e.message}")
            }
        }
    }


    private fun handleSocket(socket: Socket){
        socket.inetAddress.hostAddress?.let {

            val clientId = handshake(socket)
            if(clientId != null) {
                val eVerified = encryptionChallenge(socket, clientId)
                if(!eVerified){
                    socket.close()
                    return
                }
                clientMap[clientId] = socket
                studentMessages[clientId] = emptyList<ContentModel>().toMutableList()
                iFaceImpl.onStudentsUpdated(clientMap.keys.toList())
                iFaceImpl.onStudentConnected(socket.inetAddress?.hostAddress.toString())
                Log.e("SERVER", "A new connection has been detected!")
                handleThread = thread {

                    while(!socket.isClosed){
                        try{
                            listenForMessages(socket, clientId)
                        } catch (e: Exception){
                            Log.e("SERVER", "An error has occurred with the client $it")
                            e.printStackTrace()
                        }
                    }
                }
            }else {
                Log.e("Server", "Handshake failed with client ${socket.inetAddress.hostAddress}")
                socket.close()
            }
        }

    }

    private fun handshake(socket: Socket) : String? {
        return try{
            val reader = socket.getInputStream().bufferedReader()
            val clientData = reader.readLine()
            val clientId = Gson().fromJson(clientData, ContentModel::class.java)
            if (clientData != null && clientId.message.isNotEmpty()){
                Log.d("Server","Client with Id $clientId connected")
                clientId.message
            }else{
                null
            }
        }catch (e: Exception){
            Log.e("Server", "Handshake error ${e.message}")
            null
        }
    }

    private fun encryptionChallenge(socket: Socket, studentId: String) : Boolean{
        val hashKey = hashStrSha256(studentId)
        val aesKey = generateAESKey(hashKey)
        val aesIv = generateIV(hashKey)
        return try{
            val writer = socket.getOutputStream().bufferedWriter()
            val reader = socket.getInputStream().bufferedReader()
            val R = Random.nextInt(0, 100)
            val rContent = ContentModel("$R","192.168.49.1" )
            val challenge = Gson().toJson(rContent)
            writer.write("$challenge\n")
            writer.flush()
            val clientResponse = reader.readLine() ?: throw IOException("No response from client")
            val clientResponseStr = Gson().fromJson(clientResponse, ContentModel::class.java)
            val decryptResponse = decryptMessage(clientResponseStr.message, aesKey, aesIv )
            if(decryptResponse.toInt() == R) {
                true
            }else {
                Log.e("SERVER", "Decryption incorrect")
                false
            }
        }catch (e: Exception) {
            Log.e("SERVER", "Challenge Protocol Failed ${e.message}")
            false
        }
    }


    fun sendMessage(content: ContentModel, studentId: String){
        thread{
            val writer = clientMap[studentId]?.getOutputStream()?.bufferedWriter()
            val seed = hashStrSha256(studentId)
            val encryptContent = encryptMessage(content.message, generateAESKey(seed), generateIV(seed))
            val encryptedContent = ContentModel(encryptContent, content.senderIp)
            val contentAsStr:String = Gson().toJson(encryptedContent)
            writer?.write("$contentAsStr\n")
            writer?.flush()
            studentMessages[studentId]?.add(content)
        }
    }

    private fun listenForMessages(clientSocket: Socket, studentId: String) {
        val reader = clientSocket.getInputStream().bufferedReader()
        val hashKey = hashStrSha256(studentId)
        val aesKey = generateAESKey(hashKey)
        val aesIv = generateIV(hashKey)
        try {
            while (!clientSocket.isClosed && isRunning) {
                val receivedMessage = reader.readLine()
                if (receivedMessage != null) {
                    Log.e("Server", "Received: $receivedMessage")
                    val messageContent =Gson().fromJson(receivedMessage, ContentModel::class.java)
                    val decryptedMessage = decryptMessage(messageContent.message, aesKey, aesIv)
                    studentMessages[studentId]?.add(ContentModel(decryptedMessage, messageContent.senderIp))
                    iFaceImpl.onContent(ContentModel(decryptedMessage, messageContent.senderIp), studentId)
                }
            }
        } catch (e: Exception) {
            Log.e("Server", "Error receiving message: ${e.message}")
        }
    }



    fun close() {
        isRunning = false
        handleThread?.interrupt()
        serverThread?.interrupt()
        clientMap.values.forEach {
            try {
                it.close()
            } catch (e: Exception) {
                Log.d("Server", "Error Closing Socket ${e.message}")
            }
            svrSocket.close()
            clientMap.clear()
            studentMessages.clear()
            isClosed = true
        }
    }

    fun getStudentMessages(studentId: String) : MutableList<ContentModel>? {
        return studentMessages[studentId]
    }

    private fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte) }

    private fun getFirstNChars(str: String, n:Int) = str.substring(0,n)

    private fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex()
    }

    private fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }

    private fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun encryptMessage(plaintext: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val plainTextByteArr = plaintext.toByteArray()

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv)

        val encrypt = cipher.doFinal(plainTextByteArr)
        return Base64.Default.encode(encrypt)
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun decryptMessage(encryptedText: String, aesKey:SecretKey, aesIv: IvParameterSpec):String{
        val textToDecrypt = Base64.Default.decode(encryptedText)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)

        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)

    }
}