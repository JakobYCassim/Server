package dev.kwasi.echoservercomplete.network

import dev.kwasi.echoservercomplete.models.ContentModel

/// This [NetworkMessageInterface] acts as an interface.
interface NetworkMessageInterface {
    fun onContent(content: ContentModel, studentId: String)
    fun onStudentConnected(studentAddress:String)
    fun onStudentsUpdated(students: List<String>)
}