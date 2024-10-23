package dev.kwasi.echoservercomplete.student

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import dev.kwasi.echoservercomplete.R



class StudentAdapter(private var students: List<String>, private val adapter: StudentAdapterInterface
): RecyclerView.Adapter<StudentAdapter.StudentViewHolder>(){



    //assigns view to textview in layout file
    class StudentViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val studentView: TextView = itemView.findViewById(R.id.StudentId)
    }

    //process creation of List in UI and instantiate elements
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): StudentViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.student_item, parent, false)
        return StudentViewHolder(view)
    }
    //binds text to studentId
    override fun onBindViewHolder(holder: StudentViewHolder, position: Int) {
        val student = students[position]
        holder.studentView.text = student

        holder.itemView.setOnClickListener { adapter.onStudentClicked(student)  }
    }

    override fun getItemCount(): Int {
        return students.size
    }

    fun updateStudents(newStudents:List<String>) {
        this.students = newStudents
        notifyDataSetChanged()
    }

}