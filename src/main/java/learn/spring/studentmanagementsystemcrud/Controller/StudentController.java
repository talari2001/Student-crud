package learn.spring.studentmanagementsystemcrud.Controller;

import learn.spring.studentmanagementsystemcrud.Entity.Student;
import learn.spring.studentmanagementsystemcrud.Service.StudentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class StudentController {

    private final StudentService service;

    public StudentController(StudentService service) {
        this.service = service;
    }

    // Get all students
    @RequestMapping("/students")
    public String getAllStudents(Model model) {
        model.addAttribute("students", service.getAllStudents());
        return "students"; // students.html
    }

    // Show form to add a new student
    @RequestMapping("/students/add")
    public String addStudentForm(Model model) {
        Student student = new Student();
        model.addAttribute("student", student);
        return "add-student"; // add-student.html
    }

    // Handle POST request to add a student
    @PostMapping("/students")
    public String addStudent(@ModelAttribute("student") Student student) {
        service.addStudent(student);
        return "redirect:/students";
    }

    // Delete a student
    @RequestMapping("/students/remove/{id}")
    public String deleteStudent(@PathVariable("id") long id) throws Exception {
        service.deleteStudent(id);
        return "redirect:/students";
    }

    // Show form to update student
    @GetMapping("/students/update/{id}")
    public String updateStudentForm(@PathVariable("id") Long id, Model model) throws Exception {
        Student student = service.getStudentById(id);
        model.addAttribute("student", student);
        return "update-student"; // update-student.html
    }

    // Handle POST request to update student
    @PostMapping("/students/{id}")
    public String editStudent(@PathVariable Long id, @ModelAttribute("student") Student student) {
        Student existingStudent = service.getStudentById(id);
        existingStudent.setId(id);
        existingStudent.setfName(student.getfName());
        existingStudent.setlName(student.getlName());
        existingStudent.setEmail(student.getEmail());

        service.updateStudent(existingStudent);
        return "redirect:/students";
    }

    // NEW: View student details
    @GetMapping("/students/view/{id}")
    public String viewStudent(@PathVariable("id") Long id, Model model) {
        Student student = service.getStudentById(id);
        model.addAttribute("student", student);
        return "view-student"; // view-student.html
    }
}
