package learn.spring.studentmanagementsystemcrud.Service;

import learn.spring.studentmanagementsystemcrud.Entity.Student;
import learn.spring.studentmanagementsystemcrud.repository.StudentRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service // Letting Spring know this is a service
public class StudentServiceImpl implements StudentService {
    // Service implementation of StudentService

    private final StudentRepository studentRepository;

    // Constructor-based dependency injection
    public StudentServiceImpl(StudentRepository studentRepository) {
        this.studentRepository = studentRepository;
    }

    @Override
    public List<Student> getAllStudents() {
        return studentRepository.findAll(); //findAll() returns a list of <Student>
    }

    @Override
    public Student getStudentById(Long id) { 
        return studentRepository.getReferenceById(id); // Get student by ID reference
    }

    @Override
    public Student addStudent(Student student) {
        return studentRepository.save(student); // Save new student to DB
    }

    @Override
    public void deleteStudent(Long id) {
        studentRepository.deleteById(id); // Delete student by ID
    }

    @Override
    public Student updateStudent(Student student) {
        return studentRepository.save(student); // Save (update) student data
    }
}
