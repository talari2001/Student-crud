package learn.spring.studentmanagementsystemcrud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {
        "learn.spring.studentmanagementsystemcrud.Controller",
        "learn.spring.studentmanagementsystemcrud.Entity",
        "learn.spring.studentmanagementsystemcrud.repository",
        "learn.spring.studentmanagementsystemcrud.Service"
})
public class StudentManagementSystemCrudApplication {

    public static void main(String[] args) {
        SpringApplication.run(StudentManagementSystemCrudApplication.class, args);
    }
}
