package com.example.springapp.entity;

import lombok.*;

import javax.persistence.*;

@Entity
@Table(name = "USER_")
@Setter @Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @Column
    private String email;

    @Column
    private String firstname;

    @Column
    private String lastname;

    @Column
    @Enumerated(EnumType.STRING)
    private Gender gender;


    public enum Gender {
        MALE, FEMALE
    }

}
