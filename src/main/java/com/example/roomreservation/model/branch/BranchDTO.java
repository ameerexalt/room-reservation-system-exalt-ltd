package com.example.roomreservation.model.branch;

import com.example.roomreservation.model.room.Room;
import com.example.roomreservation.model.user.User;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class BranchDTO {

    private String name;
    private Long id;
    private Integer numberOfFloors;
}
