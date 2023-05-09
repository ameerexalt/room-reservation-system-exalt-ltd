package com.example.roomreservation;


import com.example.roomreservation.model.reservation.Reservation;
import com.example.roomreservation.model.user.User;
import com.example.roomreservation.service.ReservationService;
import com.example.roomreservation.service.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private UserDetailsServiceImpl userService;
    public  ReservationService reservationService;
    private HttpServletRequest request;
    private Object filterObject;
    private Object returnObject;
    private Object target;

    public CustomMethodSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    }
    /**
     checks if the authenticated user have access to the user detail with the id
     Only a user have access to his own user details or an admin
     */
    public boolean isOwner(Long id){
        Reservation reservation = reservationService.getReservationById(id);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName().equals(reservation.getOwner().getUsername()) ;
    }

    //We need this setter method to set the UserService from another class because this one dosen't have access to Application Context.

    public void setUserService(UserDetailsServiceImpl userService){
        this.userService=userService;
    }

    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getFilterObject() {
        return filterObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getReturnObject() {
        return returnObject;
    }

    @Override
    public Object getThis() {
        return target;
    }
}