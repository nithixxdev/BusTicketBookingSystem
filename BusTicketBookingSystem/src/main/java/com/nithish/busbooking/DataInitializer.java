package com.nithish.busbooking;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.math.BigDecimal;
import java.time.LocalTime;

@Configuration
class DataInitializer {
 @Bean CommandLineRunner init(UserRepository users, BusRepository buses, PasswordEncoder encoder){
  return args->{
   if(users.findByEmail("admin@busgo.com").isEmpty()){User a=new User();a.name="System Admin";a.email="admin@busgo.com";a.password=encoder.encode("Admin@123");a.role=Role.ADMIN;users.save(a);}
   if(buses.count()==0){
    add(buses,"TN01AB1234","BusGo Express","Chennai","Bengaluru","08:00","14:00",40,"850");
    add(buses,"TN02CD5678","Southern Star","Chennai","Coimbatore","09:30","17:00",45,"700");
    add(buses,"TN03EF9012","Night Rider","Bengaluru","Chennai","22:00","05:30",40,"950");
    add(buses,"TN04GH3456","Royal Travels","Madurai","Chennai","07:00","15:00",50,"800");
   }
  };
 }
 void add(BusRepository r,String n,String name,String s,String d,String dep,String arr,int seats,String fare){Bus b=new Bus();b.busNumber=n;b.busName=name;b.source=s;b.destination=d;b.departureTime=LocalTime.parse(dep);b.arrivalTime=LocalTime.parse(arr);b.totalSeats=seats;b.fare=new BigDecimal(fare);r.save(b);}
}