# 🚌 BusGo — Online Bus Ticket Booking System

A full-stack bus ticket booking project built with **Java 17, Spring Boot, Spring Security, JWT, JPA/Hibernate, MySQL, HTML, CSS and JavaScript**.

## Features
- JWT-based registration and login
- Role-based USER and ADMIN access
- Bus route search
- Interactive seat selection
- Double-booking protection at application and database levels
- Passenger booking details
- Booking history
- Booking cancellation
- Admin statistics and bus management API
- Responsive frontend

## Requirements
- JDK 17+
- MySQL Server + MySQL Workbench
- Maven (or VS Code Java extension with Maven support)

## Setup
1. Open `src/main/resources/application.properties`.
2. Replace:
   `spring.datasource.password=YOUR_MYSQL_PASSWORD`
   with your MySQL root password.
3. Ensure MySQL is running.
4. Open a terminal in the project folder.
5. Run:
   `mvn spring-boot:run`
6. Open `http://localhost:8080`

The database `bus_booking_db` is created automatically if the MySQL account has permission.

## Default Admin
- Email: `admin@busgo.com`
- Password: `Admin@123`

Change the default credentials for any real deployment.

## Important
For a production system, secrets should be stored in environment variables, and booking concurrency should use stronger database locking strategies. This project is designed as a strong academic/portfolio application.
