package com.nithish.busbooking;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

enum Role { USER, ADMIN }
enum BookingStatus { CONFIRMED, CANCELLED }

@Entity @Table(name="users")
class User {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
 @Column(nullable=false) String name;
 @Column(unique=true,nullable=false) String email;
 @Column(nullable=false) String password;
 @Enumerated(EnumType.STRING) Role role=Role.USER;
 public User(){}
}
@Entity
class Bus {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
 @Column(unique=true,nullable=false) String busNumber;
 String busName, source, destination;
 LocalTime departureTime, arrivalTime;
 int totalSeats;
 BigDecimal fare;
 public Bus(){}
}
@Entity @Table(name="bookings", uniqueConstraints=@UniqueConstraint(columnNames={"bus_id","seatNumber","travelDate"}))
class Booking {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
 @ManyToOne(optional=false) Bus bus;
 @ManyToOne(optional=false) User user;
 @Column(nullable=false) Integer seatNumber;
 @Column(nullable=false) LocalDate travelDate;
 @Column(nullable=false) String passengerName;
 @Column(nullable=false) String passengerGender;
 @Column(nullable=false) Integer passengerAge;
 LocalDateTime bookedAt=LocalDateTime.now();
 @Enumerated(EnumType.STRING) BookingStatus status=BookingStatus.CONFIRMED;
 BigDecimal amount;
 public Booking(){}
}

interface UserRepository extends org.springframework.data.jpa.repository.JpaRepository<User,Long>{ Optional<User> findByEmail(String email); }
interface BusRepository extends org.springframework.data.jpa.repository.JpaRepository<Bus,Long>{
 List<Bus> findBySourceIgnoreCaseAndDestinationIgnoreCase(String source,String destination);
}
interface BookingRepository extends org.springframework.data.jpa.repository.JpaRepository<Booking,Long>{
 List<Booking> findByBusIdAndTravelDateAndStatus(Long busId,LocalDate date,BookingStatus status);
 List<Booking> findByUserIdOrderByBookedAtDesc(Long userId);
 List<Booking> findAllByOrderByBookedAtDesc();
}

record RegisterRequest(@NotBlank String name,@Email String email,@Size(min=6) String password){}
record LoginRequest(@Email String email,@NotBlank String password){}
record AuthResponse(String token,String name,String role){}
record BusRequest(@NotBlank String busNumber,@NotBlank String busName,@NotBlank String source,@NotBlank String destination,
                  @NotNull LocalTime departureTime,@NotNull LocalTime arrivalTime,@Min(1) int totalSeats,@NotNull @DecimalMin("1") BigDecimal fare){}
record BookingRequest(@NotNull Long busId,@NotNull LocalDate travelDate,@Min(1) Integer seatNumber,
                      @NotBlank String passengerName,@NotBlank String passengerGender,@Min(1) Integer passengerAge){}

@Service
class JwtService {
 @Value("${app.jwt.secret}") String secret;
 @Value("${app.jwt.expiration}") long expiration;
 String generate(User u){ return Jwts.builder().subject(u.email).claim("role",u.role.name()).issuedAt(new Date())
   .expiration(new Date(System.currentTimeMillis()+expiration)).signWith(key()).compact(); }
 String email(String token){ return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject(); }
 boolean valid(String token){ try { Jwts.parser().verifyWith(key()).build().parseSignedClaims(token); return true;} catch(Exception e){return false;} }
 private SecretKey key(){ return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); }
}
@Service
class CustomUserDetailsService implements UserDetailsService {
 final UserRepository users; CustomUserDetailsService(UserRepository u){users=u;}
 public UserDetails loadUserByUsername(String email){ User u=users.findByEmail(email).orElseThrow(()->new UsernameNotFoundException("User not found"));
  return new org.springframework.security.core.userdetails.User(u.email,u.password,List.of(new SimpleGrantedAuthority("ROLE_"+u.role.name()))); }
}
@Component
class JwtFilter extends OncePerRequestFilter {
 final JwtService jwt; final CustomUserDetailsService uds;
 JwtFilter(JwtService j,CustomUserDetailsService u){jwt=j;uds=u;}
 protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws IOException,jakarta.servlet.ServletException{
  String h=req.getHeader("Authorization");
  if(h!=null&&h.startsWith("Bearer ")){String t=h.substring(7); if(jwt.valid(t)&&SecurityContextHolder.getContext().getAuthentication()==null){
   String e=jwt.email(t); UserDetails d=uds.loadUserByUsername(e);
   var a=new UsernamePasswordAuthenticationToken(d,null,d.getAuthorities()); SecurityContextHolder.getContext().setAuthentication(a);}}
  chain.doFilter(req,res);
 }
}
@Configuration
class SecurityConfig {
 final JwtFilter filter; SecurityConfig(JwtFilter f){filter=f;}
 @Bean PasswordEncoder encoder(){return new BCryptPasswordEncoder();}
 @Bean AuthenticationManager authManager(AuthenticationConfiguration c)throws Exception{return c.getAuthenticationManager();}
 @Bean SecurityFilterChain security(HttpSecurity http)throws Exception{
  return http.csrf(c->c.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .authorizeHttpRequests(a->a.requestMatchers("/","/index.html","/css/**","/js/**","/api/auth/**","/api/buses/search","/api/buses/*/seats").permitAll()
   .requestMatchers("/api/admin/**").hasRole("ADMIN").anyRequest().authenticated())
   .addFilterBefore(filter,UsernamePasswordAuthenticationFilter.class).build();
 }
}

@RestController @RequestMapping("/api/auth")
class AuthController {
 final UserRepository users; final PasswordEncoder enc; final AuthenticationManager auth; final JwtService jwt;
 AuthController(UserRepository u,PasswordEncoder e,AuthenticationManager a,JwtService j){users=u;enc=e;auth=a;jwt=j;}
 @PostMapping("/register") ResponseEntity<?> register(@Valid @RequestBody RegisterRequest r){
  if(users.findByEmail(r.email().toLowerCase()).isPresent()) return ResponseEntity.badRequest().body(Map.of("message","Email already registered"));
  User u=new User();u.name=r.name().trim();u.email=r.email().toLowerCase();u.password=enc.encode(r.password());users.save(u);
  return ResponseEntity.status(201).body(new AuthResponse(jwt.generate(u),u.name,u.role.name()));
 }
 @PostMapping("/login") ResponseEntity<?> login(@Valid @RequestBody LoginRequest r){
  try{auth.authenticate(new UsernamePasswordAuthenticationToken(r.email().toLowerCase(),r.password()));
   User u=users.findByEmail(r.email().toLowerCase()).orElseThrow();
   return ResponseEntity.ok(new AuthResponse(jwt.generate(u),u.name,u.role.name()));
  }catch(Exception e){return ResponseEntity.status(401).body(Map.of("message","Invalid email or password"));}}
}

@RestController @RequestMapping("/api/buses")
class BusController {
 final BusRepository buses; final BookingRepository bookings;
 BusController(BusRepository b,BookingRepository br){buses=b;bookings=br;}
 @GetMapping("/search") List<Bus> search(@RequestParam String source,@RequestParam String destination){
  return buses.findBySourceIgnoreCaseAndDestinationIgnoreCase(source.trim(),destination.trim());
 }
 @GetMapping List<Bus> all(){return buses.findAll();}
 @GetMapping("/{id}/seats") Map<String,Object> seats(@PathVariable Long id,@RequestParam LocalDate date){
  Bus b=buses.findById(id).orElseThrow(); List<Integer> taken=bookings.findByBusIdAndTravelDateAndStatus(id,date,BookingStatus.CONFIRMED).stream().map(x->x.seatNumber).toList();
  return Map.of("busId",id,"totalSeats",b.totalSeats,"bookedSeats",taken);
 }
}

@RestController @RequestMapping("/api/bookings")
class BookingController {
 final BookingRepository bookings; final BusRepository buses; final UserRepository users;
 BookingController(BookingRepository br,BusRepository b,UserRepository u){bookings=br;buses=b;users=u;}
 @PostMapping @Transactional ResponseEntity<?> book(@Valid @RequestBody BookingRequest r,Authentication a){
  User u=users.findByEmail(a.getName()).orElseThrow(); Bus bus=buses.findById(r.busId()).orElseThrow();
  if(r.seatNumber()>bus.totalSeats) return ResponseEntity.badRequest().body(Map.of("message","Invalid seat number"));
  if(r.travelDate().isBefore(LocalDate.now())) return ResponseEntity.badRequest().body(Map.of("message","Travel date cannot be in the past"));
  boolean taken=bookings.findByBusIdAndTravelDateAndStatus(bus.id,r.travelDate(),BookingStatus.CONFIRMED).stream().anyMatch(x->x.seatNumber.equals(r.seatNumber()));
  if(taken)return ResponseEntity.status(409).body(Map.of("message","Seat was just booked. Please select another seat."));
  Booking b=new Booking();b.bus=bus;b.user=u;b.seatNumber=r.seatNumber();b.travelDate=r.travelDate();b.passengerName=r.passengerName();b.passengerGender=r.passengerGender();b.passengerAge=r.passengerAge();b.amount=bus.fare;
  try{return ResponseEntity.status(201).body(bookings.save(b));}catch(Exception e){return ResponseEntity.status(409).body(Map.of("message","Seat is no longer available"));}
 }
 @GetMapping("/my") List<Booking> mine(Authentication a){User u=users.findByEmail(a.getName()).orElseThrow();return bookings.findByUserIdOrderByBookedAtDesc(u.id);}
 @PutMapping("/{id}/cancel") ResponseEntity<?> cancel(@PathVariable Long id,Authentication a){
  User u=users.findByEmail(a.getName()).orElseThrow(); Booking b=bookings.findById(id).orElseThrow();
  if(!b.user.id.equals(u.id)&&u.role!=Role.ADMIN)return ResponseEntity.status(403).body(Map.of("message","Not allowed"));
  if(b.status==BookingStatus.CANCELLED)return ResponseEntity.badRequest().body(Map.of("message","Already cancelled"));
  b.status=BookingStatus.CANCELLED;bookings.save(b);return ResponseEntity.ok(Map.of("message","Booking cancelled successfully"));
 }
}

@RestController @RequestMapping("/api/admin")
class AdminController {
 final BusRepository buses;final BookingRepository bookings;
 AdminController(BusRepository b,BookingRepository br){buses=b;bookings=br;}
 @GetMapping("/stats") Map<String,Object> stats(){return Map.of("totalBuses",buses.count(),"totalBookings",bookings.count(),"activeBookings",bookings.findAll().stream().filter(x->x.status==BookingStatus.CONFIRMED).count());}
 @GetMapping("/bookings") List<Booking> allBookings(){return bookings.findAllByOrderByBookedAtDesc();}
 @PostMapping("/buses") ResponseEntity<Bus> add(@Valid @RequestBody BusRequest r){return ResponseEntity.status(201).body(save(new Bus(),r));}
 @PutMapping("/buses/{id}") Bus update(@PathVariable Long id,@Valid @RequestBody BusRequest r){return save(buses.findById(id).orElseThrow(),r);}
 @DeleteMapping("/buses/{id}") void delete(@PathVariable Long id){buses.deleteById(id);}
 private Bus save(Bus b,BusRequest r){b.busNumber=r.busNumber();b.busName=r.busName();b.source=r.source();b.destination=r.destination();b.departureTime=r.departureTime();b.arrivalTime=r.arrivalTime();b.totalSeats=r.totalSeats();b.fare=r.fare();return buses.save(b);}
}

@RestControllerAdvice
class Errors {
 @ExceptionHandler(NoSuchElementException.class) ResponseEntity<?> nf(){return ResponseEntity.status(404).body(Map.of("message","Resource not found"));}
 @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class) ResponseEntity<?> validation(){return ResponseEntity.badRequest().body(Map.of("message","Please check all required fields"));}
}
