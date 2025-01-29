JWT 
1. สร้าง token
   เข้าเว็บ JWT เลือกภาษา java แล้วเลือกอันแรก ของ auth0
   copy dependency มาลงใน project

   สร้าง class TokenService 

@Service 
public class TokenService{

    //4. เอา key จากไฟล์ yaml มาใช้
    // ใช้ Anotation @Value() ที่เป็นของ spring.framework
    @Value("${app.token.secret}")
    private String secret; //เก็บเป็น String 1 ตัวที่ชื่อว่า secret

    @Value("${app.token.issuer}")
    private String issuer;

    public String tokenize(User user){ //1 รับเป็น user จะเอา id


      Calendar calendar = Calendar.getInstance(); //ทำใน method นะ
       calendar.add(Calendar.MINUTE,60);
       Date expiresAt = calendar.getTime();


       //2. copy format create token จากเว็บ เลือกอัลกอริทึมเป็น HMAC256 อย่าลืมเปลี่ยน
       Algorithm algorithm = Algorithm.HMAC256(secret); //5.1เอา secret ที่ทำไว้ในไฟล์ yaml มาไส่
       String token = JWT.create()
                       .withIssuer(issuer) //5.2 ไส่ issuer ที่ set จากไฟล์ yaml ว่าใครเป็นคนสร้าง
                       .withClaim("principal",user.getId) //7. ไส่ withClaim เอา id ที่จะได้จาก table มาไส่
                       .withClaim("rols",USER) 
                       .withExpiresAt(expiresAt)//8 ประกาศตัวแปร date+60 นาที ไปแล้วเอามาไส่
                       .sign(algorithm);// 6. ไส่ตัวแปร algorithm จากข้างบน
    }

    //มี create ก็ต้องมี verify
    public boolean verify(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(issuer)
                    .build();

            DecodedJWT jwt = verifier.verify(token);
            return true; //ถ้าผ่าน return true             
        }catch (Exception e){
            return false; //ถ้าไม่ผ่านก็จะ return false
        }

    }

    private Algorithm algorithm(){ //ทำ function algorithm เอาไว้ใช้หลายๆครั้ง
        return Algorithm.HMAC256(secret);
    }

}

//3. ประกาศตัวแปร secret, issuer ไว้ ในไฟล์ yaml
app:
  token:
    secret: #mySecret@2023  //เวลาจะ copy เอา path ตัวแปรไปใช้ เอาเมาส์ไปกดที่คำว่า secret มันจะขึ้นข้างล่างตัวสุดท้าย คลิ๊กขวา copy key
    issuer: BackendService // Service ใหน ใครเป็นคนส่งมา

// วิธีเรียกใช้
 ส่ง user เข้ามา
 ใช้ตอน login ใช้ในชั้น business 


//1:38:48 สรุปไล่ดูใหม่เรื่อง filter token
 2. สร้าง Filter เอาไว้ Token ที่ส่งเข้ามาในหลังบ้าน 
//ฝั่งหน้าบ้าน แปะ Token มาใน Authorization เลือก ฺBearer Token แล้วแปะ Token ไป 
//ไอ้ข้อความอยู่จะไปอยู่ใน Header ชื่อว่า Authorization value เป็น Token

//ลองเขียน interfaceclass มัน extends หรือ imprement กันแน่ มันต้อง Override ทุกตัวจริงไหม

//-- extends filther ทุก quest แล้ว เช็คว่าเป็น Bearer ไหม แล้วตัดๆ ออกมา verify


//(1:40:51 เพิ่มการ filther token ใน security config)
// -- สร้างไฟล์ TokenFilterConfigurer มาเพื่อไส่ใน security config ตรง apply
//     จะใช้ จะ filther จาก Filter ตัวนี้จากไฟล์​ TokenService แทน

//flow extends GenericFilterBean request ทุกตัวต้องเข้ามา Filter ก่อน
เข้า method doFilter
              เช็คว่าที่่แปะมากับ header มี authorization ไหม
              text ที่แปะเข้ามา ขึ้นต้นด้วย Bearer ไหม (1:49:59)
              ทำการตัด Token ออกมา
              ส่งเข้า function verify 
              get ค่า principal ค่า role ออกมา
              สร้างตัวแปร authenication เอา principal กับ role ไส่เข้าไป
              แล้ว set ลง context                        
 //1.52.12 END Part generate and check token พร้อมทวน
// - ลง dependency jwt
   - สร้าง Service ชื่อ TokenService 
     - สร้าง secret ในไฟล์ POM (ควรเปลี่ยนทุกๆ 3เดือน 4เดือน ครั้งหนึง เพื่อป้องกันการซุ่ม secret )
     - ทำ refesh token โดยใช้ context ที่บอกว่าใครกำลัง login อยู่ (1:55:26)
     - หลังจากเรา set context เสร็จแล้ว เราต้อง filter ต่อ 2:03:42
     - ส่วนตัวเอามาใช้ 2:05:37 ใช้ผ่าน context
     - ทำเป็น util คลาสนี้ผมจะไม่อนุญาติให้ทำการ new class 
     - retun เป็น Optional ป้องกันการเกิดอัตราการ error นอก exception ถ้าไม่มีก็ return เป็น Optional ไป (2:06:44)
     - สรุป JWT ว่ายากไหม จริงๆมันก็ไม่ยากมาก แค่ทำครั้งเดียวในหนึ่งโปรเจค (2:09:32)


  


     public class TokenFilter {
     public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest; //แปลง ServletRequest เป็น Httpserlet ก่อนเพราะเราคุยผ่าน  เพราะเราคุยกันผ่าน protocal Http
        String athorization = httpServletRequest.getHeader("Authorization"); //สั่ง get header ได้
        if(ObjectUtils.isEmpty(athorization)){ // เช็คว่ามีค่า Authorization ใน header
            filterChain.doFilter(servletRequest,servletResponse); //ถ้าไม่มีปล่อยผ่านไม่ทำอะไร return ออกไป
            return;
        }

        if(!athorization.startsWith("Bearer")){//value ในตัวแปร Authorization ที่แปะมาใน Header ขึ้นต้นด้วย Bearer รึป่าว
            filterChain.doFilter(servletRequest,servletResponse);
            return; //ถ้าไม่มี return ออกไป
        }

        String token = athorization.substring(7); //ตัด Token ออกมาจาก text ลำดับ 7 เป็นต้นไป
        DecodedJWT decodedJWT = tokenService.verify(token); //call function verify ใน TokenService
        
        if(decodedJWT == null){//ถ้า null ให้ return ออกไป
            filterChain.doFilter(servletRequest,servletResponse);
            return;
        }

        //ถ้าไม่ null get pricipal กับ role ออกมา
        String principal = decodedJWT.getClaim("principal").asString();//อันนี้เราเก็บเป็น user Id
        String role = decodedJWT.getClaim("role").asString();


        List<GrantedAuthority> athorities = new ArrayList<>();//บอกว่าสิทธิ์ของเค้าเป็นใคร
        athorities.add(new SimpleGrantedAuthority(role));

        //1. ใช้ function นี้สำหรับ authen ต้องใช้ตัวแปรอะไรบ้าง principal ตัวแปรตัวที่ 2 fix เป็น "protected", ตัวแปรตัวที่ 3 ไส่ role
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal,"protected",athorities);

        SecurityContext context = SecurityContextHolder.getContext();//หลังจาก athen แล้ว เรา set เข้าไปใน SecurityContext ของ Spring
        context.setAuthentication(authentication);

        //เอาไว้ TokenFilter ไปใช้ใน SecrutityConfig

        filterChain.doFilter(servletRequest,servletResponse);//filter ต่อ redirect ไปที่ปลายทางที่เขาอยากจะไป
     }


//API refesh Token
1.สร้างหน้า API 
2. ที่ business 
   ใช้  SecurityContext context = SecurityContextHolder.getContext(); //เรียก context ที่เก็บไว้ใน spring
       Authentication authentication = context.getAuthentication(); //get authenication ออกมา
       String userId = (String) authentication.getPrincipal(); //ดึง pricipal ออกมาพร้อมแปลงเป็น String 
       
       //ทีนี้ก็รู้แล้วว่า user id ใหน login อยู่ เอาไป findById
       userService.findById(userId);//ส่ง id เข้าไปหา
