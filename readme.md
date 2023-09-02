# .NET 6 API JWT AUTHORIZATION 

Bu proje, .NET 6 kullanarak oluşturulan bir API içerir ve JWT kimlik doğrulama ve yetkilendirme işlemlerini içerir.

### Tech Stack 
.NET 6 Core, SQLite Database, JWT Tokens, Entity Framework, Entity Framework Identity


## JWT Kimlik Doğrulama ve Yetkilendirme

Bu projede JWT kullanarak kimlik doğrulama ve yetkilendirme işlemleri gerçekleştirilir. JWT ayarları `appsettings.json` dosyasında yapılandırılabilir.

- `Issuer`: JWT'nin oluşturucusu.
- `Audience`: JWT'nin hedef kitlesi.
- `Secret`: JWT'nin imzalanması için kullanılacak gizli anahtar.

JWT doğrulama ve yetkilendirme ayarlarına `Program.cs` dosyasında erişim sağlanmıştır.

## API Endpointleri

API endpointleri aşağıdaki gibidir:

auth:
-
- `POST /api/auth/register`: Kullanıcı kaydı yapar.
- `POST /api/auth/login`: Kullanıcı girişi yapar.
- `POST /api/auth/refreshtoken`: JWT token yenileme.

todo:
-

- `GET    - /api/todo`
- `GET    - /api/todo/{id}`
- `PUT    - /api/todo/{id}`
- `POST   - /api/todo`
- `DELETE - /api/todo/{id}`


## Roles and Claims

Default olarak **Admin** ve **AppUser** olmak üzere iki adet role bulunmaktadır. Kullanıcılar kayıt
olduklarında, kullanıcılara default olarak "AppUser" rolü verilmektedir. Ayrıca roles tablosuna Admin
için "Admin" rolüyle bir kullanıcı seed olmaktadır.

Kullanıcı kayıt olduğunda, Kullanıcıya "Type" Claim tanımlanmaktadır. Kullanıcılar için bu Claim "DefaultAppUser" olarak verilmektedir.
bu claim, `TodoController.cs` rotalarında erişim için gerekli policy olarak şart koşulmuştur. gerekli Policy konfigrasyonları `program.cs` üzerinde 
yapılmıştır:

```csharp
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("TypePolicy",
                    policy => policy.RequireClaim("Type"));
});
```
TodoController.cs;

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "AppUser", Policy = "TypePolicy")]
public class TodoController : ControllerBase
{
```
## Güvenlik İpuçları

- Kullanıcı parolalarını güvenli bir şekilde saklayın.
- JWT güvenliği için gizli anahtarınızı koruyun.
- API endpointlerini yetkilendirmek için rolleri ve izinleri yönetin.

## Daha Fazla Bilgi

Daha fazla bilgi için proje kodunu inceleyin.
