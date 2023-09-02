using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using TodoAPI.Data;

public static class SeedUserService
{
    public static async Task SeedDatabaseAsync(IServiceProvider serviceProvider)
    {
        using (var scope = serviceProvider.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApiDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Roles
            if (!dbContext.Roles.Any())
            {
                Console.WriteLine($"->🍃 Roles seeding to Db...");

                await roleManager.CreateAsync(new IdentityRole("Admin"));
                await roleManager.CreateAsync(new IdentityRole("AppUser"));
            }

            // Kullanıcıların eklenmesi
            if (!dbContext.Users.Any())
            {
                var user = new IdentityUser
                {
                    UserName = "Admin",
                    Email = "Admin@mail.com"
                };

                await userManager.CreateAsync(user, "Admin1234!");

                // Kullanıcıya rol atama
                await userManager.AddToRoleAsync(user, "Admin");

                // Diğer claim'leri eklemek için IdentityUserClaims tablosunu kullanabilirsiniz.
                await userManager.AddClaimAsync(user, new Claim(ClaimTypes.Role, "Admin"));            
            }
        }
    }
}
