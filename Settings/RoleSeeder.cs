using Microsoft.AspNetCore.Identity;

namespace TodoAPI.Settings;

public static class RoleSeeder
{

    public static void InitializeRoles(RoleManager<IdentityRole> roleManager)
    {
        // Rollerinizi oluşturun veya varsa atlamak için kontrol edin
        List<string> roles = new() { "Admin", "AppUser" };

        foreach (var role in roles)
        {
            if (!roleManager.RoleExistsAsync(role).Result)
            {
                var adminRole = new IdentityRole { Name = role };
                var result = roleManager.CreateAsync(adminRole).Result;
                if (result.Succeeded)
                {
                    Console.WriteLine($"-> Role {role} was seeded the Db");
                }
            }
        }
    }
}



