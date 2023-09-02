using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TodoAPI.Config;
using TodoAPI.Data;
using TodoAPI.Dtos.Auth;
using TodoAPI.Dtos.Auth.Request;
using TodoAPI.Dtos.Auth.Response;
using TodoAPI.Models;

namespace TodoAPI.Services;

public class JwtService : IJwtService
{
    private readonly JwtConfig _jwtConfig;
    private readonly ApiDbContext _context;
    private readonly TokenValidationParameters _tokenValidationParameters;

    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;
    public JwtService(IOptionsMonitor<JwtConfig> jwtConfig, ApiDbContext context, TokenValidationParameters tokenValidationParameters, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _jwtConfig = jwtConfig.CurrentValue;
        _context = context;
        _tokenValidationParameters = tokenValidationParameters;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<AuthResult> GenerateToken(IdentityUser user)
    {

        JwtSecurityTokenHandler? jwtTokenHandler = new JwtSecurityTokenHandler();

        byte[] key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

        var claims = await GetAllValidClaims(user);

        SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddSeconds(35),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        // Create token
        SecurityToken? token = jwtTokenHandler.CreateToken(tokenDescriptor);
        string jwtToken = jwtTokenHandler.WriteToken(token);

        // Create refresh token
        RefreshToken refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            IsUsed = false,
            IsRevoked = false,
            UserId = user.Id,
            CreatedAt = DateTime.UtcNow,
            ExpiredAt = DateTime.UtcNow.AddMonths(1),
            Token = GetRandomString() + Guid.NewGuid()
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();



        return new AuthResult()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            Success = true,

        };

    }

    public async Task<RefreshTokenResponseDTO> VerifyToken(TokenRequestDTO tokenRequest)
    {
        JwtSecurityTokenHandler? jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            ////////////////
            RefreshToken? storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == tokenRequest.RefreshToken);
            if (storedToken == null)
            {
                return new RefreshTokenResponseDTO()
                {
                    Success = false,
                    Errors = new List<string>{
                     "token does not found"
                    }
                };
            }
            ClaimsPrincipal? tokenVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken); //?

            ////////////////
            var jti = tokenVerification.Claims.FirstOrDefault(t => t.Type == JwtRegisteredClaimNames.Jti).Value;

            if (storedToken.JwtId != jti)
            {
                return new RefreshTokenResponseDTO()
                {
                    Success = false,
                    Errors = new List<string>{
                     "token doesn't match"
                    }
                };
            }

            //////////////////
            long utcExpireDate = long.Parse(tokenVerification.Claims.FirstOrDefault(d => d.Type == JwtRegisteredClaimNames.Exp).Value);

            // UTC to DateTime
            DateTime expireDate = UTCtoDateTime(utcExpireDate);

            Console.WriteLine($"expireDate: {expireDate} - now: {DateTime.UtcNow}");

            if (expireDate > DateTime.UtcNow)
            {
                return new RefreshTokenResponseDTO()
                {
                    Success = false,
                    Errors = new List<string>{
                        "Token not expired"
                    }
                };
            }

            //////////////////
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                bool result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);//?

                if (!result)
                {
                    return null;
                }
            }
            //////////////////
            if (storedToken.IsUsed)
            {
                return new RefreshTokenResponseDTO()
                {
                    Success = false,
                    Errors = new List<string>{
                     "token used."
                    }
                };
            }
            ////////////////
            if (storedToken.IsRevoked)
            {
                return new RefreshTokenResponseDTO()
                {
                    Success = false,
                    Errors = new List<string>{
                     "token revoked."
                    }
                };
            }

            ////////////////
            storedToken.IsUsed = true;
            _context.RefreshTokens.Update(storedToken);
            await _context.SaveChangesAsync();

            // return token
            return new RefreshTokenResponseDTO()
            {
                UserId = storedToken.UserId,
                Success = true,
            };
        }
        catch (Exception e)
        {

            return new RefreshTokenResponseDTO()
            {
                Errors = new List<string>{
                    e.Message
                },
                Success = false
            };
        }



    }

    private DateTime UTCtoDateTime(long unixTimeStamp)
    {
        var datetimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        datetimeVal = datetimeVal.AddSeconds(unixTimeStamp).ToLocalTime();

        return datetimeVal;
    }

    private string GetRandomString()
    {
        Random random = new Random();
        string chars = "ABCDEFGHIJKLMNOPRSTUVYZWX0123456789";
        return new string(Enumerable.Repeat(chars, 35).Select(n => n[new Random().Next(n.Length)]).ToArray());

    }

    private async Task<List<Claim>> GetAllValidClaims(IdentityUser user)
    {
        List<Claim> claims = new List<Claim>
        {
            new Claim("Id", user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

        };

        var userClaims = await _userManager.GetClaimsAsync(user);
        claims.AddRange(userClaims);

        var userRoles = await _userManager.GetRolesAsync(user);

        foreach (var userRole in userRoles)
        {
            var role = await _roleManager.FindByNameAsync(userRole);

            if (role != null)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var roleClaim in roleClaims)
                {
                    claims.Add(roleClaim);
                }
            }
        }

        return claims;

    }
}
