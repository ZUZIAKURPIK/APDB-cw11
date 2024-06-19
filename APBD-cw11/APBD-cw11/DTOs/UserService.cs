using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication1.DTOs;

public class UserService : IUserService
{
    private readonly UserManager<IdentityUser> _userManager;

    public UserService(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    
    public async Task<AuthenticationResult> RegisterUserAsync(UserRegisterDto model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        
        var existingUser = await _userManager.FindByNameAsync(model.Username);

        if (existingUser != null)
        {
            return new AuthenticationResult
            {
                Errors = new[] { "User with this username already exists" }
            };
        }

        var newUser = new IdentityUser { UserName = model.Username };
        var createdUser = await _userManager.CreateAsync(newUser, model.Password);

        if (!createdUser.Succeeded)
        {
            return new AuthenticationResult
            {
                Errors = createdUser.Errors.Select(x => x.Description)
            };
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("keyHandler");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id) }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new AuthenticationResult
        {
            Success = true,
            Token = tokenHandler.WriteToken(token)
        };
    }
    
    
    public async Task<AuthenticationResult> LoginUserAsync(UserLoginDto model)
{
    var user = await _userManager.FindByNameAsync(model.Username);

    if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
    {
        return new AuthenticationResult
        {
            Errors = new[] { "Invalid username/password" }
        };
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes("keyHandler");
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id) }),
        Expires = DateTime.UtcNow.AddDays(7),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);

    return new AuthenticationResult
    {
        Success = true,
        Token = tokenHandler.WriteToken(token)
    };
}

    public async Task<AuthenticationResult> RefreshTokenAsync(TokenRefreshDto model)
    {
        var principal = GetPrincipalFromExpiredToken(model.Token);
        var userId = principal.Claims.First(c => c.Type == "id").Value;
        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return new AuthenticationResult
            {
                Errors = new[] { "Invalid token" }
            };
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("your_secret_key_here"); // Replace with your secret key
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id) }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new AuthenticationResult
        {
            Success = true,
            Token = tokenHandler.WriteToken(token)
        };
    }
    
    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your_secret_key_here")), // Replace with your secret key
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false // We are validating the token manually
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;

        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }
}