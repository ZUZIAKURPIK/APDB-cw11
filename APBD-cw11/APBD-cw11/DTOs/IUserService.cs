namespace WebApplication1.DTOs;

public interface IUserService
{
    Task<AuthenticationResult> RegisterUserAsync(UserRegisterDto model);
    Task<AuthenticationResult> LoginUserAsync(UserLoginDto model);
    Task<AuthenticationResult> RefreshTokenAsync(TokenRefreshDto model);
}