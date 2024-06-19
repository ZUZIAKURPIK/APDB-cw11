using Microsoft.AspNetCore.Mvc;
using WebApplication1.DTOs;

namespace JWT.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private IUserService _userService;

    public AccountController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserRegisterDto model)
    {
        var result = await _userService.RegisterUserAsync(model);

        if (!result.Success)
        {
            return BadRequest(result.Errors);
        }

        return Ok();
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLoginDto model)
    {
        var result = await _userService.LoginUserAsync(model);

        if (!result.Success)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { AccessToken = result.Token, RefreshToken = result.Token });
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(TokenRefreshDto model)
    {
        var result = await _userService.RefreshTokenAsync(model);

        if (!result.Success)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { AccessToken = result.Token, RefreshToken = result.Token });
    }
}