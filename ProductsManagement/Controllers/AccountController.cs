using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ProductsManagement.Context;
using ProductsManagement.Data;
using ProductsManagement.Data.Utility;
using ProductsManagement.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ProductsManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly JWTSettings _jwtSettings;

        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _dbContext;

        public AccountController(SignInManager<User> signInManager, UserManager<User> userManager, ApplicationDbContext dbContext, IOptions<JWTSettings> JWTOptions)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _dbContext = dbContext;

            _jwtSettings = JWTOptions.Value;

        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUserDto loginDto)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);
                if (user is not null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault() ?? "user";
                    //Console.WriteLine(role);
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new[]
                        {
                        new Claim(ClaimTypes.NameIdentifier, user.Id),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, role)
                    }),
                        Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes),
                        Issuer = _jwtSettings.Issuer,
                        Audience = _jwtSettings.Audience,
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)),
                            SecurityAlgorithms.HmacSha256)
                    };

                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    return Ok(new { token = tokenHandler.WriteToken(token), role });
                }

                return Unauthorized(new { errors = new[] { "Invalid credentials" } });
            }

            return BadRequest(new
            {
                errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)
            });
        }

        [HttpPost("register")]
        public IActionResult Register(RegisterUserDto registerDto)
        {
            if (ModelState.IsValid)
            {
                User user = new User
                {
                    UserName = registerDto.Username,
                    Email = registerDto.Email
                };
                var result = _userManager.CreateAsync(user, registerDto.Password).Result;
                if (result.Succeeded)
                {
                    //Add user to "User" role
                    _userManager.AddToRoleAsync(user, "user").Wait();
                    return Ok(new { message = "User registered successfully" });
                }
                else
                {
                    return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
                }
            } return BadRequest(new { errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });
        }

        
        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            // Sign out the user
            _signInManager.SignOutAsync().Wait();
            return Ok(new { message = "User logged out successfully" });
        }


        [HttpPost("admin/login")]
        public async Task<IActionResult> AdminLogin(LoginUserDto loginDto)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);
                if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    if (!roles.Contains("Admin"))
                        return Unauthorized(new { errors = new[] { "Access denied. User is not an Admin." } });

                    var role = "Admin";

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new[]
                        {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, role)
                }),
                        Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes),
                        Issuer = _jwtSettings.Issuer,
                        Audience = _jwtSettings.Audience,
                        SigningCredentials = new SigningCredentials(
                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)),
                            SecurityAlgorithms.HmacSha256)
                    };

                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    return Ok(new { token = tokenHandler.WriteToken(token), role });
                }
                return Unauthorized(new { errors = new[] { "Invalid credentials" } });
            }
            return BadRequest(new
            {
                errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)
            });
        }

    }
}
