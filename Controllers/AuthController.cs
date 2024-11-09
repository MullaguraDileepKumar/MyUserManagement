using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserManagement.Core.Constants;
using UserManagement.Core.Dtos.Auth;
using UserManagement.Core.Interfaces;

namespace UserManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //Route --> Seed Roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRolesAsync()
        { 
            var seedResult = await _authService.SeedRolesAsync();
            return StatusCode(seedResult.StatusCode, seedResult.Message);
        }

        //Route --> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        { 
            var registerResult = await _authService.RegisterAsync(registerDto);
            return StatusCode(registerResult.StatusCode,registerResult.Message);
        }

        //Route --> Login
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<LoginServiceResponseDto>> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);
            if (loginResult is null)
                return Unauthorized("Your credentials are invalid. Please contact Admin");
            return Ok(loginResult);
        }

        //Route -- Update User Role
        //An Owner can change everything
        //An Admin can change just user to Manager or reverse
        //Manager and User roles don't have access to this route
        [HttpPost]
        [Route("update-role")]
        [Authorize(Roles = StaticUserRoles.OwnerAdmin)]
        public async Task<IActionResult> UpdateRole([FromBody] UpdateRoleDto updateRoleDto)
        {
            var updateRoleResult = await _authService.UpdateRoleAsync(User,updateRoleDto);
            if (updateRoleResult.IsSucceed)
            {
                return Ok(updateRoleResult.Message);
            }
            else
            { 
                return StatusCode(updateRoleResult.StatusCode,updateRoleResult.Message);
            }
        }

        //Route --> Getting data of user from JWT
        [HttpPost]
        [Route("me")]
        public async Task<ActionResult<LoginServiceResponseDto>> Me([FromBody] MeDto token)
        {
            try
            {
                var me = await _authService.MeAsync(token);
                if (me is not null)
                    return Ok(me);
                else
                    return Unauthorized("Invalid Token");
            }
            catch (Exception)
            {
                return Unauthorized("Invalid Token");
            }
        }

        //Route --> List of all users details
        [HttpGet]
        [Route("users")]
        public async Task<ActionResult<IEnumerable<UserInfoResult>>> GetUsersList()
        { 
            var usersListResult = await _authService.GetUsersListAsync();
            return Ok(usersListResult);
        }

        //Route --> Get a user by Username
        [HttpGet]
        [Route("users/userName")]
        public async Task<ActionResult<UserInfoResult>> GetUserDetailsByUserName([FromBody] string userName)
        { 
            var user = await _authService.GetUserDetailsByUserName(userName);
            if (user is not null)
                return Ok(user);
            else
                return NotFound("UserName Not Found");
        }

        //Route --> Get List of all usernames for send message
        [HttpGet]
        [Route("usernames")]
        public async Task<ActionResult<IEnumerable<string>>> GetUserNames()
        { 
            var userNames = await _authService.GetUsernameListAsync();
            return Ok(userNames);
        }
    }
}
