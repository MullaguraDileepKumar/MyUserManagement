using System.Security.Claims;
using UserManagement.Core.Dtos.Auth;
using UserManagement.Core.Dtos.General;

namespace UserManagement.Core.Interfaces
{
    public interface IAuthService
    {
        Task<GeneralServiceResponseDto> SeedRolesAsync();
        Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<LoginServiceResponseDto?> LoginAsync(LoginDto loginDto);
        Task<GeneralServiceResponseDto> UpdateRoleAsync(ClaimsPrincipal User,UpdateRoleDto updateRoleDto);
        Task<LoginServiceResponseDto?> MeAsync(MeDto meDto);
        Task<IEnumerable<UserInfoResult>> GetUsersListAsync();
        Task<UserInfoResult?> GetUserDetailsByUserName(string userName);
        Task<IEnumerable<string>> GetUsernameListAsync();

    }
}
