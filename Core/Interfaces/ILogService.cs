using UserManagement.Core.Dtos.Log;
using System.Security.Claims;

namespace UserManagement.Core.Interfaces
{
    public interface ILogService
    {
        Task SaveNewLog(string UserName,string Description);
        Task<IEnumerable<GetLogDto>> GetLogsAsync();
        Task<IEnumerable<GetLogDto>> GetMyLogsAsync(ClaimsPrincipal User);
    }
}
