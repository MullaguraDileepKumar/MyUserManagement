using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using UserManagement.Core.DbContext;
using UserManagement.Core.Dtos.General;
using UserManagement.Core.Dtos.Message;
using UserManagement.Core.Entities;
using UserManagement.Core.Interfaces;

namespace UserManagement.Core.Services
{
    public class MessageService : IMessageService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogService _logService;
        private readonly UserManager<ApplicationUser> _userManager;
        public MessageService(ApplicationDbContext context, ILogService logService, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _logService = logService;
            _userManager = userManager;
        }

        public async Task<GeneralServiceResponseDto> CreateNewNessageAsync(ClaimsPrincipal User, CreateMessageDto createMessageDto)
        {

            if (User.Identity.Name == createMessageDto.ReceiverUserName)
            {
                return new GeneralServiceResponseDto()
                {
                    IsSucceed = false,
                    StatusCode = 400,
                    Message = "Sender and Receiver cannot be same"
                };
            }
                var IsReceiverUserNameValid = _userManager.Users.Any(q => q.UserName == createMessageDto.ReceiverUserName);
                if (!IsReceiverUserNameValid)
                {
                    return new GeneralServiceResponseDto()
                    {
                        IsSucceed = false,
                        StatusCode = 400,
                        Message = "Receiver UserName is not Valid",
                    };
                }
                    Message newMessage = new Message()
                    {
                        SenderUserName = User.Identity.Name,
                        RecieverUserName = createMessageDto.ReceiverUserName,
                        Text = createMessageDto.Text
                    };
                    await _context.Messages.AddAsync(newMessage);
                    await _context.SaveChangesAsync();
                    await _logService.SaveNewLog(User.Identity.Name, "Send Message");
                    return new GeneralServiceResponseDto()
                    {
                        IsSucceed = true,
                        StatusCode = 201,
                        Message = "Message Saved Successfully",
                    };            
        }
        public async Task<IEnumerable<GetMessageDto>> GetMessagesAsync()
        {
            var messages = await _context.Messages
                .Select(q => new GetMessageDto()
                {
                    Id = q.Id,
                    SenderUserName = q.SenderUserName,
                    ReceiverUserName = q.RecieverUserName,
                    Text = q.Text,
                    CreatedAt = q.CreatedAt,
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();
            return messages;
        }  

        public async Task<IEnumerable<GetMessageDto>> GetMyMessagesAsync(ClaimsPrincipal User)
        {
            var loggedInUser = User.Identity.Name;
            var myMyMessages = await _context.Messages
                .Where(q => q.SenderUserName == loggedInUser || q.RecieverUserName == loggedInUser)
                .Select(q => new GetMessageDto()
                { 
                    Id = q.Id,
                    SenderUserName = q.SenderUserName,
                    ReceiverUserName = q.RecieverUserName,
                    Text = q.Text,
                    CreatedAt = q.CreatedAt,
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();
            return myMyMessages;
        }
    }
}
